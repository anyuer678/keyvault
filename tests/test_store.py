"""tests/test_store.py — SQLite 持久化：init/CRUD/原子导入导出/header。"""

import os
import sqlite3

import pytest

from store import VaultRepo
from vault import VaultHeader, decrypt_entry, derive_key, encrypt_entry

SALT = bytes(range(16))
PASSWORD = "correct horse battery staple"


def _repo(tmp_path) -> VaultRepo:
    return VaultRepo(str(tmp_path / "secrets.db"))


def _header() -> VaultHeader:
    return VaultHeader(version=1, salt=SALT, kdf="scrypt")


def test_init_creates_db_file(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    assert repo.exists()
    assert os.path.getsize(str(tmp_path / "secrets.db")) > 0


def test_init_then_header_roundtrip(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    assert repo.exists()
    header = repo.load_header()
    assert header.version == 1
    assert header.salt == SALT
    assert header.kdf == "scrypt"


def test_load_header_missing_file_raises(tmp_path):
    repo = _repo(tmp_path)
    with pytest.raises(FileNotFoundError):
        repo.load_header()


def test_insert_get_list_delete(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    key = derive_key(PASSWORD, SALT)
    e1 = encrypt_entry(key, "deepseek", "deepseek", "sk-1", "2026-12-01")
    e2 = encrypt_entry(key, "github", "github", "ghp-2", None)
    repo.insert(e1)
    repo.insert(e2)
    assert repo.get("deepseek").provider == "deepseek"
    assert repo.get("missing") is None
    names = {e.name for e in repo.list_all()}
    assert names == {"deepseek", "github"}
    assert repo.delete("deepseek") is True
    assert repo.delete("deepseek") is False
    assert repo.get("deepseek") is None


def test_insert_duplicate_name_raises(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    key = derive_key(PASSWORD, SALT)
    repo.insert(encrypt_entry(key, "dup", "p", "v1", None))
    with pytest.raises(sqlite3.IntegrityError):
        repo.insert(encrypt_entry(key, "dup", "p", "v2", None))


def test_update_replaces_values(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    key = derive_key(PASSWORD, SALT)
    repo.insert(encrypt_entry(key, "a", "openai", "old", None))
    repo.update("a", encrypt_entry(key, "a", "openai", "new", "2027-01-01"))
    entry = repo.get("a")
    assert decrypt_entry(key, entry) == "new"
    assert entry.expires_at == "2027-01-01"


def test_export_import_roundtrip(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    key = derive_key(PASSWORD, SALT)
    repo.insert(encrypt_entry(key, "a", "openai", "secret-value", None))
    backup = str(tmp_path / "backup.db")
    repo.export(backup)
    assert os.path.exists(backup)

    # 新仓库导入备份
    repo2 = VaultRepo(str(tmp_path / "restored.db"))
    repo2.init(_header())
    repo2.import_from(backup)
    assert repo2.load_header().salt == SALT
    assert decrypt_entry(key, repo2.get("a")) == "secret-value"


def test_import_invalid_backup_rejected(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    fake = tmp_path / "fake.db"
    conn = sqlite3.connect(fake)
    conn.execute("CREATE TABLE junk (x TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(ValueError):
        repo.import_from(str(fake))
    assert repo.list_all() == []


def test_import_non_sqlite_rejected(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    fake = tmp_path / "fake.db"
    fake.write_text("这不是 SQLite 文件\n", encoding="utf-8")
    with pytest.raises(ValueError, match="不是合法 vault"):
        repo.import_from(str(fake))
    assert repo.list_all() == []


def test_import_missing_file_raises(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    with pytest.raises(FileNotFoundError):
        repo.import_from(str(tmp_path / "nope.db"))


def test_import_atomic_no_tmp_left(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    key = derive_key(PASSWORD, SALT)
    repo.insert(encrypt_entry(key, "a", "openai", "v", None))
    backup = str(tmp_path / "b.db")
    repo.export(backup)
    repo.import_from(backup)
    assert not os.path.exists(str(tmp_path / "secrets.db.tmp"))


def test_no_plaintext_in_db_file(tmp_path):
    repo = _repo(tmp_path)
    repo.init(_header())
    key = derive_key(PASSWORD, SALT)
    secret = "sk-PLAINTEXT-LEAK-CHECK-123456"
    repo.insert(encrypt_entry(key, "a", "openai", secret, None))
    raw = (tmp_path / "secrets.db").read_bytes()
    assert secret.encode("utf-8") not in raw
