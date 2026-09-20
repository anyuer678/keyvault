"""CLI 限速与 KDF 元数据测试。"""
import pytest

from keyvault import cli, config, store, vault


def test_unlock_rate_limit_exits(monkeypatch, tmp_path):
    monkeypatch.setenv("KV_DIR", str(tmp_path))
    monkeypatch.setenv("KV_DB", str(tmp_path / "secrets.db"))
    monkeypatch.setenv("KV_PASS", "wrong-password-xx")
    cli._KEY = None
    cli._UNLOCK_FAILS.clear()
    repo = store.VaultRepo(config.vault_path())
    repo.init(vault.VaultHeader(salt=b"0123456789abcdef"))
    key = vault.derive_key("correct-horse-battery", b"0123456789abcdef")
    repo.set_check(key)
    for _ in range(5):
        with pytest.raises(SystemExit):
            cli._ensure_key()
    with pytest.raises(SystemExit) as ei:
        cli._ensure_key()
    assert "失败次数过多" in str(ei.value)


def test_rekey_updates_kdf_meta(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("KV_DIR", str(tmp_path))
    monkeypatch.setenv("KV_DB", str(tmp_path / "secrets.db"))
    monkeypatch.setenv("KV_PASS", "correct-horse-battery")
    cli._KEY = None
    cli._UNLOCK_FAILS.clear()
    repo = store.VaultRepo(config.vault_path())
    salt = b"0123456789abcdef"
    repo.init(vault.VaultHeader(salt=salt, kdf="scrypt"))
    key = vault.derive_key("correct-horse-battery", salt)
    repo.set_check(key)
    cli.cmd_rekey(None)
    h = repo.load_header()
    assert h.kdf == getattr(vault, "KDF_VERSION", "scrypt-v1")
