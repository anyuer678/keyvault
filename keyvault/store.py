"""store.py — SQLite 持久化（0600 权限、原子写）。"""

import os
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .vault import EncryptedEntry, NONCE_LEN, VaultHeader

_TMP_SUFFIX = ".tmp"
_CHECK_MARKER = b"keyvault-ok"


def _chmod_0600(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class VaultRepo:
    """secrets.db 单文件仓库（含 header 的 meta 表）。"""

    def __init__(self, path: str):
        self.path = path

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def init(self, header: VaultHeader) -> None:
        """建库：secrets 表 + meta 表（version/salt/kdf），0600 权限。"""
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "CREATE TABLE secrets (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "name TEXT UNIQUE, provider TEXT, ciphertext BLOB, nonce BLOB, "
                "created_at TEXT, expires_at TEXT, notes TEXT)"
            )
            conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO meta VALUES ('version', ?)", (str(header.version),))
            conn.execute("INSERT INTO meta VALUES ('salt', ?)", (header.salt.hex(),))
            conn.execute("INSERT INTO meta VALUES ('kdf', ?)", (header.kdf,))
            conn.commit()
        finally:
            conn.close()
        _chmod_0600(self.path)

    def load_header(self) -> VaultHeader:
        """读取库头（扩展方法：cli 解锁 / import 校验用）。"""
        if not self.exists():
            raise FileNotFoundError(self.path)
        conn = sqlite3.connect(self.path)
        try:
            rows = dict(conn.execute("SELECT key, value FROM meta"))
        finally:
            conn.close()
        if "salt" not in rows:
            raise ValueError("vault 库头损坏：缺少 salt")
        return VaultHeader(
            version=int(rows.get("version", "1")),
            salt=bytes.fromhex(rows["salt"]),
            kdf=rows.get("kdf", "scrypt"),
        )

    def insert(self, entry: EncryptedEntry) -> None:
        """插入条目；name 冲突抛 sqlite3.IntegrityError。"""
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "INSERT INTO secrets (name, provider, ciphertext, nonce, "
                "created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (entry.name, entry.provider, entry.ciphertext, entry.nonce,
                 entry.created_at, entry.expires_at),
            )
            conn.commit()
        finally:
            conn.close()

    def get(self, name: str) -> EncryptedEntry | None:
        conn = sqlite3.connect(self.path)
        try:
            row = conn.execute(
                "SELECT name, provider, ciphertext, nonce, created_at, expires_at "
                "FROM secrets WHERE name = ?", (name,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return EncryptedEntry(*row)

    def list_all(self) -> list[EncryptedEntry]:
        conn = sqlite3.connect(self.path)
        try:
            rows = conn.execute(
                "SELECT name, provider, ciphertext, nonce, created_at, expires_at "
                "FROM secrets ORDER BY name",
            ).fetchall()
        finally:
            conn.close()
        return [EncryptedEntry(*r) for r in rows]

    def delete(self, name: str) -> bool:
        conn = sqlite3.connect(self.path)
        try:
            cur = conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def update(self, name: str, entry: EncryptedEntry) -> None:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "UPDATE secrets SET provider = ?, ciphertext = ?, nonce = ?, "
                "created_at = ?, expires_at = ? WHERE name = ?",
                (entry.provider, entry.ciphertext, entry.nonce,
                 entry.created_at, entry.expires_at, name),
            )
            conn.commit()
        finally:
            conn.close()

    def export(self, out_path: str) -> None:
        """全库序列化（含 header/meta），经 SQLite backup API。"""
        if not os.path.exists(os.path.dirname(os.path.abspath(out_path))):
            raise FileNotFoundError(os.path.dirname(os.path.abspath(out_path)))
        src = sqlite3.connect(self.path)
        try:
            dst = sqlite3.connect(out_path)
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
        _chmod_0600(out_path)

    def set_check(self, key: bytes) -> None:
        """写入解锁校验标记（扩展：cli init 后调用）。"""
        nonce = os.urandom(NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, _CHECK_MARKER, b"check")
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO meta VALUES ('check', ?)",
                (nonce.hex() + ":" + ct.hex(),),
            )
            conn.commit()
        finally:
            conn.close()

    def verify_check(self, key: bytes) -> bool:
        """校验解锁标记是否匹配（扩展：cli 解锁用）。"""
        conn = sqlite3.connect(self.path)
        try:
            row = conn.execute("SELECT value FROM meta WHERE key = 'check'").fetchone()
        finally:
            conn.close()
        if row is None:
            return False
        nonce_hex, _, ct_hex = row[0].partition(":")
        try:
            plain = AESGCM(key).decrypt(bytes.fromhex(nonce_hex),
                                        bytes.fromhex(ct_hex), b"check")
        except Exception:
            return False
        return plain == _CHECK_MARKER

    def import_from(self, in_path: str) -> None:
        """校验 header 后原子替换为备份库（tmp + os.replace）。"""
        if not os.path.exists(in_path):
            raise FileNotFoundError(in_path)
        probe = sqlite3.connect(in_path)
        try:
            rows = dict(probe.execute("SELECT key, value FROM meta"))
        except sqlite3.Error:
            raise ValueError("备份文件不是合法 vault（缺少 meta 表）")
        finally:
            probe.close()
        if "salt" not in rows or rows.get("version", "1") != "1" \
                or rows.get("kdf", "scrypt") != "scrypt":
            raise ValueError("备份文件不是合法 vault（缺少/错误 header）")
        tmp = self.path + _TMP_SUFFIX
        try:
            src = sqlite3.connect(in_path)
            try:
                dst = sqlite3.connect(tmp)
                try:
                    _chmod_0600(tmp)
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        try:
            os.replace(tmp, self.path)
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        _chmod_0600(self.path)
