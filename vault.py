"""vault.py — 加解密核心（scrypt + AES-GCM），纯函数、无 IO。"""

import os
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32
NONCE_LEN = 12
TAG_BYTES = 16


class IntegrityError(ValueError):
    """密文完整性校验失败。"""


@dataclass
class VaultHeader:
    version: int = 1
    salt: bytes = b""
    kdf: str = "scrypt"


@dataclass
class EncryptedEntry:
    name: str                 # 明文：仅名称（非密文）
    provider: str
    ciphertext: bytes
    nonce: bytes              # 独立 nonce/条目
    created_at: str
    expires_at: str | None


def derive_key(password: str, salt: bytes) -> bytes:
    """scrypt 派生 32B 主密钥。"""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def _aad(name: str, provider: str) -> bytes:
    """关联数据 name+provider（长度前缀防边界混淆）。"""
    nb = name.encode("utf-8")
    pb = provider.encode("utf-8")
    return struct.pack(">I", len(nb)) + nb + pb


def encrypt_entry(key: bytes, name: str, provider: str,
                  value: str, expires: str | None) -> EncryptedEntry:
    """加密单条密钥，独立 nonce。"""
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), _aad(name, provider))
    return EncryptedEntry(
        name=name,
        provider=provider,
        ciphertext=ciphertext,
        nonce=nonce,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        expires_at=expires,
    )


def decrypt_entry(key: bytes, entry: EncryptedEntry) -> str:
    """解密条目，完整性失败抛 IntegrityError。"""
    try:
        plain = AESGCM(key).decrypt(entry.nonce, entry.ciphertext,
                                    _aad(entry.name, entry.provider))
    except Exception as e:
        raise IntegrityError("完整性校验失败") from e
    return plain.decode("utf-8")

