"""tests/test_vault.py — 加解密核心：往返、篡改、nonce 独立、密文无明文。"""

import pytest

from vault import (EncryptedEntry, IntegrityError, NONCE_LEN, TAG_BYTES,
                   decrypt_entry, derive_key, encrypt_entry, payload_from)

PASSWORD = "correct horse battery staple"
SALT = bytes(range(16))


def test_derive_key_same_password_salt_stable():
    assert derive_key(PASSWORD, SALT) == derive_key(PASSWORD, SALT)


def test_derive_key_different_salt_differs():
    other = bytes(reversed(range(16)))
    assert derive_key(PASSWORD, SALT) != derive_key(PASSWORD, other)


def test_derive_key_different_password_differs():
    assert derive_key(PASSWORD, SALT) != derive_key(PASSWORD + "x", SALT)


def test_derive_key_length_is_32():
    assert len(derive_key(PASSWORD, SALT)) == 32


def test_encrypt_decrypt_roundtrip():
    key = derive_key(PASSWORD, SALT)
    entry = encrypt_entry(key, "deepseek", "deepseek", "sk-secret-123", "2026-12-01")
    assert decrypt_entry(key, entry) == "sk-secret-123"
    assert entry.expires_at == "2026-12-01"
    assert entry.name == "deepseek"
    assert entry.provider == "deepseek"


def test_encrypt_decrypt_roundtrip_no_expires():
    key = derive_key(PASSWORD, SALT)
    entry = encrypt_entry(key, "github", "github", "ghp_token", None)
    assert entry.expires_at is None
    assert decrypt_entry(key, entry) == "ghp_token"


def test_ciphertext_does_not_contain_plaintext():
    key = derive_key(PASSWORD, SALT)
    value = "sk-SUPERSECRET-abc123"
    entry = encrypt_entry(key, "openai", "openai", value, None)
    assert value.encode("utf-8") not in entry.ciphertext


def test_nonce_unique_and_random_per_entry():
    key = derive_key(PASSWORD, SALT)
    e1 = encrypt_entry(key, "a", "openai", "v1", None)
    e2 = encrypt_entry(key, "a", "openai", "v1", None)
    assert e1.nonce != e2.nonce
    assert len(e1.nonce) == NONCE_LEN
    assert e1.ciphertext != e2.ciphertext


def test_payload_from_separates_tag():
    key = derive_key(PASSWORD, SALT)
    value = "hello-world"
    entry = encrypt_entry(key, "n", "p", value, None)
    payload = payload_from(entry.ciphertext, entry.nonce, b"")
    assert payload == entry.ciphertext[:-TAG_BYTES]
    assert len(entry.ciphertext) == len(payload) + TAG_BYTES


def test_payload_from_too_short_raises():
    with pytest.raises(ValueError):
        payload_from(b"short", b"", b"")


def test_tampered_ciphertext_raises_valueerror():
    key = derive_key(PASSWORD, SALT)
    entry = encrypt_entry(key, "name", "p", "value", None)
    flipped = bytes([entry.ciphertext[-1] ^ 0xFF])
    bad = EncryptedEntry(entry.name, entry.provider,
                         entry.ciphertext[:-1] + flipped, entry.nonce,
                         entry.created_at, entry.expires_at)
    with pytest.raises(ValueError):
        decrypt_entry(key, bad)


def test_tampered_tag_raises():
    key = derive_key(PASSWORD, SALT)
    entry = encrypt_entry(key, "name", "p", "value", None)
    flipped = bytes([entry.ciphertext[0] ^ 0xFF])
    bad = EncryptedEntry(entry.name, entry.provider,
                         flipped + entry.ciphertext[1:], entry.nonce,
                         entry.created_at, entry.expires_at)
    with pytest.raises(ValueError):
        decrypt_entry(key, bad)


def test_tampered_nonce_raises():
    key = derive_key(PASSWORD, SALT)
    entry = encrypt_entry(key, "name", "p", "value", None)
    bad_nonce = bytes([entry.nonce[0] ^ 1]) + entry.nonce[1:]
    bad = EncryptedEntry(entry.name, entry.provider, entry.ciphertext,
                         bad_nonce, entry.created_at, entry.expires_at)
    with pytest.raises(ValueError):
        decrypt_entry(key, bad)


def test_tampered_name_aad_raises():
    key = derive_key(PASSWORD, SALT)
    entry = encrypt_entry(key, "name", "p", "value", None)
    bad = EncryptedEntry(entry.name + "x", entry.provider, entry.ciphertext,
                         entry.nonce, entry.created_at, entry.expires_at)
    with pytest.raises(ValueError):
        decrypt_entry(key, bad)


def test_tampered_provider_aad_raises():
    key = derive_key(PASSWORD, SALT)
    entry = encrypt_entry(key, "name", "p", "value", None)
    bad = EncryptedEntry(entry.name, entry.provider + "x", entry.ciphertext,
                         entry.nonce, entry.created_at, entry.expires_at)
    with pytest.raises(ValueError):
        decrypt_entry(key, bad)


def test_wrong_key_fails():
    entry = encrypt_entry(derive_key(PASSWORD, SALT), "n", "p", "value", None)
    with pytest.raises(ValueError):
        decrypt_entry(derive_key("other-password", SALT), entry)


def test_integrity_error_is_valueerror():
    assert issubclass(IntegrityError, ValueError)
