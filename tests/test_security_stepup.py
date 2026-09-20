"""step-up 与 Windows ACL 相关测试。"""
import os
import sys

import pytest

from keyvault import config, store, vault, webui


PASSWORD = "stepup-test-pass"
SECRET = "sk-stepup-secret-999"


@pytest.fixture
def vault_env(tmp_path, monkeypatch):
    monkeypatch.setenv("KV_DIR", str(tmp_path))
    monkeypatch.setenv("KV_DB", str(tmp_path / "secrets.db"))
    webui._SESSIONS.clear()
    webui._UNLOCK_FAILS.clear()
    repo = store.VaultRepo(config.vault_path())
    salt = b"unit-test-salt-16b"
    header = vault.VaultHeader(salt=salt)
    repo.init(header)
    key = vault.derive_key(PASSWORD, salt)
    repo.insert(vault.encrypt_entry(key, "deepseek", "deepseek", SECRET, None))
    return key, repo


def test_delete_requires_step_up_password(vault_env):
    key, _ = vault_env
    # 无 password
    r = webui.api_delete({"name": "deepseek"}, key)
    assert r["ok"] is False
    assert r.get("need_step_up") is True
    # 错误 password
    r = webui.api_delete({"name": "deepseek", "password": "wrong"}, key)
    assert r["ok"] is False
    assert r.get("need_step_up") is True
    # 正确 password
    r = webui.api_delete({"name": "deepseek", "password": PASSWORD}, key)
    assert r["ok"] is True


def test_export_requires_step_up(vault_env, tmp_path):
    key, _ = vault_env
    backups = os.path.expanduser("~/.keyvault/backups")
    os.makedirs(backups, exist_ok=True)
    path = os.path.join(backups, "stepup-test.db")
    r = webui.api_export({"path": path}, key)
    assert r["ok"] is False and r.get("need_step_up")
    r = webui.api_export({"path": path, "password": PASSWORD}, key)
    assert r["ok"] is True


def test_acl_status_reports_platform(vault_env):
    _, repo = vault_env
    info = config.acl_status(repo.path)
    assert info["exists"] is True
    assert info["platform"] in ("windows", "posix")
