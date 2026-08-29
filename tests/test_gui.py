"""tests/test_gui.py — GUI 表单逻辑 + 实例化冒烟（不进入 mainloop）。"""

import os

import pytest

from keyvault import config
from keyvault import gui
from keyvault import store
from keyvault import vault

PASSWORD = "gui-test-pass"
SECRET = "sk-gui-secret-1234"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("KV_DIR", str(tmp_path))
    r = store.VaultRepo(config.vault_path())
    salt = os.urandom(16)
    r.init(vault.VaultHeader(version=1, salt=salt, kdf="scrypt"))
    return r


@pytest.fixture
def key(repo):
    return vault.derive_key(PASSWORD, repo.load_header().salt)


# ---------- 纯逻辑 ----------

def test_validate_expires():
    assert gui.validate_expires("")
    assert gui.validate_expires("2099-01-31")
    assert not gui.validate_expires("2026/12/01")
    assert not gui.validate_expires("not-a-date")


def test_mask_short_and_long():
    assert gui.mask("short") == "*" * 8
    m = gui.mask(SECRET)
    assert SECRET not in m
    assert m.endswith("1234") and m.startswith("sk-g")


def test_is_expired():
    assert gui.is_expired("2000-01-01")
    assert not gui.is_expired("2099-01-01")
    assert not gui.is_expired(None)


def test_add_entry_roundtrip(repo, key):
    gui.add_entry(repo, key, "deepseek", "deepseek", SECRET, "2099-01-01")
    entry = repo.get("deepseek")
    assert vault.decrypt_entry(key, entry) == SECRET
    assert entry.expires_at == "2099-01-01"


def test_add_entry_rejects_duplicate(repo, key):
    gui.add_entry(repo, key, "a", "openai", SECRET, "")
    with pytest.raises(ValueError, match="同名"):
        gui.add_entry(repo, key, "a", "openai", "other", "")


def test_add_entry_rejects_bad_input(repo, key):
    with pytest.raises(ValueError, match="不能为空"):
        gui.add_entry(repo, key, "", "openai", SECRET, "")
    with pytest.raises(ValueError, match="不能为空"):
        gui.add_entry(repo, key, "a", "openai", "", "")
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        gui.add_entry(repo, key, "a", "openai", SECRET, "2026/01/01")


def test_update_entry_keeps_value_when_blank(repo, key):
    gui.add_entry(repo, key, "a", "openai", SECRET, "2099-01-01")
    gui.update_entry(repo, key, "a", "", "", "2027-07-01")
    entry = repo.get("a")
    assert vault.decrypt_entry(key, entry) == SECRET
    assert entry.expires_at == "2027-07-01"
    assert entry.provider == "openai"


def test_update_entry_changes_value(repo, key):
    gui.add_entry(repo, key, "a", "openai", SECRET, "")
    gui.update_entry(repo, key, "a", "", "sk-new-value", "")
    assert vault.decrypt_entry(key, repo.get("a")) == "sk-new-value"


def test_update_entry_changes_provider(repo, key):
    gui.add_entry(repo, key, "a", "openai", SECRET, "")
    gui.update_entry(repo, key, "a", "deepseek", "", "")
    assert repo.get("a").provider == "deepseek"
    # 新 provider 参与 AAD：仍能解密
    assert vault.decrypt_entry(key, repo.get("a")) == SECRET


def test_update_entry_rejects_bad_expires(repo, key):
    gui.add_entry(repo, key, "a", "openai", SECRET, "")
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        gui.update_entry(repo, key, "a", "", "", "bad-date")


# ---------- 实例化冒烟（Windows 有 display；无则跳过） ----------

def test_gui_unlock_creates_vault_when_missing(monkeypatch, tmp_path):
    """vault 不存在且默认目录也不存在时，解锁向导创建成功（P1 修复）。"""
    monkeypatch.setenv("KV_DIR", str(tmp_path / "nested" / "dir"))
    import tkinter as tk
    try:
        app = gui.GuiApp()
    except tk.TclError:
        pytest.skip("无可用 display，跳过")
    try:
        assert not app._repo.exists()
        monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
        real = gui.UnlockDialog
        answers = iter(["gui-pass-123", "gui-pass-123"])

        class FakeDialog(real):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                self.after(0, self.destroy)  # 事件循环中立即关闭，避免 wait_window 死锁

            def result(self):
                return next(answers)

        monkeypatch.setattr(gui, "UnlockDialog", FakeDialog)
        app._unlock()
        assert app._repo.exists()
        assert app._key is not None
        app.withdraw()
    finally:
        app.destroy()


def test_gui_app_instantiates(monkeypatch, tmp_path):
    monkeypatch.setenv("KV_DIR", str(tmp_path))
    try:
        import tkinter as tk
        app = gui.GuiApp()
    except tk.TclError:
        pytest.skip("无可用 display，跳过 GUI 冒烟")
    try:
        assert app.title() == "KeyVault — API 密钥保险箱"
        app.withdraw()
    finally:
        app.destroy()
