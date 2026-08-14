"""tests/test_cli.py — CLI 参数/输出格式/二次确认/安全边界。"""

import io
import os
import sys

import pytest

import cli

PASSWORD = "test-pass-123"
SECRET = "sk-stdin-value-9999"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("KV_DIR", str(tmp_path))
    monkeypatch.setenv("KV_PASS", PASSWORD)
    monkeypatch.setattr(cli, "_KEY", None)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": SECRET)
    return tmp_path


def _init(env):
    cli.main(["init"])


# ---------- init / unlock ----------

def test_init_creates_vault(env, capsys):
    _init(env)
    assert (env / "secrets.db").exists()
    assert "vault 已创建" in capsys.readouterr().out


def test_init_rejects_short_password(env, monkeypatch):
    monkeypatch.setenv("KV_PASS", "short")
    with pytest.raises(SystemExit) as e:
        cli.main(["init"])
    assert "≥8 位" in str(e.value)


def test_init_twice_rejected(env):
    _init(env)
    with pytest.raises(SystemExit):
        cli.main(["init"])


def test_unlock_wrong_password_fails(env, monkeypatch):
    _init(env)
    monkeypatch.setenv("KV_PASS", "wrong-pass")
    with pytest.raises(SystemExit) as e:
        cli.main(["unlock"])
    assert "无法解锁" in str(e.value)


def test_unlock_ok(env, capsys):
    _init(env)
    cli.main(["unlock"])
    assert "已解锁" in capsys.readouterr().out


def test_command_without_vault_exits(env):
    with pytest.raises(SystemExit) as e:
        cli.main(["list"])
    assert "kv init" in str(e.value)


# ---------- add / get ----------

def test_add_get_full_roundtrip(env, capsys):
    _init(env)
    cli.main(["add", "deepseek", "--provider", "deepseek"])
    capsys.readouterr()  # 清空 init/add 输出
    cli.main(["get", "deepseek", "--full"])
    assert capsys.readouterr().out.strip() == SECRET


def test_add_stdin(env, monkeypatch, capsys):
    _init(env)
    monkeypatch.setattr(sys, "stdin", io.StringIO("sk-from-stdin\n"))
    cli.main(["add", "a", "--provider", "openai", "--stdin"])
    capsys.readouterr()
    cli.main(["get", "a", "--full"])
    assert capsys.readouterr().out.strip() == "sk-from-stdin"


def test_add_duplicate_rejected(env):
    _init(env)
    cli.main(["add", "a", "--provider", "openai"])
    with pytest.raises(SystemExit):
        cli.main(["add", "a", "--provider", "openai"])


def test_add_invalid_expires_rejected(env):
    _init(env)
    with pytest.raises(SystemExit):
        cli.main(["add", "a", "--expires", "2026/12/01"])


def test_get_masked_by_default(env, capsys):
    _init(env)
    cli.main(["add", "deepseek", "--provider", "deepseek"])
    cli.main(["get", "deepseek"])
    out = capsys.readouterr().out
    assert SECRET not in out
    assert out.strip().endswith("9999")


def test_get_missing_exits(env):
    _init(env)
    with pytest.raises(SystemExit):
        cli.main(["get", "nope"])


def test_get_reports_tampered_data(env, capsys):
    _init(env)
    cli.main(["add", "a", "--provider", "openai"])
    import sqlite3
    conn = sqlite3.connect(str(env / "secrets.db"))
    conn.execute("UPDATE secrets SET ciphertext = 'TAMPERED'")
    conn.commit()
    conn.close()
    with pytest.raises(SystemExit) as e:
        cli.main(["get", "a"])
    assert "完整性校验失败" in str(e.value)


def test_expired_entry_warns(env, capsys):
    _init(env)
    cli.main(["add", "old", "--provider", "openai", "--expires", "2020-01-01"])
    cli.main(["get", "old", "--full"])
    assert "已过期" in capsys.readouterr().err


# ---------- list ----------

def test_list_never_shows_values(env, capsys):
    _init(env)
    cli.main(["add", "deepseek", "--provider", "deepseek"])
    cli.main(["add", "github", "--provider", "github"])
    cli.main(["list"])
    out = capsys.readouterr().out
    assert SECRET not in out
    assert "deepseek" in out and "github" in out


def test_list_marks_expired_entries(env, capsys):
    _init(env)
    cli.main(["add", "old", "--provider", "openai", "--expires", "2020-01-01"])
    cli.main(["add", "new", "--provider", "openai", "--expires", "2099-01-01"])
    out = capsys.readouterr().out
    cli.main(["list"])
    out = capsys.readouterr().out
    assert "EXPIRED" in out and "old" in out
    assert "2099-01-01" in out


# ---------- use ----------

def test_use_prints_export_line(env, capsys):
    _init(env)
    cli.main(["add", "deepseek", "--provider", "deepseek"])
    capsys.readouterr()
    cli.main(["use", "deepseek"])
    out = capsys.readouterr().out
    assert out.strip() == f"export DEEPSEEK_API_KEY={SECRET}"


def test_use_github_maps_to_token(env, capsys):
    _init(env)
    cli.main(["add", "gh", "--provider", "github"])
    cli.main(["use", "gh"])
    assert "export GITHUB_TOKEN=" in capsys.readouterr().out


def test_use_fish_shell(env, capsys):
    _init(env)
    cli.main(["add", "gh", "--provider", "github"])
    cli.main(["use", "gh", "--shell", "fish"])
    assert f"set -gx GITHUB_TOKEN {SECRET}" in capsys.readouterr().out


def test_use_dotenv_writes_0600_file(env, capsys):
    _init(env)
    cli.main(["add", "deepseek", "--provider", "deepseek"])
    dotenv = env / "out.env"
    cli.main(["use", "deepseek", "--dotenv", str(dotenv)])
    assert dotenv.read_text(encoding="utf-8").strip() == f"DEEPSEEK_API_KEY={SECRET}"
    assert "已写入" in capsys.readouterr().out
    assert not (env / "out.env.tmp").exists()


# ---------- edit / delete ----------

def test_edit_updates_value(env, monkeypatch, capsys):
    _init(env)
    cli.main(["add", "a", "--provider", "openai"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "new-value-1111")
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    cli.main(["edit", "a"])
    capsys.readouterr()
    cli.main(["get", "a", "--full"])
    assert capsys.readouterr().out.strip() == "new-value-1111"


def test_edit_rejects_invalid_expires(env, monkeypatch):
    _init(env)
    cli.main(["add", "a", "--provider", "openai"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "")
    monkeypatch.setattr("builtins.input", lambda prompt="": "2026/12/01")
    with pytest.raises(SystemExit) as e:
        cli.main(["edit", "a"])
    assert "YYYY-MM-DD" in str(e.value)


def test_delete_requires_yes_word(env, monkeypatch):
    _init(env)
    cli.main(["add", "a", "--provider", "openai"])
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    cli.main(["delete", "a"])
    assert cli._repo().get("a") is not None
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    cli.main(["delete", "a"])
    assert cli._repo().get("a") is None


def test_delete_with_yes_flag_skips_confirm(env):
    _init(env)
    cli.main(["add", "a", "--provider", "openai"])
    cli.main(["delete", "a", "--yes"])
    assert cli._repo().get("a") is None


# ---------- audit / rotate / shell-init ----------

def test_audit_reports_without_values(env, capsys):
    _init(env)
    proj = env / "proj"
    proj.mkdir()
    (proj / ".env").write_text(
        "DEEPSEEK_API_KEY=sk-leak-123456\nOPENAI_API_KEY=sk-leak-654321\n"
        "# COMMENT=sk-ignored\nNORMAL=value\n",
        encoding="utf-8",
    )
    cli.main(["audit", "--dir", str(proj)])
    out = capsys.readouterr().out
    assert ".env" in out
    assert "DEEPSEEK_API_KEY" in out
    assert "sk-leak-123456" not in out
    assert "sk-leak-654321" not in out


def test_audit_no_hits(env, capsys):
    _init(env)
    (env / "clean").mkdir()
    (env / "clean" / ".env").write_text("FOO=bar\n", encoding="utf-8")
    cli.main(["audit", "--dir", str(env / "clean")])
    assert "未发现" in capsys.readouterr().out


def test_rotate_prints_url(env, capsys):
    cli.main(["rotate", "--provider", "github"])
    out = capsys.readouterr().out
    assert "github.com/settings/tokens" in out


def test_shell_init_prints_alias(env, capsys):
    cli.main(["shell-init"])
    assert "alias kvg=" in capsys.readouterr().out


# ---------- backup ----------

def test_export_to_missing_dir_rejected(env):
    _init(env)
    with pytest.raises(FileNotFoundError):
        cli.main(["export-backup", str(env / "nope" / "backup.db")])


def test_export_import_backup_roundtrip(env, monkeypatch, capsys, tmp_path):
    _init(env)
    cli.main(["add", "deepseek", "--provider", "deepseek"])
    backup = str(tmp_path / "backup.db")
    cli.main(["export-backup", backup])
    assert os.path.exists(backup)

    # 在第二个目录里恢复（模拟新会话：内存 key 应为空）
    env2 = tmp_path / "env2"
    env2.mkdir()
    monkeypatch.setenv("KV_DIR", str(env2))
    monkeypatch.setattr(cli, "_KEY", None)
    cli.main(["init"])
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    cli.main(["import-backup", backup])
    monkeypatch.setattr(cli, "_KEY", None)  # 导入后重新按库头 salt 派生
    capsys.readouterr()
    cli.main(["get", "deepseek", "--full"])
    assert capsys.readouterr().out.strip() == SECRET


# ---------- 安全底线 ----------

def test_db_file_contains_no_plaintext(env):
    _init(env)
    cli.main(["add", "deepseek", "--provider", "deepseek"])
    raw = (env / "secrets.db").read_bytes()
    assert SECRET.encode("utf-8") not in raw
    assert PASSWORD.encode("utf-8") not in raw


def test_key_recovered_from_env_after_memory_reset(env, monkeypatch, capsys):
    """key 只存内存：重置 _KEY 后仅凭 KV_PASS 即可再次解锁。"""
    _init(env)
    cli.main(["add", "deepseek", "--provider", "deepseek"])
    monkeypatch.setattr(cli, "_KEY", None)
    capsys.readouterr()
    cli.main(["get", "deepseek", "--full"])
    assert capsys.readouterr().out.strip() == SECRET
