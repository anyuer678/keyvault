"""tests/test_cli_json.py — kv get/list 的 --json 机器可读输出（脱敏语义与文本模式一致）。"""

import json

import pytest

from keyvault import cli

PASSWORD = "test-pass-123"
SECRET = "sk-json-value-424242"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("KV_DIR", str(tmp_path))
    monkeypatch.setenv("KV_PASS", PASSWORD)
    monkeypatch.setattr(cli, "_KEY", None)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": SECRET)
    cli.main(["init"])
    cli.main(["add", "deepseek", "--provider", "deepseek"])
    return tmp_path


def _parse_json(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def test_get_json_masks_by_default(env, capsys):
    cli.main(["get", "deepseek", "--json"])
    out = _parse_json(capsys)
    assert out["name"] == "deepseek"
    assert out["provider"] == "deepseek"
    assert out["expires_at"] is None
    assert out["expired"] is False
    assert out["value"] != SECRET
    assert SECRET not in json.dumps(out)


def test_get_json_full_requires_explicit_full(env, capsys):
    cli.main(["get", "deepseek", "--json", "--full"])
    out = _parse_json(capsys)
    assert out["value"] == SECRET


def test_list_json_never_contains_values(env, capsys):
    cli.main(["list", "--json"])
    out = _parse_json(capsys)
    entries = out["entries"]
    assert len(entries) == 1
    assert entries[0]["name"] == "deepseek"
    assert "value" not in entries[0]
    assert SECRET not in json.dumps(out)


def test_list_json_expired_flag(env, capsys, monkeypatch):
    cli.main(["add", "old1", "--expires", "2001-01-01"])
    capsys.readouterr()
    cli.main(["list", "--json"])
    entries = {e["name"]: e for e in _parse_json(capsys)["entries"]}
    assert entries["old1"]["expired"] is True
    assert entries["deepseek"]["expired"] is False
