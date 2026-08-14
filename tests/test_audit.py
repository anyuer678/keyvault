"""tests/test_audit.py — 明文密钥扫描：单行判定 + 目录扫描（只读、永不暴露值）。"""

import os

from audit import KEY_NAME_PATTERN, scan_dir, scan_envline


def test_pattern_matches_known_keys():
    assert KEY_NAME_PATTERN.search("DEEPSEEK_API_KEY")
    assert KEY_NAME_PATTERN.search("OPENAI_API_KEY")
    assert KEY_NAME_PATTERN.search("GITHUB_TOKEN")
    assert KEY_NAME_PATTERN.search("AWS_SECRET_ACCESS_KEY")
    assert KEY_NAME_PATTERN.search("AZURE_OPENAI_API_KEY")
    assert KEY_NAME_PATTERN.search("GOOGLE_API_KEY")
    assert KEY_NAME_PATTERN.search("ANYTHING_API_KEY")


def test_scan_envline_hits():
    hit = scan_envline("DEEPSEEK_API_KEY=sk-abc123")
    assert hit is not None
    assert hit.key_name == "DEEPSEEK_API_KEY"
    assert hit.redacted is True
    # Finding 结构里不允许出现值本身
    assert "sk-abc123" not in str(hit)


def test_scan_envline_misses():
    assert scan_envline("") is None
    assert scan_envline("# DEEPSEEK_API_KEY=sk-abc") is None
    assert scan_envline("FOO=bar") is None
    assert scan_envline("no-equals-here") is None
    assert scan_envline("=value") is None
    assert scan_envline("DEEPSEEK_API_KEY") is None


def test_scan_dir_finds_env_ini_toml(tmp_path):
    (tmp_path / ".env").write_text("DEEPSEEK_API_KEY=sk-leak\n", encoding="utf-8")
    sub = tmp_path / "config"
    sub.mkdir()
    (sub / "settings.ini").write_text("[default]\nGITHUB_TOKEN=ghp-leak\n", encoding="utf-8")
    (sub / "app.toml").write_text('OPENAI_API_KEY = "sk-toml"\n', encoding="utf-8")
    (sub / "ignored.py").write_text("x = 1\n", encoding="utf-8")
    findings = scan_dir(str(tmp_path))
    files = {f.file for f in findings}
    assert any(f.endswith(".env") for f in files)
    assert any(f.endswith("settings.ini") for f in files)
    assert any(f.endswith("app.toml") for f in files)
    assert not any(f.endswith("ignored.py") for f in files)


def test_scan_dir_respects_ignore(tmp_path):
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-x\n", encoding="utf-8")
    sub = tmp_path / "node_modules"
    sub.mkdir()
    (sub / ".env").write_text("OPENAI_API_KEY=sk-leak2\n", encoding="utf-8")
    findings = scan_dir(str(tmp_path))
    files = [f.file for f in findings]
    assert any(f.endswith(".env") for f in files)
    assert not any("node_modules" in f for f in files)


def test_scan_dir_never_exposes_values(tmp_path):
    secret = "sk-THIS-SHOULD-NEVER-LEAK-42"
    (tmp_path / ".env").write_text(f"DEEPSEEK_API_KEY={secret}\n", encoding="utf-8")
    findings = scan_dir(str(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.key_name == "DEEPSEEK_API_KEY"
    assert f.redacted is True
    assert not hasattr(f, "value")
    assert secret not in str(f)


def test_scan_dir_read_only_no_writes(tmp_path):
    target = tmp_path / ".env"
    target.write_text("OPENAI_API_KEY=sk-x\n", encoding="utf-8")
    before = target.read_bytes()
    scan_dir(str(tmp_path))
    assert target.read_bytes() == before
    assert set(os.listdir(tmp_path)) == {".env"}


def test_max_files_cap(tmp_path):
    for i in range(5):
        (tmp_path / f".env{i}").write_text("OPENAI_API_KEY=sk-x\n", encoding="utf-8")
    findings = scan_dir(str(tmp_path), max_files=3)
    assert len(findings) <= 3
