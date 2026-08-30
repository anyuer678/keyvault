"""audit.py — .env 明文密钥扫描（只读，不写任何文件）。"""

import os
import re
from dataclasses import dataclass

KEY_NAME_PATTERN = re.compile(
    r"(OPENAI|ANTHROPIC|DEEPSEEK|GITHUB|AWS|AZURE|GOOGLE|ZHIPU|MOONSHOT|QWEN|DOUBAO|API)_?(KEY|TOKEN|SECRET)"
)

_TARGET_SUFFIXES = (".env", ".ini", ".toml", ".config", ".yaml", ".yml", ".json", ".ps1")


@dataclass
class Finding:
    file: str
    key_name: str
    redacted: bool = True


def scan_envline(line: str) -> Finding | None:
    """单行判定：KEY=value 且 key 名匹配模式。"""
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    key, _, _ = line.partition("=")
    key = key.strip()
    if not key:
        return None
    if KEY_NAME_PATTERN.search(key):
        return Finding(file="", key_name=key, redacted=True)
    return None


def scan_dir(root: str, *, max_files: int = 10_000,
             ignore: tuple[str, ...] = (".git", "node_modules")) -> list[Finding]:
    """递归扫描目标后缀文件，命中 KEY=value 即报告，值区永不返回。"""
    findings: list[Finding] = []
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore]
        for fn in filenames:
            if count >= max_files:
                return findings
            count += 1
            if not _is_target(fn):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        hit = scan_envline(line)
                        if hit is not None:
                            hit.file = path
                            findings.append(hit)
            except OSError:
                continue
    return findings


def _is_target(fn: str) -> bool:
    return fn.startswith(".env") or fn.lower().endswith(_TARGET_SUFFIXES)
