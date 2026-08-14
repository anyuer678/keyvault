"""config.py — vault 路径/目录权限/文件权限。"""

import os

_DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".keyvault")
_DB_NAME = "secrets.db"


def vault_dir() -> str:
    """vault 目录（环境变量 KV_DIR 可覆盖）。"""
    return os.environ.get("KV_DIR", _DEFAULT_DIR)


def vault_path() -> str:
    """vault 数据库文件路径（环境变量 KV_DB 可覆盖）。"""
    return os.environ.get("KV_DB", os.path.join(vault_dir(), _DB_NAME))


def ensure_vault_dir() -> None:
    """创建 vault 目录（0700）。"""
    d = os.path.dirname(vault_path())
    os.makedirs(d, exist_ok=True)
    chmod_0700(d)


def chmod_0600(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def chmod_0700(path: str) -> None:
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
