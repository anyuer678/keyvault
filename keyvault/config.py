"""config.py — vault 路径/目录权限/文件权限（Windows ACL 可选加固）。"""

import os
import subprocess
import sys

_DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".keyvault")
_DB_NAME = "secrets.db"


def vault_dir() -> str:
    """vault 目录（环境变量 KV_DIR 可覆盖）。"""
    return os.environ.get("KV_DIR", _DEFAULT_DIR)


def vault_path() -> str:
    """vault 数据库文件路径（环境变量 KV_DB 可覆盖）。"""
    return os.environ.get("KV_DB", os.path.join(vault_dir(), _DB_NAME))


def ensure_vault_dir() -> None:
    """创建 vault 目录（0700；Windows 可选 ACL）。"""
    d = os.path.dirname(vault_path())
    os.makedirs(d, exist_ok=True)
    chmod_0700(d)
    if os.environ.get("KV_APPLY_WIN_ACL", "0") == "1":
        restrict_path_acl(d)


def _win_acl_enabled() -> bool:
    """Windows ACL 默认关闭，避免与 SQLite 并发/ACL 误配冲突。

    生产加固：设置 KV_APPLY_WIN_ACL=1，或 CLI `kv harden-acl`。
    """
    return os.name == "nt" and os.environ.get("KV_APPLY_WIN_ACL", "0") == "1"


def chmod_0600(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        print(f"[WARN] 无法收紧文件权限（0600）: {path}: {exc}", file=sys.stderr)
    if _win_acl_enabled():
        restrict_path_acl(path)


def chmod_0700(path: str) -> None:
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    if _win_acl_enabled():
        restrict_path_acl(path)


def _windows_user() -> str:
    try:
        proc = subprocess.run(
            ["whoami"],
            capture_output=True,
            timeout=5,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode == 0 and (proc.stdout or "").strip():
            return proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        import getpass

        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME", "")


def restrict_path_acl(path: str) -> bool:
    """Windows：将 ACL 收紧为当前用户。默认关闭；需 KV_APPLY_WIN_ACL=1。"""
    if os.name != "nt" or not path or not os.path.exists(path):
        return False
    if os.environ.get("KV_APPLY_WIN_ACL", "0") != "1":
        return False
    user = _windows_user()
    if not user:
        return False
    # 先授予当前用户完全控制，再切断继承，最后移除常见宽泛组（若存在）
    cmds = [
        ["icacls", path, "/grant:r", f"{user}:(OI)(CI)F"],
        ["icacls", path, "/inheritance:r"],
        ["icacls", path, "/grant:r", f"{user}:(OI)(CI)F"],
        ["icacls", path, "/remove:g", "Users"],
        ["icacls", path, "/remove:g", "Everyone"],
        ["icacls", path, "/remove:g", "Authenticated Users"],
    ]
    ok = True
    for cmd in cmds:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode != 0 and "/remove:g" in cmd:
                continue
            if proc.returncode != 0:
                ok = False
                print(
                    f"[WARN] icacls failed ({proc.returncode}): {' '.join(cmd)}: {proc.stderr.strip()[:200]}",
                    file=sys.stderr,
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"[WARN] icacls error {path}: {exc}", file=sys.stderr)
            ok = False
    return ok


def acl_status(path: str) -> dict:
    """诊断：平台与权限相关信息。"""
    info = {
        "platform": "windows" if os.name == "nt" else "posix",
        "path": path,
        "exists": os.path.exists(path),
        "chmod_mode": None,
        "win_acl_opt_in": os.environ.get("KV_APPLY_WIN_ACL", "0") == "1",
        "icacls_available": os.name == "nt",
    }
    try:
        info["chmod_mode"] = oct(os.stat(path).st_mode & 0o777)
    except OSError:
        pass
    return info
