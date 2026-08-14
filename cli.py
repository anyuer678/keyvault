"""cli.py — 全部子命令（kv 入口）。"""

import argparse
import getpass
import json
import os
import shlex
import sys
from datetime import datetime

import audit as audit_mod
import config
import store
import vault

_KEY: bytes | None = None

_ENV_NAMES = {
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "github": "GITHUB_TOKEN",
    "aws": "AWS_ACCESS_KEY_ID",
    "azure": "AZURE_OPENAI_API_KEY",
    "google": "GOOGLE_API_KEY",
}

_ROTATE_URLS = {
    "github": "https://github.com/settings/tokens",
    "openai": "https://platform.openai.com/api-keys",
    "deepseek": "https://platform.deepseek.com/api_keys",
    "anthropic": "https://console.anthropic.com/settings/keys",
    "google": "https://console.cloud.google.com/apis/credentials",
    "azure": "https://portal.azure.com",
    "aws": "https://console.aws.amazon.com/iam/home#/security_credentials",
}


def _repo() -> store.VaultRepo:
    return store.VaultRepo(config.vault_path())


def _ensure_key(prompt: str = "主密码: ", force: bool = False) -> bytes:
    """返回进程内存主密钥；密码来自 KV_PASS 或交互输入，失败即退出。"""
    global _KEY
    if _KEY is not None and not force:
        return _KEY
    repo = _repo()
    if not repo.exists():
        sys.exit("vault 不存在：请先运行 kv init")
    passphrase = os.environ.get("KV_PASS")
    if not passphrase:
        passphrase = getpass.getpass(prompt)
    key = vault.derive_key(passphrase, repo.load_header().salt)
    if not repo.verify_check(key):
        sys.exit("无法解锁：主密码错误")
    _KEY = key
    return key


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * 8
    return f"{value[:4]}…****{value[-4:]}"


def _env_name(provider: str) -> str:
    if provider in _ENV_NAMES:
        return _ENV_NAMES[provider]
    return f"{provider.upper().replace('-', '_')}_API_KEY"


def cmd_init(args) -> None:
    repo = _repo()
    if repo.exists():
        sys.exit(f"vault 已存在：{repo.path}")
    config.ensure_vault_dir()
    passphrase = os.environ.get("KV_PASS")
    if not passphrase:
        passphrase = getpass.getpass("设置主密码（≥8 位）: ")
        confirm = getpass.getpass("再次输入主密码: ")
        if confirm != passphrase:
            sys.exit("两次输入不一致")
    if len(passphrase) < 8:
        sys.exit("主密码必须 ≥8 位")
    salt = os.urandom(16)
    header = vault.VaultHeader(version=1, salt=salt, kdf="scrypt")
    repo.init(header)
    key = vault.derive_key(passphrase, salt)
    repo.set_check(key)
    global _KEY
    _KEY = key
    print(f"vault 已创建：{repo.path}")
    print("警示：主密码丢失 = 数据不可恢复，请立即导出加密备份（kv export-backup <file>）")


def cmd_unlock(args) -> None:
    _ensure_key(force=True)
    print("已解锁（主密钥仅存于进程内存，退出即失效）")


def cmd_add(args) -> None:
    key = _ensure_key()
    repo = _repo()
    if repo.get(args.name) is not None:
        sys.exit(f"已存在同名条目 {args.name}（如需修改请用 kv edit）")
    if args.expires:
        try:
            datetime.strptime(args.expires, "%Y-%m-%d")
        except ValueError:
            sys.exit("--expires 格式须为 YYYY-MM-DD")
    if args.stdin:
        value = sys.stdin.read().strip().lstrip("\ufeff")
        if not value:
            sys.exit("stdin 为空")
    else:
        value = getpass.getpass(f"输入 {args.name} 的密钥值: ")
        if not value:
            sys.exit("密钥值不能为空")
    repo.insert(vault.encrypt_entry(key, args.name, args.provider, value, args.expires))
    print(f"已保存 {args.name}（provider={args.provider or '未指定'}）")


def cmd_get(args) -> None:
    key = _ensure_key()
    entry = _repo().get(args.name)
    if entry is None:
        sys.exit(f"未找到 {args.name}")
    try:
        value = vault.decrypt_entry(key, entry)
    except ValueError:
        sys.exit("完整性校验失败：密文或名称被篡改")
    print(value if args.full else _mask(value))
    if entry.expires_at and entry.expires_at < datetime.now().strftime("%Y-%m-%d"):
        print(f"（该条目已过期：{entry.expires_at}，请轮换）", file=sys.stderr)


def cmd_list(args) -> None:
    repo = _repo()
    if not repo.exists():
        sys.exit("vault 不存在：请先运行 kv init")
    print(f"{'NAME':<20} {'PROVIDER':<12} {'EXPIRES':<12} STATUS")
    today = datetime.now().strftime("%Y-%m-%d")
    for e in repo.list_all():
        expired = bool(e.expires_at) and e.expires_at < today
        status = "EXPIRED" if expired else ""
        print(f"{e.name:<20} {e.provider or '-':<12} {(e.expires_at or '-'):<12} {status}")


def cmd_use(args) -> None:
    key = _ensure_key()
    entry = _repo().get(args.name)
    if entry is None:
        sys.exit(f"未找到 {args.name}")
    try:
        value = vault.decrypt_entry(key, entry)
    except ValueError:
        sys.exit("完整性校验失败：密文或名称被篡改")
    env_name = _env_name(entry.provider)
    if args.dotenv:
        if os.path.islink(args.dotenv):
            sys.exit("拒绝写入符号链接：" + args.dotenv)
        tmp = args.dotenv + ".tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            sys.exit(f"拒绝写入已存在的 {tmp}（防符号链接跟随）")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(f"{env_name}={shlex.quote(value)}\n")
            config.chmod_0600(tmp)
            os.replace(tmp, args.dotenv)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        config.chmod_0600(args.dotenv)
        print(f"已写入 {args.dotenv}（0600 权限）；请用后删除，勿提交到 git")
        return
    shell = args.shell or "bash"
    if shell == "fish":
        print(f"set -gx {env_name} {shlex.quote(value)}")
    else:
        print(f"export {env_name}={shlex.quote(value)}")
    print(f"# 用法：eval \"$(kv use {args.name})\"", file=sys.stderr)


def cmd_edit(args) -> None:
    key = _ensure_key()
    repo = _repo()
    entry = repo.get(args.name)
    if entry is None:
        sys.exit(f"未找到 {args.name}")
    print(f"编辑 {args.name}（provider={entry.provider or '-'}，过期={entry.expires_at or '无'}）")
    new_value = getpass.getpass("新密钥值（直接回车保持不变）: ")
    expires = input(f"新过期日期 YYYY-MM-DD（直接回车保持 {entry.expires_at or '无'}）: ").strip()
    if expires:
        try:
            datetime.strptime(expires, "%Y-%m-%d")
        except ValueError:
            sys.exit("过期日期格式须为 YYYY-MM-DD")
    if not new_value and not expires:
        print("无变更")
        return
    if not new_value:
        try:
            value = vault.decrypt_entry(key, entry)
        except ValueError:
            sys.exit("完整性校验失败：密文或名称被篡改")
    else:
        value = new_value
    new_expires = entry.expires_at if not expires else expires
    repo.update(entry.name, vault.encrypt_entry(key, entry.name, entry.provider, value, new_expires))
    print("已更新")


def cmd_delete(args) -> None:
    repo = _repo()
    if repo.get(args.name) is None:
        sys.exit(f"未找到 {args.name}")
    if not args.yes:
        try:
            answer = input(f"确认删除 {args.name}？输入 yes 确认: ").strip().lstrip("\ufeff").lower()
        except EOFError:
            print("已取消（非交互环境请用 kv delete --yes）")
            return
        if answer != "yes":
            print("已取消")
            return
    repo.delete(args.name)
    print(f"已删除 {args.name}")


def cmd_audit(args) -> None:
    findings = audit_mod.scan_dir(args.dir)
    if args.json:
        print(json.dumps(
            [{"file": f.file, "key_name": f.key_name} for f in findings],
            ensure_ascii=False, indent=2,
        ))
        return
    if not findings:
        print(f"未发现明文密钥文件（{args.dir}）")
        return
    for f in findings:
        print(f"{f.file} | {f.key_name} | REDACTED（值已打码，不打印）")
    print(f"共 {len(findings)} 处命中（仅报告，未写入任何文件）")
    if args.fix_0600:
        for f in findings:
            config.chmod_0600(f.file)
        print("已对命中文件执行 chmod 0600")


def cmd_rotate(args) -> None:
    url = _ROTATE_URLS.get(args.provider)
    if url:
        print(f"{args.provider} 密钥轮换指引：请登录 {url} 撤销旧密钥并生成新密钥")
    else:
        print(f"未内置 {args.provider} 的轮换指引；请前往该服务官网的安全设置页轮换密钥")
    print("轮换后请用 kv edit <name> 更新本地密文")


def cmd_export_backup(args) -> None:
    repo = _repo()
    if not repo.exists():
        sys.exit("vault 不存在：请先运行 kv init")
    repo.export(args.path)
    print(f"备份已导出：{args.path}（加密内容 + header，恢复需主密码）")


def cmd_import_backup(args) -> None:
    repo = _repo()
    if not repo.exists():
        sys.exit("vault 不存在：请先运行 kv init")
    try:
        answer = input("导入将覆盖当前 vault，输入 yes 确认: ").strip().lstrip("\ufeff").lower()
    except EOFError:
        print("已取消（非交互环境请通过管道输入 yes）")
        return
    if answer != "yes":
        print("已取消")
        return
    repo.import_from(args.path)
    print("备份已导入")


def cmd_shell_init(args) -> None:
    shell = args.shell or "bash"
    if shell == "fish":
        print('alias kvg "kv use"')
    else:
        print("alias kvg='kv use'")


def cmd_gui(args) -> None:
    """启动 tkinter 桌面前端（延迟 import，避免无显示环境受影响）。"""
    try:
        import gui
    except Exception as e:
        sys.exit(f"无法启动 GUI：{e}")
    gui.main()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kv", description="个人 API 密钥保险箱（KeyVault）")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="创建 vault（主密码 ≥8 位）")
    sub.add_parser("unlock", help="解锁（密码经 stdin / 环境变量 KV_PASS）")

    p_add = sub.add_parser("add", help="加密入库")
    p_add.add_argument("name")
    p_add.add_argument("--provider", default="")
    p_add.add_argument("--expires", help="过期日期 YYYY-MM-DD")
    p_add.add_argument("--stdin", action="store_true", help="从 stdin 读取密钥值")

    p_get = sub.add_parser("get", help="解密输出（默认仅显示后 4 位）")
    p_get.add_argument("name")
    p_get.add_argument("--full", action="store_true", help="显示完整值")

    sub.add_parser("list", help="列出名称/供应商/过期日期（永不含值）")

    p_use = sub.add_parser("use", help="输出 export 行或写入临时 .env")
    p_use.add_argument("name")
    p_use.add_argument("--shell", choices=["bash", "zsh", "fish"])
    p_use.add_argument("--dotenv", help="写入 .env 文件（0600）")

    p_edit = sub.add_parser("edit", help="交互修改值/到期日")
    p_edit.add_argument("name")

    p_del = sub.add_parser("delete", help="删除（需二次确认）")
    p_del.add_argument("name")
    p_del.add_argument("--yes", action="store_true", help="跳过确认")

    p_audit = sub.add_parser("audit", help="扫描 .env 明文密钥（只读）")
    p_audit.add_argument("--dir", default=".")
    p_audit.add_argument("--json", action="store_true")
    p_audit.add_argument("--fix-0600", action="store_true", help="对命中文件修复权限")

    p_rot = sub.add_parser("rotate", help="打印轮换指引 URL")
    p_rot.add_argument("--provider", required=True)

    p_exp = sub.add_parser("export-backup", help="导出加密备份")
    p_exp.add_argument("path")
    p_imp = sub.add_parser("import-backup", help="导入加密备份（原子替换）")
    p_imp.add_argument("path")

    p_sh = sub.add_parser("shell-init", help="生成 shell alias")
    p_sh.add_argument("--shell", choices=["bash", "zsh", "fish"])

    sub.add_parser("gui", help="启动桌面 GUI（tkinter，Windows 原生）")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _dispatch(args)
    return 0


def _dispatch(args) -> None:
    cmds = {
        "init": cmd_init,
        "unlock": cmd_unlock,
        "add": cmd_add,
        "get": cmd_get,
        "list": cmd_list,
        "use": cmd_use,
        "edit": cmd_edit,
        "delete": cmd_delete,
        "audit": cmd_audit,
        "rotate": cmd_rotate,
        "export-backup": cmd_export_backup,
        "import-backup": cmd_import_backup,
        "shell-init": cmd_shell_init,
        "gui": cmd_gui,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
