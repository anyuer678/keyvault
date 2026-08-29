"""gui.py — tkinter 桌面前端（kv gui）。

安全约束（与 CLI 一致）：
- 主密钥仅存本进程内存（_key 实例属性），永不写盘
- 列表/表格永不含明文值；查看/复制为单条显式操作
- 删除/导入备份需二次确认
"""

import os
import sqlite3
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import config
from . import store
from . import vault

_PROVIDERS = ["openai", "deepseek", "anthropic", "github", "aws", "azure", "google"]


# ---------- 可测试纯逻辑（不依赖 Tk） ----------

def validate_expires(s: str) -> bool:
    """过期日期校验：空或 YYYY-MM-DD 合法。"""
    if not s:
        return True
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def mask(value: str) -> str:
    """打码显示：sk-ab…****cd34。"""
    if len(value) <= 8:
        return "*" * 8
    return f"{value[:4]}…****{value[-4:]}"


def is_expired(expires: str | None) -> bool:
    """到期判断（YYYY-MM-DD 字符串比较）。"""
    return bool(expires) and expires < datetime.now().strftime("%Y-%m-%d")


def add_entry(repo: store.VaultRepo, key: bytes, name: str, provider: str,
              value: str, expires: str) -> None:
    """表单校验 + 加密入库；失败抛 ValueError。"""
    name = name.strip()
    provider = provider.strip()
    expires = expires.strip()
    if not name or not value:
        raise ValueError("名称与密钥值不能为空")
    if repo.get(name) is not None:
        raise ValueError(f"已存在同名条目 {name}")
    if not validate_expires(expires):
        raise ValueError("过期日期格式须为 YYYY-MM-DD")
    repo.insert(vault.encrypt_entry(key, name, provider, value, expires or None))


def update_entry(repo: store.VaultRepo, key: bytes, name: str, provider: str,
                 value: str, expires: str) -> None:
    """表单校验 + 更新；provider/value/expires 为空表示保持不变。"""
    entry = repo.get(name)
    if entry is None:
        raise ValueError(f"条目不存在 {name}")
    provider = provider.strip()
    expires = expires.strip()
    if not validate_expires(expires):
        raise ValueError("过期日期格式须为 YYYY-MM-DD")
    new_provider = provider if provider else entry.provider
    new_value = value if value else vault.decrypt_entry(key, entry)
    new_expires = expires if expires else entry.expires_at
    repo.update(name, vault.encrypt_entry(key, entry.name, new_provider,
                                          new_value, new_expires))


# ---------- 对话框 ----------

class UnlockDialog(tk.Toplevel):
    """主密码输入框（show=*），返回密码或 None。"""

    def __init__(self, master: tk.Misc, title: str = "解锁"):
        super().__init__(master)
        self.title(title)
        self._result: str | None = None
        self.resizable(False, False)
        self.transient(master)
        self.wait_visibility()
        self.grab_set()
        tk.Label(self, text="主密码:").grid(row=0, column=0, padx=8, pady=8)
        self.entry = tk.Entry(self, show="*", width=28)
        self.entry.grid(row=0, column=1, padx=8, pady=8)
        self.entry.bind("<Return>", lambda _e: self._ok())
        tk.Button(self, text="确定", width=10, command=self._ok).grid(
            row=1, column=0, padx=8, pady=8)
        tk.Button(self, text="取消", width=10, command=self.destroy).grid(
            row=1, column=1, padx=8, pady=8)
        self.entry.focus_set()

    def _ok(self) -> None:
        self._result = self.entry.get()
        self.destroy()

    def result(self) -> str | None:
        return self._result


class AddEditDialog(tk.Toplevel):
    """添加/编辑条目对话框；返回 dict 或 None。"""

    def __init__(self, master: tk.Misc, title: str,
                 entry: vault.EncryptedEntry | None = None):
        super().__init__(master)
        self.title(title)
        self._result: dict | None = None
        self.resizable(False, False)
        self.transient(master)
        self.wait_visibility()
        self.grab_set()
        body = tk.Frame(self)
        body.pack(padx=10, pady=10)
        rows = [
            ("名称", tk.Entry(body, width=30)),
            ("供应商", ttk.Combobox(body, values=_PROVIDERS, width=28)),
            ("密钥值", tk.Entry(body, width=30, show="*")),
            ("过期 YYYY-MM-DD", tk.Entry(body, width=30)),
        ]
        self.widgets = {}
        for i, (label, w) in enumerate(rows):
            tk.Label(body, text=label).grid(row=i, column=0, sticky="w", pady=3)
            w.grid(row=i, column=1, pady=3)
            self.widgets[label] = w
        if entry is not None:
            self.widgets["名称"].insert(0, entry.name)
            self.widgets["名称"].config(state="disabled")
            self.widgets["供应商"].set(entry.provider)
            self.widgets["过期 YYYY-MM-DD"].insert(0, entry.expires_at or "")
            self.widgets["密钥值"].insert(0, "")
        btns = tk.Frame(self)
        btns.pack(pady=8)
        tk.Button(btns, text="保存", width=10, command=self._ok).pack(side="left", padx=6)
        tk.Button(btns, text="取消", width=10, command=self.destroy).pack(side="left", padx=6)

    def _ok(self) -> None:
        self._result = {
            "name": self.widgets["名称"].get(),
            "provider": self.widgets["供应商"].get(),
            "value": self.widgets["密钥值"].get(),
            "expires": self.widgets["过期 YYYY-MM-DD"].get(),
        }
        self.destroy()

    def result(self) -> dict | None:
        return self._result


# ---------- 主窗口 ----------

class GuiApp(tk.Tk):
    """KeyVault 桌面前端主窗口。"""

    def __init__(self):
        super().__init__()
        self.title("KeyVault — API 密钥保险箱")
        self.geometry("760x480")
        self._repo = store.VaultRepo(config.vault_path())
        self._key: bytes | None = None
        self._build_ui()
        self._refresh_list()

    # ---- 界面 ----

    def _build_ui(self) -> None:
        top = tk.Frame(self)
        top.pack(fill="x", padx=8, pady=6)
        self.lock_btn = tk.Button(top, text="解锁", width=10, command=self._unlock)
        self.lock_btn.pack(side="left")
        tk.Button(top, text="刷新", width=8, command=self._refresh_list).pack(side="left", padx=6)
        tk.Button(top, text="查看/复制", width=10, command=self._on_view).pack(side="left")
        tk.Button(top, text="添加", width=8, command=self._on_add).pack(side="left", padx=6)
        tk.Button(top, text="编辑", width=8, command=self._on_edit).pack(side="left")
        tk.Button(top, text="删除", width=8, command=self._on_delete).pack(side="left", padx=6)
        tk.Button(top, text="导出备份", width=9, command=self._on_export).pack(side="left")
        tk.Button(top, text="导入备份", width=9, command=self._on_import).pack(side="left", padx=6)
        tk.Button(top, text="退出", width=8, command=self.destroy).pack(side="right")

        cols = ("name", "provider", "expires", "status")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        headers = {"name": "NAME", "provider": "PROVIDER",
                   "expires": "EXPIRES", "status": "STATUS"}
        for c in cols:
            self.tree.heading(c, text=headers[c])
            self.tree.column(c, width=170 if c == "name" else 130, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8)
        self.tree.bind("<Double-1>", lambda _e: self._on_view())

        self.status = tk.Label(self, text="", anchor="w", relief="sunken")
        self.status.pack(fill="x", side="bottom")

    # ---- 动作 ----

    def _unlock(self) -> None:
        """解锁（vault 不存在则先创建）。"""
        if not self._repo.exists():
            if not messagebox.askyesno("初始化", "vault 不存在，是否创建？（主密码丢失 = 数据不可恢复）"):
                return
            dlg = UnlockDialog(self, "设置主密码（≥8 位）")
            self.wait_window(dlg)
            p1 = dlg.result()
            dlg2 = UnlockDialog(self, "再次输入主密码")
            self.wait_window(dlg2)
            p2 = dlg2.result()
            if not p1 or p1 != p2:
                messagebox.showerror("错误", "密码为空或两次输入不一致")
                return
            if len(p1) < 8:
                messagebox.showerror("错误", "主密码必须 ≥8 位")
                return
            config.ensure_vault_dir()
            salt = os.urandom(16)
            header = vault.VaultHeader(version=1, salt=salt, kdf="scrypt")
            self._repo.init(header)
            key = vault.derive_key(p1, salt)
            self._repo.set_check(key)
            self._key = key
            self._set_status("已初始化并解锁；请立即 kv export-backup 导出加密备份")
            self._refresh_list()
            return
        dlg = UnlockDialog(self, "解锁")
        self.wait_window(dlg)
        passphrase = dlg.result()
        if not passphrase:
            return
        key = vault.derive_key(passphrase, self._repo.load_header().salt)
        if not self._repo.verify_check(key):
            messagebox.showerror("错误", "无法解锁：主密码错误")
            return
        self._key = key
        self._set_status("已解锁（主密钥仅存内存）")

    def _require_key(self) -> bool:
        if self._key is None:
            messagebox.showwarning("提示", "请先解锁")
            return False
        return True

    def _refresh_list(self) -> None:
        for i in self.tree.get_children():
            self.tree.delete(i)
        if not self._repo.exists():
            self._set_status(f"vault 不存在：{self._repo.path}（点击“解锁”创建）")
            return
        for e in self._repo.list_all():
            status = "EXPIRED" if is_expired(e.expires_at) else ""
            self.tree.insert("", "end", values=(
                e.name, e.provider or "-", e.expires_at or "-", status))
        locked = "已解锁" if self._key is not None else "未解锁"
        self._set_status(f"vault：{self._repo.path} | {locked} | 共 {len(self.tree.get_children())} 条")

    def _set_status(self, text: str) -> None:
        self.status.config(text=text)

    def _selected_name(self) -> str | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return self.tree.item(sel[0], "values")[0]

    def _on_view(self) -> None:
        """单条显式查看：解密后弹窗显示 + 复制按钮。"""
        if not self._require_key():
            return
        name = self._selected_name()
        if name is None:
            messagebox.showinfo("提示", "请先选中一行")
            return
        entry = self._repo.get(name)
        if entry is None:
            return
        try:
            value = vault.decrypt_entry(self._key, entry)
        except ValueError:
            messagebox.showerror("错误", "完整性校验失败：密文或名称被篡改")
            return
        top = tk.Toplevel(self)
        top.title(f"查看 {name}")
        top.transient(self)
        tk.Label(top, text=f"名称: {name}   供应商: {entry.provider or '-'}").pack(padx=10, pady=6)
        tk.Label(top, text=value, font=("Consolas", 11), fg="#0b5394").pack(padx=10, pady=4)
        btn = tk.Button(top, text="复制到剪贴板", command=lambda: self._copy(value))
        btn.pack(pady=8)
        tk.Button(top, text="关闭", command=top.destroy).pack(pady=4)

    def _copy(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)

    def _on_add(self) -> None:
        if not self._require_key():
            return
        dlg = AddEditDialog(self, "添加条目")
        self.wait_window(dlg)
        data = dlg.result()
        if data is None:
            return
        try:
            add_entry(self._repo, self._key, data["name"], data["provider"],
                      data["value"], data["expires"])
        except ValueError as e:
            messagebox.showerror("错误", str(e))
            return
        self._refresh_list()

    def _on_edit(self) -> None:
        if not self._require_key():
            return
        name = self._selected_name()
        if name is None:
            messagebox.showinfo("提示", "请先选中一行")
            return
        entry = self._repo.get(name)
        if entry is None:
            return
        dlg = AddEditDialog(self, f"编辑 {name}", entry)
        self.wait_window(dlg)
        data = dlg.result()
        if data is None:
            return
        try:
            update_entry(self._repo, self._key, name, data["provider"],
                         data["value"], data["expires"])
        except ValueError as e:
            messagebox.showerror("错误", str(e))
            return
        self._refresh_list()

    def _on_delete(self) -> None:
        if not self._require_key():
            return
        name = self._selected_name()
        if name is None:
            messagebox.showinfo("提示", "请先选中一行")
            return
        if not messagebox.askyesno("确认删除", f"确定删除 {name}？此操作不可撤销"):
            return
        self._repo.delete(name)
        self._refresh_list()

    def _on_export(self) -> None:
        if not self._require_key():
            return
        path = filedialog.asksaveasfilename(
            title="导出加密备份", defaultextension=".db",
            initialfile="keyvault-backup.db")
        if not path:
            return
        try:
            self._repo.export(path)
        except (OSError, sqlite3.Error) as e:
            messagebox.showerror("错误", f"导出失败：{e}")
            return
        self._set_status(f"已导出加密备份：{path}")

    def _on_import(self) -> None:
        if not self._require_key():
            return
        path = filedialog.askopenfilename(title="选择备份文件", filetypes=[("db", "*.db")])
        if not path:
            return
        if not messagebox.askyesno(
                "确认导入", "导入将覆盖当前 vault，且需重新解锁。继续？"):
            return
        try:
            self._repo.import_from(path)
        except (ValueError, OSError, sqlite3.Error) as e:
            messagebox.showerror("错误", f"导入失败：{e}")
            return
        self._key = None  # 库头 salt 可能变化，强制重新解锁
        self._set_status("已导入备份，请重新解锁")
        self._refresh_list()


def main() -> None:
    GuiApp().mainloop()
