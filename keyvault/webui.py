"""webui — KeyVault 个人 API 密钥保险箱 Web 前端（零第三方依赖）。

用法：
    python webui.py [--port 8765] [--host 127.0.0.1]
浏览器打开 http://127.0.0.1:8765 即可。

接口：
    GET  /               单页应用（内嵌 HTML/JS/CSS）
    GET  /api/status     {exists, unlocked}        unlocked 按请求携带的会话判定
    POST /api/unlock     {passphrase}              解锁，返回一次性会话 token（主密钥仅存进程内存）
    POST /api/lock       清除当前会话
    GET  /api/entries    列出条目（仅名称/供应商/过期/状态，永不含值）
    POST /api/add        {name, provider, expires, value}   加密入库
    POST /api/get        {name, full}            摘要（默认）或完整值（显式）
    POST /api/delete     {name}                  删除（页面需二次确认）
    POST /api/rotate     {provider}              轮换指引 URL（不联网）
    POST /api/audit      {dir}                   明文密钥扫描（只读，值打码）
    POST /api/export     {path}                  导出加密备份
    POST /api/import     {path}                  导入备份（原子替换，需 confirm）

会话：除 unlock 外的所有接口都要求请求头 X-Session 携带 unlock 返回的 token；
会话 15 分钟滑动过期，到期或 lock 后必须重新输入主密码。任何进程在网页解锁
之前都无法读取密钥。

安全：仅本机默认监听；Host 头必须是 127.0.0.1/localhost（防 DNS rebinding）；
带 Origin 的跨站请求一律拒绝；解锁失败限速；主密码经页面输入后只在进程内存
派生密钥（与 CLI 相同信任模型）；任何列表/状态接口都不返回密钥值；完整值
输出需显式请求且页面二次确认。请勿暴露到公网。
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import audit as audit_mod
from . import config
from . import store
from . import vault

_LOCK = threading.Lock()
# 会话表：token -> {"key": 主密钥, "last_used": 时间戳}；仅存进程内存，不落盘
_SESSIONS: dict[str, dict] = {}
_SESSION_TTL_S = 900  # 15 分钟滑动过期
# 解锁失败时间戳（滑动窗口限速）
_UNLOCK_FAILS: list[float] = []
_UNLOCK_MAX_FAILS = 5
_UNLOCK_WINDOW_S = 60.0

_PROVIDERS = ("", "openai", "deepseek", "anthropic", "github", "google", "azure", "aws")


def _repo() -> store.VaultRepo:
    return store.VaultRepo(config.vault_path())


def _session_key(token: str | None) -> bytes | None:
    """校验会话 token，有效则滑动续期并返回主密钥，否则 None。"""
    if not token:
        return None
    now = time.time()
    with _LOCK:
        sess = _SESSIONS.get(token)
        if not sess:
            return None
        if now - sess["last_used"] > _SESSION_TTL_S:
            del _SESSIONS[token]
            return None
        sess["last_used"] = now
        return sess["key"]


def _drop_session(token: str | None) -> None:
    if token:
        with _LOCK:
            _SESSIONS.pop(token, None)


def _status(has_session: bool) -> dict:
    repo = _repo()
    return {"exists": repo.exists(), "unlocked": has_session,
            "path": config.vault_path()}


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * 8
    return f"{value[:4]}…****{value[-4:]}"


def api_status(has_session: bool) -> dict:
    return _status(has_session)


def api_unlock(payload: dict) -> dict:
    now = time.time()
    with _LOCK:
        _UNLOCK_FAILS[:] = [t for t in _UNLOCK_FAILS if now - t < _UNLOCK_WINDOW_S]
        if len(_UNLOCK_FAILS) >= _UNLOCK_MAX_FAILS:
            return {"ok": False,
                    "error": "解锁失败次数过多，请 1 分钟后再试"}
    passphrase = (payload.get("passphrase") or "").strip()
    if not passphrase:
        return {"ok": False, "error": "请输入主密码"}
    repo = _repo()
    if not repo.exists():
        return {"ok": False, "error": "vault 不存在，请先通过 CLI 执行 kv init 创建"}
    key = vault.derive_key(passphrase, repo.load_header().salt)
    if not repo.verify_check(key):
        with _LOCK:
            _UNLOCK_FAILS.append(time.time())
        return {"ok": False, "error": "无法解锁：主密码错误"}
    with _LOCK:
        _UNLOCK_FAILS.clear()
        token = secrets.token_urlsafe(32)
        _SESSIONS[token] = {"key": key, "last_used": time.time()}
    return {"ok": True, "session": token}


def api_lock(token: str | None) -> dict:
    _drop_session(token)
    return {"ok": True}


def api_entries(key: bytes) -> dict:
    repo = _repo()
    today = datetime.now().strftime("%Y-%m-%d")
    items = []
    for e in repo.list_all():
        expired = bool(e.expires_at) and e.expires_at < today
        items.append({
            "name": e.name,
            "provider": e.provider or "-",
            "expires": e.expires_at or "-",
            "status": "EXPIRED" if expired else "",
        })
    return {"ok": True, "items": items}


def api_add(payload: dict, key: bytes) -> dict:
    name = (payload.get("name") or "").strip()
    value = (payload.get("value") or "").strip()
    provider = (payload.get("provider") or "").strip()
    expires = (payload.get("expires") or "").strip()
    if not name:
        return {"ok": False, "error": "名称不能为空"}
    if not value:
        return {"ok": False, "error": "密钥值不能为空"}
    if expires:
        try:
            datetime.strptime(expires, "%Y-%m-%d")
        except ValueError:
            return {"ok": False, "error": "过期日期格式须为 YYYY-MM-DD"}
    repo = _repo()
    if repo.get(name) is not None:
        return {"ok": False, "error": f"已存在同名条目 {name}"}
    repo.insert(vault.encrypt_entry(key, name, provider, value, expires or None))
    return {"ok": True, "name": name}


def api_get(payload: dict, key: bytes) -> dict:
    name = (payload.get("name") or "").strip()
    full = bool(payload.get("full"))
    entry = _repo().get(name)
    if entry is None:
        return {"ok": False, "error": f"未找到 {name}"}
    try:
        value = vault.decrypt_entry(key, entry)
    except vault.IntegrityError:
        return {"ok": False, "error": "完整性校验失败：密文或名称被篡改"}
    return {"ok": True, "value": value if full else _mask(value), "full": full}


def api_delete(payload: dict) -> dict:
    name = (payload.get("name") or "").strip()
    if not name:
        return {"ok": False, "error": "名称不能为空"}
    ok = _repo().delete(name)
    return {"ok": ok, "error": None if ok else f"未找到 {name}"}


def api_rotate(payload: dict) -> dict:
    provider = (payload.get("provider") or "").strip().lower()
    urls = {
        "github": "https://github.com/settings/tokens",
        "openai": "https://platform.openai.com/api-keys",
        "deepseek": "https://platform.deepseek.com/api_keys",
        "anthropic": "https://console.anthropic.com/settings/keys",
        "google": "https://console.cloud.google.com/apis/credentials",
        "azure": "https://portal.azure.com",
        "aws": "https://console.aws.amazon.com/iam/home#/security_credentials",
    }
    if provider in urls:
        return {"ok": True, "url": urls[provider],
                "tip": "请登录后撤销旧密钥并生成新密钥，再用 kv edit <name> 更新本地密文"}
    return {"ok": True, "url": None,
            "tip": "未内置该供应商指引，请前往其官网安全设置页轮换密钥"}


def api_audit(payload: dict) -> dict:
    directory = (payload.get("dir") or ".").strip()
    if not os.path.isdir(directory):
        return {"ok": False, "error": f"目录不存在：{directory}"}
    findings = audit_mod.scan_dir(directory)
    return {"ok": True, "count": len(findings),
            "items": [{"file": f.file, "key_name": f.key_name} for f in findings]}


def _validate_backup_path(path: str) -> str | None:
    """限制备份路径只能在 ~/.keyvault/backups/ 内（含子目录），
    防止通过任意路径读写系统文件。"""
    backups_dir = os.path.join(os.path.expanduser("~"), ".keyvault", "backups")
    abs_path = os.path.abspath(path)
    abs_backups = os.path.abspath(backups_dir)
    try:
        if not abs_path.startswith(abs_backups + os.sep) and abs_path != abs_backups:
            return None
    except Exception:
        return None
    return abs_path


def api_export(payload: dict) -> dict:
    path = (payload.get("path") or "").strip()
    if not path:
        return {"ok": False, "error": "请指定备份路径"}
    safe_path = _validate_backup_path(path)
    if safe_path is None:
        return {"ok": False, "error": "备份路径必须在 ~/.keyvault/backups/ 内"}
    try:
        _repo().export(safe_path)
    except Exception as exc:
        return {"ok": False, "error": f"导出失败：{exc}"}
    return {"ok": True, "path": safe_path}


def api_import(payload: dict) -> dict:
    path = (payload.get("path") or "").strip()
    confirm = payload.get("confirm") == "yes"
    if not path:
        return {"ok": False, "error": "请指定备份路径"}
    safe_path = _validate_backup_path(path)
    if safe_path is None:
        return {"ok": False, "error": "备份路径必须在 ~/.keyvault/backups/ 内"}
    if not confirm:
        return {"ok": False, "need_confirm": True, "error": "导入将覆盖当前 vault，请在页面输入 yes 确认"}
    try:
        _repo().import_from(safe_path)
    except Exception as exc:
        return {"ok": False, "error": f"导入失败：{exc}"}
    return {"ok": True}


def _json_response(handler, obj, status=200):
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "KeyVaultWebUI/0.1"

    def log_message(self, fmt, *args):  # 安静日志，不记录请求内容
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        session = self.headers.get("X-Session")
        if parsed.path in ("/", "/index.html"):
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/status":
            return _json_response(self, api_status(_session_key(session) is not None))
        if parsed.path == "/api/entries":
            key = _session_key(session)
            if key is None:
                return _json_response(self, {"ok": False, "error": "未解锁：请先输入主密码"}, 401)
            return _json_response(self, api_entries(key))
        return _json_response(self, {"error": "not found"}, 404)

    _LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

    def _same_origin(self) -> bool:
        """DNS-rebinding 防线：Host 必须是本机回环地址——攻击者域名的 rebinding
        解析到本机 IP 后，其 Host 头仍是攻击者域名，在此被拒。
        CSRF 防线：浏览器跨站请求必带 Origin，携带 Origin 时其主机名同样
        必须是本机回环地址；非浏览器客户端无 Origin，放行。"""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if host not in self._LOCAL_HOSTS:
            return False
        origin = self.headers.get("Origin")
        if not origin:
            return True
        ohost = (urlparse(origin).hostname or "").lower()
        return ohost in self._LOCAL_HOSTS

    def do_POST(self):
        if not self._same_origin():
            return _json_response(self, {"error": "cross-origin request rejected"}, 403)
        parsed = urlparse(self.path)
        session = self.headers.get("X-Session")
        try:
            raw_len = int(self.headers.get("Content-Length") or 0)
            if raw_len < 0 or raw_len > 1024 * 1024:  # 1MB 上限 + 拒绝负数
                return _json_response(self, {"error": "请求体大小超限（最大 1MB）"}, 413)
            length = raw_len
            payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except (ValueError, UnicodeDecodeError) as exc:
            return _json_response(self, {"error": "请求体不是合法 JSON：%s" % exc}, 400)
        if not isinstance(payload, dict):
            return _json_response(self, {"error": "请求体必须是 JSON 对象"}, 400)
        # 无需会话的路由（unlock/lock）
        open_routes = {
            "/api/unlock": api_unlock,
            "/api/lock": lambda _p: api_lock(session),
        }
        # 需要有效会话的路由；需要主密钥的接口以 key 参数注入
        key_routes = {
            "/api/add": lambda p, key: api_add(p, key),
            "/api/get": lambda p, key: api_get(p, key),
            "/api/entries": lambda p, key: api_entries(key),
        }
        plain_routes = {
            "/api/delete": api_delete,
            "/api/rotate": api_rotate,
            "/api/audit": api_audit,
            "/api/export": api_export,
            "/api/import": api_import,
        }
        try:
            fn = open_routes.get(parsed.path)
            if fn is not None:
                return _json_response(self, fn(payload))
            if parsed.path in key_routes or parsed.path in plain_routes:
                key = _session_key(session)
                if key is None:
                    return _json_response(self, {"ok": False, "error": "未解锁或会话已过期：请重新输入主密码"}, 401)
                kf = key_routes.get(parsed.path)
                if kf is not None:
                    return _json_response(self, kf(payload, key))
                return _json_response(self, plain_routes[parsed.path](payload))
            return _json_response(self, {"error": "not found"}, 404)
        except PermissionError as exc:
            return _json_response(self, {"ok": False, "error": str(exc)}, 401)
        except Exception as exc:  # 服务端兜底，不泄露堆栈
            return _json_response(self, {"ok": False, "error": "服务器错误：%s" % type(exc).__name__}, 500)


def main(argv=None):
    p = argparse.ArgumentParser(prog="keyvault-webui", description="KeyVault Web 前端")
    p.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    p.add_argument("--port", type=int, default=8765, help="监听端口（默认 8765）")
    args = p.parse_args(argv if argv is not None else None)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print("KeyVault Web UI 已启动：http://%s:%d  （Ctrl+C 退出，仅本机可访问）"
          % (args.host, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        server.server_close()


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KeyVault · 个人 API 密钥保险箱</title>
<style>
  :root {
    --kb-color-primary:#374151; --kb-color-success:#4b5563; --kb-color-warning:#6b7280;
    --kb-color-danger:#1f2937; --kb-color-info:#9ca3af;
    --kb-color-bg:#fafaf7; --kb-color-bg-elevated:#f1f0ea; --kb-color-border:#e2e0d8;
    --kb-color-text-1:#27241d; --kb-color-text-2:#57534e; --kb-color-text-3:#a8a29e;
    --kb-radius-sm:4px; --kb-radius-md:6px; --kb-radius-lg:10px; --kb-radius-round:999px;
    --kb-shadow-1:0 1px 2px rgb(0 0 0/5%); --kb-shadow-2:0 4px 12px rgb(0 0 0/8%);
    --kb-font:"Noto Serif SC","Songti SC","SimSun",serif;
    --kb-mono:"Cascadia Code",Consolas,"Courier New",monospace;
    --kb-space-1:4px; --kb-space-2:8px; --kb-space-3:12px; --kb-space-4:16px; --kb-space-5:20px; --kb-space-6:24px;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--kb-color-bg); color:var(--kb-color-text-1);
         font:15px/1.6 var(--kb-font); transition:background .2s,color .2s; }
  .wrap { max-width:920px; margin:0 auto; padding:var(--kb-space-6) var(--kb-space-5) 80px; }
  header h1 { font-size:22px; margin:0; font-weight:600; letter-spacing:.5px; }
  header .sub { color:var(--kb-color-text-3); font-size:13px; margin:6px 0 0; }
  .card { background:var(--kb-color-bg-elevated); border:1px solid var(--kb-color-border);
          border-radius:var(--kb-radius-lg); padding:var(--kb-space-4); margin-bottom:var(--kb-space-4); }
  label { color:var(--kb-color-text-2); font-size:12.5px; display:block; margin:12px 0 4px; }
  input, select {
    background:var(--kb-color-bg); color:var(--kb-color-text-1);
    border:1px solid var(--kb-color-border); border-radius:var(--kb-radius-md);
    padding:9px 11px; font-size:14px; font-family:inherit; width:100%;
    transition:border-color .15s;
  }
  input:focus, select:focus { outline:none; border-color:var(--kb-color-primary); }
  input[type=password] { font-family:var(--kb-mono); }
  .btn { background:var(--kb-color-primary); color:var(--kb-color-bg); border:none;
         border-radius:var(--kb-radius-md); padding:10px 22px; font-size:14.5px;
         font-weight:600; font-family:inherit; cursor:pointer; margin-top:var(--kb-space-3);
         transition:opacity .15s,filter .15s; }
  .btn:hover { filter:brightness(1.08); }
  .btn:disabled { opacity:.5; cursor:wait; }
  .btn.ghost { background:transparent; color:var(--kb-color-primary); border:1px solid var(--kb-color-border); }
  .btn.danger { background:var(--kb-color-danger); }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; }
  .row > div { flex:1; min-width:150px; }
  table { width:100%; border-collapse:collapse; font-size:13.5px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--kb-color-border);
           vertical-align:middle; }
  th { color:var(--kb-color-text-3); font-weight:500; font-size:12px; letter-spacing:1px; }
  .mono { font-family:var(--kb-mono); font-size:12.5px; }
  .badge { display:inline-block; padding:1px 9px; border-radius:var(--kb-radius-round); font-size:11px;
           font-weight:600; }
  .badge.exp { background:color-mix(in srgb,var(--kb-color-danger) 12%,transparent); color:var(--kb-color-danger); }
  .badge.ok { background:color-mix(in srgb,var(--kb-color-success) 12%,transparent); color:var(--kb-color-success); }
  .errbox { background:color-mix(in srgb,var(--kb-color-danger) 8%,transparent);
            border:1px solid color-mix(in srgb,var(--kb-color-danger) 30%,transparent);
            color:var(--kb-color-danger); border-radius:var(--kb-radius-md);
            padding:10px 14px; margin-bottom:var(--kb-space-3); }
  .notice { background:color-mix(in srgb,var(--kb-color-info) 8%,transparent);
            border:1px solid color-mix(in srgb,var(--kb-color-info) 25%,transparent);
            color:var(--kb-color-text-2); border-radius:var(--kb-radius-md);
            padding:10px 14px; margin-bottom:var(--kb-space-4); font-size:13px; }
  .notice b { color:var(--kb-color-text-1); }
  .hidden { display:none; }
  .empty { color:var(--kb-color-text-3); text-align:center; padding:26px 0; font-size:13.5px; }
  .loading { color:var(--kb-color-text-3); text-align:center; padding:26px 0; font-size:13.5px; }
  h2 { font-size:13px; color:var(--kb-color-text-3); margin:0 0 10px; letter-spacing:1.5px;
       text-transform:uppercase; font-weight:500; }
  footer { margin-top:36px; color:var(--kb-color-text-3); font-size:12px; line-height:1.8; }
  code { background:var(--kb-color-bg); border:1px solid var(--kb-color-border);
         border-radius:var(--kb-radius-sm); padding:1px 6px; font-family:var(--kb-mono); font-size:12px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>KeyVault <span class="badge ok" id="stateBadge">未解锁</span></h1>
    <p class="sub">本地加密钥匙串。主密码不落盘，密钥以 AES-256-GCM 密文存于本机。仅本机访问。</p>
  </header>

  <div class="notice">安全约定：主密码只在浏览器会话内派生出主密钥并保存在本进程内存（会话 15 分钟无操作自动上锁）；列表永不含密钥值；
    查看完整值需显式点击并二次确认。请勿将本服务暴露到公网。</div>

  <!-- 解锁面板 -->
  <div class="card" id="unlockCard">
    <h2>解锁</h2>
    <label for="passphrase">主密码</label>
    <div class="row">
      <div><input type="password" id="passphrase" placeholder="输入主密码（vault 由 CLI 的 kv init 创建）" autocomplete="off"></div>
      <div style="flex:0"><button class="btn" id="unlockBtn">解锁</button></div>
    </div>
    <div id="unlockErr" class="errbox hidden" style="margin-top:10px"></div>
  </div>

  <!-- 主面板 -->
  <div id="mainPanel" class="hidden">
    <div class="card">
      <div class="row" style="align-items:center;justify-content:space-between;flex-wrap:wrap">
        <h2 style="margin:0">已保存的密钥</h2>
        <button class="btn ghost" id="lockBtn" style="margin:0">锁定（清除内存密钥）</button>
      </div>
      <div id="entryList"></div>
    </div>

    <div class="card">
      <h2>添加密钥</h2>
      <div class="row">
        <div><label for="aName">名称</label><input type="text" id="aName" placeholder="如 deepseek"></div>
        <div><label for="aProvider">供应商</label>
          <select id="aProvider">
            <option value="">（未指定）</option>
            <option value="openai">openai</option>
            <option value="deepseek">deepseek</option>
            <option value="anthropic">anthropic</option>
            <option value="github">github</option>
            <option value="google">google</option>
            <option value="azure">azure</option>
            <option value="aws">aws</option>
          </select>
        </div>
        <div><label for="aExpires">过期日期（YYYY-MM-DD，可选）</label><input type="text" id="aExpires" placeholder="2027-01-01"></div>
        <div style="flex:2"><label for="aValue">密钥值</label><input type="password" id="aValue" placeholder="sk-... 或 ghp_..."></div>
        <div style="flex:0"><button class="btn" id="addBtn" style="margin:0">加密入库</button></div>
      </div>
      <div id="addErr" class="errbox hidden" style="margin-top:10px"></div>
    </div>

    <div class="card">
      <h2>工具</h2>
      <div class="row">
        <div><label for="rotProvider">轮换指引</label>
          <select id="rotProvider">
            <option value="github">github</option>
            <option value="openai">openai</option>
            <option value="deepseek">deepseek</option>
            <option value="anthropic">anthropic</option>
            <option value="google">google</option>
            <option value="azure">azure</option>
            <option value="aws">aws</option>
          </select>
        </div>
        <div style="flex:0"><button class="btn ghost" id="rotBtn" style="margin:0">获取指引</button></div>
        <div><label for="auditDir">明文密钥扫描目录</label><input type="text" id="auditDir" value="."></div>
        <div style="flex:0"><button class="btn ghost" id="auditBtn" style="margin:0">扫描</button></div>
      </div>
      <div id="toolOut" class="mono" style="margin-top:12px;font-size:12.5px"></div>
    </div>
  </div>

  <div id="status"></div>

  <footer>
    KeyVault · 本地加密密钥保险箱。主密码丢失 = 数据不可恢复，请定期 <code>kv export-backup</code> 导出加密备份。
    <br>完整值显示与删除操作均在页面二次确认；审计扫描只读、值区打码。
  </footer>
</div>

<script>
const $ = id => document.getElementById(id);

/* 会话 token 仅存本页内存：刷新/关闭页面即失效，需重新输入主密码 */
let SESSION = null;

async function post(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: SESSION ? {"Content-Type": "application/json", "X-Session": SESSION}
                     : {"Content-Type": "application/json"},
    body: JSON.stringify(body || {}),
  });
  const data = await r.json();
  if (r.status === 401) { SESSION = null; refresh(); throw new Error(data.error || "会话已过期，请重新解锁"); }
  return data;
}
async function getJSON(path) {
  const r = await fetch(path, {headers: SESSION ? {"X-Session": SESSION} : {}});
  const data = await r.json();
  if (r.status === 401) { SESSION = null; refresh(); throw new Error(data.error || "会话已过期，请重新解锁"); }
  return data;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

async function refresh() {
  const st = await getJSON("/api/status");
  const unlocked = st.unlocked;
  $("unlockCard").classList.toggle("hidden", unlocked);
  $("mainPanel").classList.toggle("hidden", !unlocked);
  $("stateBadge").textContent = unlocked ? "已解锁" : "未解锁";
  $("stateBadge").className = "badge " + (unlocked ? "ok" : "");
  if (unlocked) await loadEntries();
}

async function loadEntries() {
  const box = $("entryList");
  box.innerHTML = '<div class="loading">加载中…</div>';
  const data = await getJSON("/api/entries");
  if (!data.ok) { box.innerHTML = '<div class="empty">' + esc(data.error) + '</div>'; return; }
  if (!data.items.length) { box.innerHTML = '<div class="empty">尚未保存任何密钥</div>'; return; }
  let html = '<table><thead><tr><th>名称</th><th>供应商</th><th>过期</th><th>状态</th><th></th></tr></thead><tbody>';
  for (const it of data.items) {
    html += '<tr>' +
      '<td class="mono">' + esc(it.name) + '</td>' +
      '<td>' + esc(it.provider) + '</td>' +
      '<td class="mono">' + esc(it.expires) + '</td>' +
      '<td>' + (it.status ? '<span class="badge exp">' + esc(it.status) + '</span>' : '') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="btn ghost" data-act="view" data-name="' + esc(it.name) + '" style="margin:0;padding:4px 10px;font-size:12.5px">查看</button> ' +
        '<button class="btn ghost" data-act="del" data-name="' + esc(it.name) + '" style="margin:0;padding:4px 10px;font-size:12.5px">删除</button>' +
      '</td></tr>';
  }
  html += '</tbody></table>';
  box.innerHTML = html;
}

/* 完整值查看：显式请求 + 二次确认 */
async function viewValue(name) {
  if (!confirm("查看「" + name + "」的完整密钥值？该值将显示在本页面。")) return;
  const data = await post("/api/get", {name: name, full: true});
  if (!data.ok) { alert(data.error); return; }
  prompt("「" + name + "」完整密钥值（请勿长期留在屏幕）：", data.value);
}

async function deleteEntry(name) {
  if (!confirm("确认删除「" + name + "」？此操作不可撤销。\n如不确定，请先查看或备份。")) return;
  const answer = prompt("再次输入密钥名称以确认删除：");
  if (answer !== name) { alert("名称不匹配，已取消"); return; }
  const data = await post("/api/delete", {name: name});
  if (!data.ok) { alert(data.error); return; }
  await loadEntries();
}

$("unlockBtn").addEventListener("click", async () => {
  const p = $("passphrase").value;
  if (!p) { $("unlockErr").textContent = "请输入主密码"; $("unlockErr").classList.remove("hidden"); return; }
  $("unlockBtn").disabled = true;
  try {
    const data = await post("/api/unlock", {passphrase: p});
    if (!data.ok) { $("unlockErr").textContent = data.error; $("unlockErr").classList.remove("hidden"); return; }
    $("unlockErr").classList.add("hidden");
    $("passphrase").value = "";
    SESSION = data.session;
    await refresh();
  } finally { $("unlockBtn").disabled = false; }
});
$("passphrase").addEventListener("keydown", e => { if (e.key === "Enter") $("unlockBtn").click(); });

$("lockBtn").addEventListener("click", async () => { await post("/api/lock", {}); await refresh(); });

$("addBtn").addEventListener("click", async () => {
  const body = {
    name: $("aName").value.trim(),
    provider: $("aProvider").value,
    expires: $("aExpires").value.trim(),
    value: $("aValue").value,
  };
  const data = await post("/api/add", body);
  if (!data.ok) { $("addErr").textContent = data.error; $("addErr").classList.remove("hidden"); return; }
  $("addErr").classList.add("hidden");
  $("aName").value = ""; $("aValue").value = ""; $("aExpires").value = "";
  await loadEntries();
});

$("rotBtn").addEventListener("click", async () => {
  const data = await post("/api/rotate", {provider: $("rotProvider").value});
  $("toolOut").textContent = data.url ? data.url + "  " + data.tip : data.tip;
});

$("auditBtn").addEventListener("click", async () => {
  $("auditBtn").disabled = true;
  try {
    const data = await post("/api/audit", {dir: $("auditDir").value.trim() || "."});
    if (!data.ok) { $("toolOut").textContent = data.error; return; }
    $("toolOut").textContent = data.count
      ? "发现 " + data.count + " 处明文密钥（值已打码）：\n" + data.items.map(i => i.file + " | " + i.key_name + " | REDACTED").join("\n")
      : "未发现明文密钥（" + ($("auditDir").value || ".") + "）";
  } finally { $("auditBtn").disabled = false; }
});

$("entryList").addEventListener("click", async e => {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const act = btn.dataset.act, name = btn.dataset.name;
  if (act === "view") await viewValue(name);
  else if (act === "del") await deleteEntry(name);
});

refresh().catch(e => { $("status").textContent = "初始化失败：" + e.message; });
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
