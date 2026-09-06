"""tests/test_webui.py — Web 前端安全行为：Host 校验、会话隔离、解锁限速。"""

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from keyvault import config, store, vault, webui

PASSWORD = "webui-test-pass"
SECRET = "sk-webui-secret-1234"


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("KV_DIR", str(tmp_path))
    r = store.VaultRepo(config.vault_path())
    r.init(vault.VaultHeader(version=1, salt=os.urandom(16), kdf="scrypt"))
    r.set_check(vault.derive_key(PASSWORD, r.load_header().salt))

    webui._SESSIONS.clear()
    webui._UNLOCK_FAILS.clear()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), webui.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()
    webui._SESSIONS.clear()
    webui._UNLOCK_FAILS.clear()


def _post(url, payload, headers=None):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    # 直连本机，绕过系统代理（代理会改写 Host 破坏 rebinding 用例）
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _unlock(base, passphrase=PASSWORD, headers=None):
    return _post(base + "/api/unlock", {"passphrase": passphrase}, headers)


def _add(base, session, name="deepseek", value=SECRET):
    return _post(base + "/api/add", {"name": name, "value": value, "provider": "deepseek"},
                 {"X-Session": session})


def _get(base, session, name="deepseek", full=False):
    return _post(base + "/api/get", {"name": name, "full": full}, {"X-Session": session})


def test_unlock_returns_session_and_add_get_roundtrip(server):
    status, data = _unlock(server)
    assert status == 200 and data["ok"] is True
    token = data["session"]
    assert token

    status, data = _add(server, token)
    assert data["ok"] is True

    status, data = _get(server, token)
    assert data["ok"] is True and data["value"] != SECRET  # 默认打码
    status, data = _get(server, token, full=True)
    assert data["ok"] is True and data["value"] == SECRET


def test_api_requires_session(server):
    # 无会话直接调受保护接口 → 401
    status, data = _add(server, "")
    assert status == 401 and data["ok"] is False
    status, data = _post(server + "/api/get", {"name": "x"}, {})
    assert status == 401


def test_fake_session_rejected(server):
    status, data = _add(server, "forged-token")
    assert status == 401


def test_lock_drops_session(server):
    _, data = _unlock(server)
    token = data["session"]
    _post(server + "/api/lock", {}, {"X-Session": token})
    status, _ = _add(server, token)
    assert status == 401


def test_dns_rebinding_host_rejected(server):
    """rebinding：攻击者域名解析到 127.0.0.1，但 Host 头仍是攻击者域名 → 拒绝。"""
    status, data = _unlock(server, headers={"Host": "evil.example.com"})
    assert status == 403 and "cross-origin" in data.get("error", "")


def test_cross_origin_request_rejected(server):
    """携带外部 Origin 的跨站请求 → 拒绝。"""
    status, data = _post(server + "/api/unlock", {"passphrase": "x"},
                         {"Origin": "http://evil.example.com"})
    assert status == 403


def test_localhost_origin_accepted(server):
    status, data = _post(server + "/api/unlock", {"passphrase": PASSWORD},
                         {"Origin": "http://localhost:8765"})
    assert status == 200 and data["ok"] is True


def test_unlock_rate_limited(server):
    for _ in range(5):
        _, data = _unlock(server, passphrase="wrong-password")
        assert data["ok"] is False
    # 第 6 次即使密码正确也被限速拦截
    _, data = _unlock(server)
    assert data["ok"] is False and "过多" in data["error"]


def test_session_ttl_expiry(server, monkeypatch):
    _, data = _unlock(server)
    token = data["session"]
    _add(server, token)
    # 把会话时间戳拨老，超过 TTL → 视为过期
    with webui._LOCK:
        webui._SESSIONS[token]["last_used"] -= webui._SESSION_TTL_S + 1
    status, _ = _get(server, token)
    assert status == 401
