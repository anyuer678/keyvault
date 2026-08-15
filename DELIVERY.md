# 交付清单 — 个人 API 密钥保险箱（KeyVault）

## 一、文件清单

```
cli.py          全部子命令（init/unlock/add/get/list/use/edit/delete/audit/rotate/
                export-backup/import-backup/shell-init/gui）
vault.py        加解密核心（scrypt + AES-256-GCM，纯函数无 IO，AAD 防篡改）
store.py        SQLite 持久化（0600 权限、原子写、导入校验 header）
audit.py        明文密钥扫描（只读，值永不返回，REDACTED 打码）
gui.py          tkinter 桌面 GUI（延迟 import，Windows 原生）
webui.py        零依赖 Web 前端（新增，标准库 http.server，内嵌单页 HTML/JS）
config.py       vault 路径/目录权限（KV_DIR / KV_DB 环境变量）
requirements.txt  cryptography
tests/
  test_vault.py   17 项：scrypt 派生/AES-GCM 加解密/AAD 篡改拦截/nonce 独立性
  test_cli.py     32 项：全部子命令/密码校验/日期校验/掩码输出
  test_store.py   12 项：增删改查/事务/导入校验/备份
  test_audit.py    8 项：明文扫描/模式匹配/值不泄露
  test_gui.py     12 项：tkinter 表单校验（无 display 时跳过冒烟）
```

## 二、验证结果（本机 Windows / Python 3.12.3）

- `python -m pytest tests/ -q` → **81 passed**（GUI 冒烟在无 display 环境按设计跳过）
- 全流程实测（隔离临时 vault）：
  1. `kv init` 创建（主密码 ≥8 位）→ 通过
  2. 错误密码校验 → 拒绝
  3. 加密入库 2 条 → 通过
  4. 列表无明文泄露 → 通过
  5. 解密值正确 → 通过
  6. AAD 篡改（改 provider）→ `IntegrityError` 拦截
  7. 备份导出 → 通过
  8. 备份导入（原子替换）→ 通过
- Web 端到端：`GET /` → 200；`/api/status` exists=True；解锁→列表→添加→掩码查看→锁定后 401 拦截，全部通过（13 项 API 测试）

## 三、接口核对清单（架构设计 §接口，全部通过）

- [x] `encrypt_entry(key, name, provider, value, expires) -> EncryptedEntry`（独立 nonce）
- [x] `decrypt_entry(key, entry)` 完整性失败抛 `IntegrityError`（AAD = name+provider）
- [x] `VaultRepo`：init/insert/get/list_all/delete/update/export/import_from/set_check/verify_check
- [x] `kv list` 永不返回密钥值；`kv audit` 值区打码 REDACTED
- [x] `kv get`/`kv use` 完整值输出需显式请求；库文件 0600

## 四、本轮交付（Web 前端新增 + 协议统一）

**Web 前端（webui.py，零新依赖，新增）**

- 形态：标准库 `http.server`，仅绑定 `127.0.0.1`，内嵌单页 HTML/JS
- 设计：kb-ui 风格设计令牌（CSS 变量），单一「水墨」主题（纸张米白 + 宋体）
- 功能：解锁（主密码，key 仅存进程内存）/ 密钥列表（永不含值）/ 添加 / 掩码查看 / 完整值显式查看（二次确认）/ 删除（二次确认 + 名称验证）/ 轮换指引 / 明文审计扫描 / 锁定
- 安全：未解锁时列表与写操作 401 拦截；锁定即清空内存 key；页面常驻安全约定说明

**协议**

- LICENSE 统一为 GPL-3.0（Copyright (C) 2026 anyuer678）；pyproject 补声明

**脱敏**

- 派工提示词.md 移除本机绝对路径（改为相对路径）

## 五、安全与隐私

- 主密钥由 `scrypt(主密码, 随机盐)` 派生，**从不落盘**，仅存进程内存，退出即失效
- 密文 AES-256-GCM + AAD 防篡改；篡改 → 解密抛 `ValueError`
- 零网络：除打印轮换指引 URL 外不发起任何网络调用
- **主密码丢失 = 数据不可恢复**（无后门），请备份加密库

## 六、与文档的偏差（架构文档）

1. `payload_from(cipher, nonce, aad)`：契约签名无 key 参数，实现为「从密文分离 payload（末尾 16B tag）」；实际解密校验在 `decrypt_entry` 内完成
2. `kv shell-init` 生成的 `kvg` 指向 `kv use`（规划文档写 `kv get --env`，但架构契约 `kv get` 仅 `--full`，按契约优先级取 `kv use`，功能等价且更安全）
3. `store.VaultRepo` 新增 `load_header()`/`set_check()`/`verify_check()` 三个只读扩展（不改契约签名）
4. Web 前端为纯新增能力（CLI/GUI 之外第三种界面），不修改任何现有契约
