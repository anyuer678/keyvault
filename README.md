# KeyVault — 个人 API 密钥保险箱

本地加密钥匙串，专管 LLM API Key（OpenAI / DeepSeek / Anthropic）、GitHub Token、
云厂商凭据。**主密码（Key）不落盘**，密钥仅以 AES-256-GCM 密文存于本地单文件 `secrets.db`。

- 加密：`scrypt`（N=2¹⁵, r=8, p=1）派生主密钥 + `AES-256-GCM`，每条独立 nonce
- 存储：SQLite 单文件（0600 权限），表结构固定，写操作经事务原子提交
- 零网络：除打印轮换指引 URL 外不发起任何网络调用
- 只读审计：`kv audit` 扫描 `.env*/.ini/.toml/.config` 中的明文密钥，**值永不打印**

## 安装

```bash
pip install -e .        # 安装为 kv 命令（依赖 cryptography）
```

## 快速上手

```bash
# 1. 初始化（主密码 ≥8 位；警告：密码丢失 = 数据不可恢复）
kv init

# 2. 加密入库（交互输入值，不回显；也可管道输入）
kv add deepseek --provider deepseek
echo -n "sk-xxx" | kv add github --provider github --stdin

# 3. 查看
kv list                 # 仅名称/供应商/过期日期，永不含值
kv get deepseek         # 默认摘要 sk-…****h4
kv get deepseek --full  # 仅显式请求时输出完整值

# 4. 注入当前 shell（输出 export 行，请用 eval 消费）
eval "$(kv use deepseek)"
# 或写入临时 .env（0600，用后即删）
kv use deepseek --dotenv .env.tmp

# 5. 修改 / 删除（删除需二次确认）
kv edit deepseek
kv delete deepseek
kv delete deepseek --yes

# 6. 审计明文密钥（只读，值打码）
kv audit --dir ~/myproject
kv audit --json

# 7. 轮换指引（打印官方 URL，不联网）
kv rotate --provider github

# 8. 备份 / 恢复（加密备份 + header，恢复需主密码）
kv export-backup backup.db
kv import-backup backup.db   # 原子替换，需二次确认

# 9. 桌面 GUI（tkinter 标准库，零新依赖）
kv gui
```

## 命令速查

| 命令 | 说明 |
| --- | --- |
| `kv init` | 创建 vault（主密码 ≥8 位，scrypt 随机盐） |
| `kv unlock` | 验证主密码并解锁（密码经 stdin / 环境变量 `KV_PASS`，key 仅存进程内存） |
| `kv add <name> [--provider p] [--expires YYYY-MM-DD] [--stdin]` | 加密入库 |
| `kv get <name> [--full]` | 解密输出（默认只显示前 4 后 4） |
| `kv list` | 列出名称/供应商/过期日期（永不含值） |
| `kv use <name> [--shell bash\|zsh\|fish] [--dotenv FILE]` | 输出 export 行或写入 0600 的 .env |
| `kv edit <name>` | 交互修改值/到期日 |
| `kv delete <name> [--yes]` | 删除（需输入 `yes` 确认） |
| `kv audit [--dir .] [--json] [--fix-0600]` | 扫描明文密钥（只读，永不打印值） |
| `kv rotate --provider <p>` | 打印官方轮换指引 URL |
| `kv export-backup <file>` / `kv import-backup <file>` | 加密备份导出/原子导入 |
| `kv shell-init` | 生成 shell alias（如 `kvg='kv use'`） |
| `kv gui` | 启动 tkinter 桌面前端（Windows 原生，零新依赖） |

## 桌面 GUI

```bash
kv gui            # 启动窗口；vault 不存在时自动进入“创建”向导
```

- 功能：解锁 / 列表（永不含值）/ 单条查看·复制 / 添加 / 编辑 / 删除（二次确认）/ 导出·导入加密备份
- 主密码弹窗输入（`show=*`），主密钥仅存 GUI 进程内存，关闭即失效
- 列表与 CLI 一致：`NAME / PROVIDER / EXPIRES / STATUS`，过期条目标 `EXPIRED`
- 查看/复制为单条显式操作，不提供批量明文导出
- 表单校验与 CLI 同源（日期 `YYYY-MM-DD`、重名拦截等），错误弹窗提示

## 环境变量

| 变量 | 用途 |
| --- | --- |
| `KV_PASS` | 主密码（避免交互输入；环境变量对同用户进程可见，请仅在可信环境中使用，且勿写进 shell 历史） |
| `KV_DIR` | vault 目录（默认 `~/.keyvault`） |
| `KV_DB` | vault 数据库文件路径（默认 `<KV_DIR>/secrets.db`） |

## 安全模型与边界

- 主密钥由 `scrypt(主密码, 随机盐)` 派生，**从不落盘**，仅存进程内存，退出即失效
- 密文用 AES-256-GCM，AAD = name+provider 防篡改；篡改 ciphertext/tag/nonce/名称 → 解密抛 `ValueError`
- 库文件与备份文件创建时设为 0600（Windows 上 `os.chmod` 仅影响只读位，请配合磁盘加密/ACL）
- `kv list` 永不返回密钥值；`kv audit` 仅报告文件名+key 名，值区打码 `REDACTED`
- `kv get`/`kv use` 的完整值输出走 stdout，请勿重定向到文件后长期保存
- **主密码丢失 = 数据不可恢复**（无后门、无主密钥恢复机制），请备份加密库

## 测试

```bash
python -m pytest tests/ -v
```

## 实现说明（与架构文档的偏差）

1. `payload_from(cipher, nonce, aad)`：契约签名无 key 参数，故实现为「从密文分离 payload（末尾 16B tag）」；实际解密校验在 `decrypt_entry` 内完成。
2. `kv shell-init` 生成的 `kvg` 指向 `kv use`（规划文档写 `kv get --env`，但架构契约 `kv get` 仅 `--full`，按契约优先级取 `kv use`，功能等价且更安全）。
3. `store.VaultRepo` 新增 `load_header()` / `set_check()` / `verify_check()` 三个只读扩展方法（不改契约签名），用于解锁校验与备份恢复。
4. 解锁校验：`init` 时在 meta 表存入加密校验标记，主密码错误时统一提示「无法解锁」。
