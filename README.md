# KeyVault —— 个人 API 密钥保险箱

> 本地加密钥匙串，专管 LLM API Key（OpenAI / DeepSeek / Anthropic）、GitHub Token、云厂商凭据。主密码（Key）不落盘。

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-81%20passed-brightgreen)](tests/)
[![Crypto](https://img.shields.io/badge/crypto-scrypt%20%2B%20AES--256--GCM-blueviolet)](vault.py)

比 1Password 轻、比 `.env` 安全。密钥仅以 AES-256-GCM 密文存于本地单文件 `secrets.db`。

## 功能特性

| 能力 | 说明 |
|---|---|
| 强加密 | `scrypt`（N=2¹⁵, r=8, p=1）派生主密钥 + `AES-256-GCM`，每条独立 nonce，AAD 防篡改 |
| 主密码不落盘 | Key 仅存进程内存，退出即失效；密码丢失 = 数据不可恢复 |
| 零网络 | 除打印轮换指引 URL 外不发起任何网络调用 |
| 只读审计 | `kv audit` 扫描 `.env*/.ini/.toml/.config` 中的明文密钥，**值永不打印** |
| 三种界面 | CLI / tkinter 桌面 GUI / 零依赖 Web UI（新增） |
| 备份恢复 | 加密备份导出 / 原子导入（校验 header，恢复需主密码） |

## 快速开始

```bash
pip install -e .        # 安装 kv 命令（依赖 cryptography）

# 1. 初始化（主密码 ≥8 位；警告：密码丢失 = 数据不可恢复）
kv init

# 2. 加密入库（交互输入值，不回显；也可管道输入）
kv add deepseek --provider deepseek
echo -n "sk-xxx" | kv add github --provider github --stdin

# 3. 查看（永不含值）
kv list                 # 仅名称/供应商/过期日期
kv get deepseek         # 默认摘要 sk-…****h4
kv get deepseek --full  # 仅显式请求时输出完整值

# 4. 注入当前 shell（输出 export 行，请用 eval 消费）
eval "$(kv use deepseek)"

# 5. 审计明文密钥（只读，值打码）
kv audit --dir ~/myproject

# 6. 备份 / 恢复（加密备份，恢复需主密码）
kv export-backup backup.db
kv import-backup backup.db   # 原子替换，需二次确认

# 7. 桌面 GUI / Web UI
kv gui
python webui.py         # 浏览器打开 http://127.0.0.1:8765
```

## 命令速查

| 命令 | 说明 |
|---|---|
| `kv init` / `kv unlock` | 创建 / 解锁 vault（密码经 stdin 或环境变量 `KV_PASS`） |
| `kv add <name> [--provider p] [--expires YYYY-MM-DD] [--stdin]` | 加密入库 |
| `kv get <name> [--full]` | 解密输出（默认只显示前 4 后 4） |
| `kv list` | 列出名称/供应商/过期日期（永不含值） |
| `kv use <name> [--shell bash\|zsh\|fish] [--dotenv FILE]` | 输出 export 行或写入 0600 的 .env |
| `kv edit / kv delete [--yes]` | 修改 / 删除（二次确认） |
| `kv audit [--dir .] [--json] [--fix-0600]` | 扫描明文密钥（只读） |
| `kv rotate --provider <p>` | 打印官方轮换指引 URL（不联网） |
| `kv export-backup <file>` / `kv import-backup <file>` | 加密备份导出 / 原子导入 |
| `kv gui` | 启动 tkinter 桌面前端 |

## 环境变量

| 变量 | 用途 |
|---|---|
| `KV_PASS` | 主密码（避免交互输入；仅限可信环境，勿写进 shell 历史） |
| `KV_DIR` | vault 目录（默认 `~/.keyvault`） |
| `KV_DB` | vault 数据库文件路径（默认 `<KV_DIR>/secrets.db`） |

## 安全模型与边界

- 主密钥由 `scrypt(主密码, 随机盐)` 派生，**从不落盘**，仅存进程内存，退出即失效。
- 密文用 AES-256-GCM，AAD = name+provider 防篡改；篡改 ciphertext/tag/nonce/名称 → 解密抛 `ValueError`。
- 库文件与备份文件创建时设为 0600（Windows 上 `os.chmod` 仅影响只读位，请配合磁盘加密/ACL）。
- `kv list` 永不返回密钥值；`kv audit` 仅报告文件名+key 名，值区打码 `REDACTED`。
- **主密码丢失 = 数据不可恢复**（无后门、无主密钥恢复机制），请备份加密库。

## 项目结构

```
cli.py          全部子命令（kv 入口）
vault.py        加解密核心（scrypt + AES-GCM，纯函数无 IO）
store.py        SQLite 持久化（0600 权限、原子写、导入校验）
audit.py        明文密钥扫描（只读，值永不返回）
gui.py          tkinter 桌面 GUI（延迟 import）
webui.py        零依赖 Web 前端（内嵌 HTML/JS/CSS）
config.py       vault 路径/目录权限
tests/          pytest 测试（81 例，全 mock 不触网）
```

## 测试

```bash
python -m pytest tests/ -v
```

## 隐私与免责

- 本工具除打印轮换指引 URL 外零网络调用；主密码与密钥值均不出本机。
- 完整值输出走 stdout，请勿重定向到文件后长期保存；`kv use --dotenv` 生成的文件请用后删除，勿提交 git。
- 加密算法与实现经过测试验证，但不构成安全审计结论；存放高价值密钥请额外评估威胁模型。

## 免责声明

本项目仅供学习交流与演示用途，不构成任何形式的商业服务或技术承诺。软件按「现状」提供，不作任何明示或暗示的保证，包括但不限于适销性、特定用途适用性与非侵权性。

您理解并同意：使用本项目即表示您自行承担全部风险。如您在使用过程中发现缺陷或问题，欢迎通过 GitHub Issues 反馈，但作者不因使用本软件所直接或间接产生的任何损失（包括但不限于数据丢失、业务中断、第三方索赔）承担责任。

本项目以功能演示与学习交流为主要目的，其架构设计、安全基线、容错机制与性能表现均未按生产级标准进行验证与加固，不适用于实际生产环境或关键业务场景。任何将本项目部署于生产系统、对外提供服务、或将其接入真实业务工作流的做法，均属使用者的自主决策行为；由此产生的任何直接或间接不良后果，包括但不限于服务中断、数据损坏或泄露、业务损失、合规风险、以及因依赖本软件而引发的第三方纠纷，**开发者均不承担任何责任**。若您确有生产级使用需求，请在充分评估与自行加固（包括但不限于安全审计、压力测试、代码审查）后，自行承担相应风险。

## License

[GPL-3.0](LICENSE) — Copyright (C) 2026 anyuer678
