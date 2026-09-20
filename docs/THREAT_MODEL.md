# 威胁模型 — keyvault

> 状态：`local-tool` · 本机 API 密钥保险箱

## 资产
- 主密码派生密钥（仅进程内存）
- `secrets.db` 密文条目
- 备份文件（`~/.keyvault/backups/`）

## 控制（现状 + Sprint）
| 控制 | 说明 |
|---|---|
| AES-256-GCM + scrypt | 每条独立 nonce + AAD |
| 主密码不落盘 | 解锁后 key 仅会话内存 |
| Web 本机绑定 + Host/Origin | 防 rebinding/CSRF |
| 解锁限速 | 5 次/分钟 |
| **step-up** | delete/export/import 须再次输入主密码 |
| **Windows DACL** | `icacls` 收紧为仅当前用户（chmod 之外） |
| 备份路径限制 | 仅 `~/.keyvault/backups/` |

## 残余风险
- 同机恶意进程：内存中 key / 剪贴板 / `--full` 明文输出
- Windows ACL 依赖 icacls 可用性；建议配合 BitLocker
- CLI 解锁仍无速率限制（本地可信环境假设）

## 事故响应
1. 轮换所有泄露 API key  
2. `kv` 删除或重建 vault  
3. 检查 `~/.keyvault/backups/` 是否被拷走  
