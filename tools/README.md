# tools 目录 — 已验证工具

更新时间：2026-05-07

`tools/` 目录当前仅保留 **7 个已验证可工作的工具**。所有历史迭代脚本已移至 `../archive/scripts-noise/`（~215个）。

## 当前工具

### 认证与 API 客户端

| 脚本 | 功能 | 依赖 |
|------|------|------|
| `lingma_37510_server.py` | 完整 OAuth 回调模拟服务器（PKCE + 认证流程） | `websocket-client`（可选） |
| `lingma_37510_auto.py` | 自动化包装：停灵码 → 启动模拟 → 等回调 | 同上 |
| `lingma_full_auth.py` | 完整 v4.0 认证（Encode=1 + Signature/Bearer 双模式） | `requests`（可选） |
| `lingma_refresh_token.py` | Token 刷新（Signature 模式） | stdlib |

### 凭证管理

| 脚本 | 功能 | 依赖 |
|------|------|------|
| `credential_extractor.py` | 从本地缓存提取凭证（AES-128-CBC 解密） | `cryptography` |

### Go TLS 测试

| 脚本 | 功能 | 依赖 |
|------|------|------|
| `go_auth.go` | Go 原生 TLS 指纹测试（Signature 认证） | Go |
| `go_auth_h2.go` | Go HTTP/2 指纹测试 | Go |

## 归档位置

- **历史迭代脚本**：`../archive/scripts-noise/`（~215个）
- **旧版归档**：`../archive/tools/`（89个）
- **IDA 分析数据**：`../docs/ida/`（37个反编译输出）
- **未验证脚本**：`../docs/doubt/lingma_refresh_token_direct.py`（依赖未验证签名构造）

## 使用建议

- 新增工具时，给明确的职责和文件名，不要叠 `vN` 变体
- 需要实验时，把结论收敛进 `docs/`，而不是堆新的 `final` 或 `test` 文件
