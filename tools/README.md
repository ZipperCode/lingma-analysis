# tools 目录

更新时间：2026-05-10

## 当前工具

| 脚本 | 功能 | 依赖 |
|------|------|------|
| `credential_extractor.py` | 从本地缓存提取凭证（AES-128-CBC 解密） | `cryptography` |

此工具被 `lingma_oauth_complete.py` 引用，用于从 `~/.lingma/cache/user` 解密 COSY 凭据。

## 主力脚本（根目录）

OAuth 登录和 Chat API 功能已移至根目录的独立脚本：

- `lingma_oauth_complete.py` — 自主 OAuth 登录（v5.0）
- `lingma_remote_api.py` — Chat API 远端客户端
- `lingma_client.py` — 本地 37010 WebSocket 客户端

## 归档位置

- **历史迭代脚本**：`../archive/scripts-noise/`（~215个）
- **旧版工具**：`../archive/tools/`（含 2026-05-10 归档的 v4 认证脚本、Go 尝试等）
