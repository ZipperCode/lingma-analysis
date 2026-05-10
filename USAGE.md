# Lingma 调用与脚本使用指南

更新时间：2026-05-10

## 前置条件

```bash
pip install -r requirements.txt
```

## 快速开始

### 1. OAuth 自主登录

```bash
# 首次登录：打开浏览器完成阿里云认证
python lingma_oauth_complete.py login

# 查看凭据状态和有效期
python lingma_oauth_complete.py status

# 手动导入 window.user_info
python lingma_oauth_complete.py manual
```

登录成功后，凭据自动保存到 `~/.lingma/portable_config.json`（Token 有效期约 60 天）。

### 2. Chat API 调用

```bash
# Smoke test（自动读取凭据）
python lingma_remote_api.py
```

库调用方式：

```python
from lingma_remote_api import LingmaRemoteAPI

api = LingmaRemoteAPI()
print(api.chat("你好"))
print(api.get_models())
```

### 3. 本地 37010 WebSocket（需灵码运行中）

```bash
python lingma_client.py "你好"
```

```python
from lingma_client import LingmaClient
client = LingmaClient()
client.connect()
print(client.ask("写一个快排"))
client.close()
```

## 核心脚本

| 脚本 | 用途 |
|------|------|
| `lingma_oauth_complete.py` | 自主 OAuth 登录（PKCE + V2 回调 + Encode=1 解码） |
| `lingma_remote_api.py` | Chat API 远端客户端（COSY Bearer 签名 + SSE 解析） |
| `lingma_client.py` | 本地 37010 WebSocket 客户端 |
| `tools/credential_extractor.py` | 本地缓存凭据提取（AES 解密） |

## 凭据来源（自动按优先级选择）

1. 直接传参
2. 环境变量：`LINGMA_COSY_KEY` + `LINGMA_ENCRYPT_USER_INFO`
3. 便携配置：`~/.lingma/portable_config.json`
4. 本地缓存：`~/.lingma/cache/id` + `~/.lingma/cache/user`（AES 解密）

## 已知限制

1. **Token 刷新**：远端 API 返回 404/403，当前 Token 有效期约 60 天，到期需重新登录
2. **COSY 凭据**：`cosy_key` 和 `encrypt_user_info` 从本地 Lingma 缓存提取，首次需要 Lingma 安装
3. **TLS 指纹**：Chat API 需通过 curl 发送，Python requests 可能被拒

## 文档索引

| 文档 | 说明 |
|------|------|
| [docs/topics/oauth-flow-verified.md](docs/topics/oauth-flow-verified.md) | OAuth 完整流程（已验证） |
| [docs/remote-api-direct-connection.md](docs/remote-api-direct-connection.md) | Chat API 直连说明 |
| [docs/topics/encode1-complete-analysis.md](docs/topics/encode1-complete-analysis.md) | Encode=1 算法分析 |
| [docs/topics/callback-37510-simulation.md](docs/topics/callback-37510-simulation.md) | IDA 逆向分析文档 |
