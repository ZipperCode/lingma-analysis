# Lingma 分析文档索引

更新时间：2026-05-10

## 核心文档（按优先级）

| 优先级 | 文档 | 说明 |
|--------|------|------|
| 1 | [topics/oauth-flow-verified.md](./topics/oauth-flow-verified.md) | OAuth 完整流程（已验证，最新） |
| 2 | [remote-api-direct-connection.md](./remote-api-direct-connection.md) | Chat API 直连现状 |
| 3 | [topics/encode1-complete-analysis.md](./topics/encode1-complete-analysis.md) | Encode=1 算法完整分析 |
| 4 | [topics/callback-37510-simulation.md](./topics/callback-37510-simulation.md) | IDA 逆向 + 37510 回调分析 |
| 5 | [topics/session-key-analysis.md](./topics/session-key-analysis.md) | Session Key 分析 |

## 按问题导航

| 问题 | 文档 | 对应实现 |
|------|------|---------|
| 如何自主 OAuth 登录 | [topics/oauth-flow-verified.md](./topics/oauth-flow-verified.md) | `lingma_oauth_complete.py` |
| Chat API 如何调用 | [remote-api-direct-connection.md](./remote-api-direct-connection.md) | `lingma_remote_api.py` |
| Encode=1 编码细节 | [topics/encode1-complete-analysis.md](./topics/encode1-complete-analysis.md) | `lingma_remote_api.py` 中的编解码函数 |
| IDA 逆向数据 | [ida/README.md](./ida/README.md) | IDA Pro 反编译输出 |

## 代码入口

- OAuth 自主登录：[../lingma_oauth_complete.py](../lingma_oauth_complete.py)
- Chat API 客户端：[../lingma_remote_api.py](../lingma_remote_api.py)
- 本地 WebSocket 客户端：[../lingma_client.py](../lingma_client.py)
- 凭据提取工具：[../tools/credential_extractor.py](../tools/credential_extractor.py)
- 使用说明：[../USAGE.md](../USAGE.md)

## 文档分层

### 1. 已验证专题（topics/）

- [oauth-flow-verified.md](./topics/oauth-flow-verified.md) — OAuth 流程（2026-05-10 端到端验证通过）
- [encode1-complete-analysis.md](./topics/encode1-complete-analysis.md) — Encode=1 算法
- [session-key-analysis.md](./topics/session-key-analysis.md) — Session Key
- [callback-37510-simulation.md](./topics/callback-37510-simulation.md) — IDA 逆向

### 2. API 文档

- [remote-api-direct-connection.md](./remote-api-direct-connection.md) — Chat API 直连

### 3. IDA 参考数据（ida/）

- [ida/README.md](./ida/README.md) — 反编译原始数据索引

### 4. 下游设计（superpowers/specs/）

- [superpowers/specs/](./superpowers/specs/) — lingma2api 设计规格

### 5. 历史归档

- [archive/](./archive/) — 已解决的推测、旧分析、旧计划
- [tools-archive/](./tools-archive/) — 工具阶段历史报告
