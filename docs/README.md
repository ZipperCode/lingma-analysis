# Lingma 分析文档索引

更新时间：2026-05-07

这份索引只做三件事：

1. 告诉你当前哪些文档代表"现在可用的结论"。
2. 告诉你每份文档对应哪条实现链和哪类问题。
3. 把已验证结论、未验证推测、IDA 参考数据、下游设计和历史归档明确分层。

## 先看这 4 份

如果你第一次进入这个仓库，按下面顺序阅读即可：

1. [lingma-analysis-overview.md](./lingma-analysis-overview.md)
2. [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
3. [remote-api-direct-connection.md](./remote-api-direct-connection.md)
4. [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)

这 4 份负责回答当前最核心的问题。

## 事实优先级

阅读时按下面优先级判断"哪份更应该代表当前状态"：

1. **当前实现代码**：
   - [../lingma_client.py](../lingma_client.py)
   - [../lingma_remote_api.py](../lingma_remote_api.py)
2. **`docs/` 根层主文档**（已验证结论）：
   - [lingma-analysis-overview.md](./lingma-analysis-overview.md)
   - [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
   - [remote-api-direct-connection.md](./remote-api-direct-connection.md)
   - [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)
3. **`topics/`** 下的已验证专项分析（4篇）
4. **`doubt/`** 未验证推测区（当作假设而非结论）
5. **`superpowers/`** 与 **`plans/`**：下游 `lingma2api` 设计
6. **`archive/`** 与 **`tools-archive/`**：历史归档

重复内容处理规则：

- 根层主文档与当前实现冲突时，以根层主文档和代码为准。
- `doubt/` 中的结论不得当作已验证事实使用。
- `archive/` 与 `tools-archive/` 不再代表当前状态。

## 按问题导航

| 你要回答的问题 | 先看哪份文档 | 对应实现或入口 |
|---|---|---|
| 这个仓库当前最稳的结论是什么 | [lingma-analysis-overview.md](./lingma-analysis-overview.md) | [../lingma_client.py](../lingma_client.py), [../lingma_remote_api.py](../lingma_remote_api.py) |
| 远端 HTTP 直连现在能做到哪一步 | [remote-api-direct-connection.md](./remote-api-direct-connection.md) | [../lingma_remote_api.py](../lingma_remote_api.py) |
| 本地 `37010` 路线怎么工作 | [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md) | [../lingma_client.py](../lingma_client.py) |
| 当前已完成与未完成的边界 | [lingma-analysis-final-status.md](./lingma-analysis-final-status.md) | 根目录两个客户端 |
| `Encode=1`、字母表、session key 专项细节 | [`topics/`](./topics/) 下对应主题 | `lingma_remote_api.py` 中的编码函数 |
| IDA 反编译原始数据在哪 | [`ida/README.md`](./ida/README.md) | 37个反编译输出 + JSON + Python 脚本 |
| **未验证的推测和矛盾在哪** | [`doubt/UNVERIFIED-README.md`](./doubt/UNVERIFIED-README.md) | [`doubt/CONTRADICTIONS.md`](./doubt/CONTRADICTIONS.md) |

## 文档分层

### 1. 已验证的主文档

这些文件代表已验证的结论：

- [lingma-analysis-overview.md](./lingma-analysis-overview.md)
- [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
- [remote-api-direct-connection.md](./remote-api-direct-connection.md)
- [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)
- [lingma-analysis-endpoint-auth.md](./lingma-analysis-endpoint-auth.md) — 端点认证证据链
- [lingma-analysis-token-flow.md](./lingma-analysis-token-flow.md) — Token 流转证据链

### 2. 已验证的专项主题

- [topics/encode1-complete-analysis.md](./topics/encode1-complete-analysis.md) — Encode=1 完整分析（已验证编解码往返）
- [topics/encode1-complete-analysis.md](./topics/encode1-complete-analysis.md) — Encode=1 完整分析（编码字母表已过时版本见 archive）
- [topics/session-key-analysis.md](./topics/session-key-analysis.md) — Session Key 分析（1/3 Oracle 验证）
- [topics/callback-37510-simulation.md](./topics/callback-37510-simulation.md) — 37510 回调模拟、完整认证流程

### 3. ⚠️ 未验证推测区（doubt/）

包含 IDA 静态分析推导但从未被 Frida 运行时验证的结论：

- [doubt/UNVERIFIED-README.md](./doubt/UNVERIFIED-README.md) — 怀疑区说明
- [doubt/CONTRADICTIONS.md](./doubt/CONTRADICTIONS.md) — 跨文档矛盾注册表（8项）
- IDA 认证头分析、OAuth 刷新分析、加密假设、client_id 提取失败、v3 端点分析等（共11个文件）

### 4. IDA 参考数据（ida/）

IDA Pro 反编译原始输出，按版本（v2.11.1/v2.11.2）分类：

- [ida/README.md](./ida/README.md) — 文件索引

### 5. 下游 `lingma2api` / 独立化设计

- [plans/](./plans/)
- [superpowers/specs/](./superpowers/specs/)
- [superpowers/plans/](./superpowers/plans/)

### 6. 历史归档

- [archive/](./archive/) — 2026-04-25 阶段的综合分析和快照
- [tools-archive/](./tools-archive/) — 工具阶段历史报告

最容易误导的旧点：2026-04-25 文档曾声称 Chat API 必须依赖 Encode=1，现已纠正为原始 JSON body。

## 代码与工具入口

- 本地 `37010` 客户端：[../lingma_client.py](../lingma_client.py)
- 远端直连客户端：[../lingma_remote_api.py](../lingma_remote_api.py)
- 已验证工具目录：[../tools/README.md](../tools/README.md)
- 使用说明：[../USAGE.md](../USAGE.md)
