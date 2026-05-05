# Lingma 分析文档索引

更新时间：2026-05-04

这份索引只做三件事：

1. 告诉你当前哪些文档代表“现在可用的结论”。
2. 告诉你每份文档对应哪条实现链和哪类问题。
3. 把当前仓库分析、下游 `lingma2api` 设计、步骤拆分报告和历史归档明确分层，避免混读。

## 先看这 4 份

如果你第一次进入这个仓库，按下面顺序阅读即可：

1. [lingma-analysis-overview.md](./lingma-analysis-overview.md)
2. [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
3. [remote-api-direct-connection.md](./remote-api-direct-connection.md)
4. [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)

这 4 份负责回答当前最核心的问题：

- 现在到底已经打通了什么
- 本地 `37010` 路线和远端直连路线分别怎么实现
- 哪些结论来自当前仓库主实现，哪些只是专项推导或下游设计
- 还剩哪些约束没有解除

## 事实优先级

阅读时按下面优先级判断“哪份更应该代表当前状态”：

1. 当前实现代码：
   - [../lingma_client.py](../lingma_client.py)
   - [../lingma_remote_api.py](../lingma_remote_api.py)
2. `docs/` 根层主文档：
   - [lingma-analysis-overview.md](./lingma-analysis-overview.md)
   - [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
   - [remote-api-direct-connection.md](./remote-api-direct-connection.md)
   - [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)
3. `topics/` 下的专项分析：
   - 负责展开某一个技术点
   - 不自动等于“当前主结论”
4. `superpowers/` 与 `plans/`：
   - 主要服务于下游 `lingma2api` / OpenAI 兼容代理设计
   - 不是当前仓库主脚本已经落地的实现
5. `archive/` 与 `tools-archive/`：
   - 保留证据与推导过程
   - 不应再直接当作今天的最终状态

重复内容处理规则：

- 根层主文档与当前实现冲突时，以根层主文档和代码为准。
- `topics/` 与根层主文档冲突时，以根层主文档的“当前边界”判断为准，`topics/` 只提供专项证据。
- `archive/step-analysis-2026-05-04/` 与 `tools-archive/` 只保留阶段拆分分析、失败路径和旧报告，不再代表当前总状态。

## 按问题导航

| 你要回答的问题 | 先看哪份文档 | 对应实现或入口 |
|---|---|---|
| 这个仓库当前最稳的结论是什么 | [lingma-analysis-overview.md](./lingma-analysis-overview.md) | [../lingma_client.py](../lingma_client.py), [../lingma_remote_api.py](../lingma_remote_api.py) |
| 远端 HTTP 直连现在能做到哪一步 | [remote-api-direct-connection.md](./remote-api-direct-connection.md) | [../lingma_remote_api.py](../lingma_remote_api.py) |
| 本地 `37010` 路线怎么工作 | [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md) | [../lingma_client.py](../lingma_client.py), [../tools/lingma_probe.py](../tools/lingma_probe.py) |
| 当前已完成与未完成的边界 | [lingma-analysis-final-status.md](./lingma-analysis-final-status.md) | 根目录两个客户端 |
| `Encode=1`、字母表、心跳 body 这些专项细节 | [`topics/`](./topics/) 下对应主题 | `lingma_remote_api.py` 中的编码函数与 `tools/` 专项脚本 |
| OAuth、`client_id`、`refresh_token`、`session_key` 的独立化方案 | [`topics/`](./topics/) 与 [`superpowers/`](./superpowers/) 对应文档 | 主要是下游 `lingma2api` 设计，不是当前仓库主线实现 |

## 文档分层

### 1. 当前仓库主实现与当前结论

这些文件默认代表“当前有效入口”：

- [lingma-analysis-overview.md](./lingma-analysis-overview.md)
- [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
- [remote-api-direct-connection.md](./remote-api-direct-connection.md)
- [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)
- [lingma-analysis-endpoint-auth.md](./lingma-analysis-endpoint-auth.md)
- [lingma-analysis-token-flow.md](./lingma-analysis-token-flow.md)

其中前 4 份是主阅读面；后 2 份保留更长的证据链和中间推导。

### 2. 当前仓库的专项主题

这些文件适合按问题深挖：

- [topics/encode1-complete-analysis.md](./topics/encode1-complete-analysis.md)
- [topics/encoding-alphabet-decoded.md](./topics/encoding-alphabet-decoded.md)
- [topics/encryption-analysis.md](./topics/encryption-analysis.md)
- [topics/encryption-status.md](./topics/encryption-status.md)
- [topics/heartbeat-body-structure.md](./topics/heartbeat-body-structure.md)
- [topics/ida-http-auth-headers-analysis.md](./topics/ida-http-auth-headers-analysis.md)
- [topics/frida-verification-guide.md](./topics/frida-verification-guide.md)
- [topics/frida-verification-summary.md](./topics/frida-verification-summary.md)
- [topics/callback-37510-simulation.md](./topics/callback-37510-simulation.md) — 37510 回调模拟、编码算法、完整认证流程与函数地址表

### 3. 下游 `lingma2api` / 独立化设计相关文档

这部分内容很重要，但要明确它们的职责：

- 它们主要回答“如果继续做完全独立的 OAuth、刷新和代理层，应该怎么设计或验证”。
- 它们不等于当前仓库根目录脚本已经集成的能力。

入口如下：

- [topics/client-id-extraction.md](./topics/client-id-extraction.md)
- [topics/refresh-token-flow.md](./topics/refresh-token-flow.md)
- [topics/session-key-analysis.md](./topics/session-key-analysis.md)
- [topics/standalone-oauth-analysis.md](./topics/standalone-oauth-analysis.md)
- [topics/ida-oauth-refresh-analysis.md](./topics/ida-oauth-refresh-analysis.md)
- [plans/](./plans/)
- [superpowers/specs/](./superpowers/specs/)
- [superpowers/plans/](./superpowers/plans/)

### 4. 历史归档

以下内容保留证据价值，但已经被后续结论覆盖：

- [archive/lingma-complete-analysis-2026-04-25.md](./archive/lingma-complete-analysis-2026-04-25.md)
- [archive/continue-analysis-from-current-state-2026-04-25.md](./archive/continue-analysis-from-current-state-2026-04-25.md)
- [archive/lingma-analysis-snapshots.md](./archive/lingma-analysis-snapshots.md)
- [archive/step-analysis-2026-05-04/](./archive/step-analysis-2026-05-04/)

最容易误导的旧点是：

- `2026-04-25` 阶段文档还保留过“`agent_chat_generation` 必须依赖 `Encode=1` 模板重放”的阶段性判断。
- 当前根层主文档与实际实现已经收敛为：“远端直连的 Chat API 使用原始 JSON body，不依赖 `Encode=1`。”
- `2026-05-04` 归档的步骤拆分报告仍可用于查函数地址、端点清单和结构体推导，但其中“未解决”“下一步”类判断必须回到本索引和 `lingma-analysis-final-status.md` 复核。

### 5. 工具阶段报告

工具侧历史 Markdown 已集中在 [`tools-archive/`](./tools-archive/)：

- [tools-archive/auth_final_report.md](./tools-archive/auth_final_report.md)
- [tools-archive/signing_final.md](./tools-archive/signing_final.md)
- [tools-archive/signing_analysis.md](./tools-archive/signing_analysis.md)
- [tools-archive/getappsalt_analysis.md](./tools-archive/getappsalt_analysis.md)
- [tools-archive/getappsalt_analysis_v2.md](./tools-archive/getappsalt_analysis_v2.md)
- [tools-archive/getappsalt_result.md](./tools-archive/getappsalt_result.md)
- [tools-archive/next_steps.md](./tools-archive/next_steps.md)
- [tools-archive/root-copies-2026-05-04/](./tools-archive/root-copies-2026-05-04/)

它们的用法只有一个：

- 当你需要证据、实验过程和失败路径时去翻。
- 当你需要“今天这个仓库当前到底成立到哪里”时，不要从这里开始。

## 代码与工具入口

- 本地 `37010` 客户端：[../lingma_client.py](../lingma_client.py)
- 远端直连客户端：[../lingma_remote_api.py](../lingma_remote_api.py)
- 工具目录说明：[../tools/README.md](../tools/README.md)
- 使用说明：[../USAGE.md](../USAGE.md)
