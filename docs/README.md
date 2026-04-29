# Lingma 分析文档索引

更新时间：2026-04-27

## 先看这 4 份

如果你第一次进入这个仓库，按下面顺序阅读即可：

1. [lingma-analysis-overview.md](./lingma-analysis-overview.md)
2. [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
3. [remote-api-direct-connection.md](./remote-api-direct-connection.md)
4. [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)

这 4 份文档负责回答当前最核心的问题：

- 现在哪些结论已经成立
- 本地 `37010` 路线和远端直连路线分别走到哪一步
- 当前主实现代码在哪
- 还有哪些约束没有解除

## 文档分层

### 1. 当前有效结论

这些文件保留在 `docs/` 根层，默认视为当前主阅读面：

- [lingma-analysis-overview.md](./lingma-analysis-overview.md)
- [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
- [remote-api-direct-connection.md](./remote-api-direct-connection.md)
- [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)
- [lingma-analysis-endpoint-auth.md](./lingma-analysis-endpoint-auth.md)
- [lingma-analysis-token-flow.md](./lingma-analysis-token-flow.md)

### 2. 专项主题

专项主题保留在 [`topics/`](./topics/) 下，适合按问题深挖，不再和主线入口并列：

- [topics/encode1-complete-analysis.md](./topics/encode1-complete-analysis.md)
- [topics/encoding-alphabet-decoded.md](./topics/encoding-alphabet-decoded.md)
- [topics/encryption-analysis.md](./topics/encryption-analysis.md)
- [topics/encryption-status.md](./topics/encryption-status.md)
- [topics/heartbeat-body-structure.md](./topics/heartbeat-body-structure.md)

### 3. 历史归档

以下内容保留证据价值，但已经被后续结论覆盖，不应再当作当前状态入口：

- [archive/lingma-complete-analysis-2026-04-25.md](./archive/lingma-complete-analysis-2026-04-25.md)
- [archive/continue-analysis-from-current-state-2026-04-25.md](./archive/continue-analysis-from-current-state-2026-04-25.md)
- [archive/lingma-analysis-snapshots.md](./archive/lingma-analysis-snapshots.md)

其中最容易误导的一点是：

- `2026-04-25` 阶段文档里还保留了“`agent_chat_generation` 需要 `Encode=1` 模板重放”的旧结论。
- 当前实现与最新状态文档已经收敛为“Chat API 可直接发送原始 JSON body”。

### 4. 工具阶段报告

工具侧历史 Markdown 已集中在 [`tools-archive/`](./tools-archive/)：

- [tools-archive/auth_final_report.md](./tools-archive/auth_final_report.md)
- [tools-archive/signing_final.md](./tools-archive/signing_final.md)
- [tools-archive/getappsalt_analysis.md](./tools-archive/getappsalt_analysis.md)
- [tools-archive/getappsalt_analysis_v2.md](./tools-archive/getappsalt_analysis_v2.md)
- [tools-archive/getappsalt_result.md](./tools-archive/getappsalt_result.md)
- [tools-archive/next_steps.md](./tools-archive/next_steps.md)

## 代码与工具入口

- 本地 `37010` 客户端：[`../lingma_client.py`](../lingma_client.py)
- 远端直连客户端：[`../lingma_remote_api.py`](../lingma_remote_api.py)
- 工具目录说明：[`../tools/README.md`](../tools/README.md)
- 使用说明：[`../USAGE.md`](../USAGE.md)
