# 步骤拆分分析归档

更新时间：2026-05-04

这个目录收纳从 `docs/` 根层移出的阶段性拆分报告。它们仍有证据价值，但不再作为当前阅读入口。

## 为什么归档

- 这些文件是在分步骤分析 API、认证、加密、OAuth、本地服务和响应结构时生成的。
- 部分内容和 `topics/`、根层主文档重复。
- 部分“当前阻塞”“下一步”判断已经被后续实现或更高置信分析覆盖。

## 当前事实优先级

1. 当前实现代码：
   - `lingma_client.py`
   - `lingma_remote_api.py`
2. 根层主文档：
   - `docs/lingma-analysis-overview.md`
   - `docs/lingma-analysis-final-status.md`
   - `docs/remote-api-direct-connection.md`
   - `docs/lingma-analysis-request-flow-pruned.md`
3. 专项主题：
   - `docs/topics/`
4. 本目录：
   - 只用于查阶段性证据、函数地址、端点清单、结构体推导和历史判断。

## 已归档文件

- `LINGMA_API_COMPLETE_DOCUMENTATION.md`
- `api_endpoints_inventory.md`
- `api_request_construction_analysis.md`
- `encode1_mechanism_complete.md`
- `encryption_mechanisms_complete.md`
- `ida-http-refresh-cracked.md`
- `local_http_server_monitoring_mechanism.md`
- `oauth-capture-guide.md`
- `oauth_login_flow_complete.md`
- `oauth_token_storage_mechanism.md`
- `response_data_structures_complete.md`

## 阅读提醒

- 需要回答“当前仓库已经打通什么”时，不要从本目录开始。
- 如果本目录和根层主文档冲突，以根层主文档和当前代码为准。
- 如果只是查某个历史分析过程，本目录可以作为证据索引。
