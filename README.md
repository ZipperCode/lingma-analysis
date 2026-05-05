# lingma-analysis

Lingma 程序分析仓库。

当前已经把文档分成五层：

- 当前实现与当前结论
- 当前仓库专项主题
- 下游 `lingma2api` / 独立化设计
- 历史归档
- 工具阶段报告

## 从哪里开始

- 仓库导航：[docs/README.md](./docs/README.md)
- 当前结论总览：[docs/lingma-analysis-overview.md](./docs/lingma-analysis-overview.md)
- 当前最终状态：[docs/lingma-analysis-final-status.md](./docs/lingma-analysis-final-status.md)
- 调用方式与脚本使用：[USAGE.md](./USAGE.md)
- 工具目录说明：[tools/README.md](./tools/README.md)

## 当前主实现

- 本地 `37010` 客户端：[lingma_client.py](./lingma_client.py)
- 远端直连客户端：[lingma_remote_api.py](./lingma_remote_api.py)
