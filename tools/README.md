# tools 目录整理说明

更新时间：2026-05-04

## 目的

`tools/` 曾经混合三类内容：

- 当前仍有参考价值的探针和辅助脚本
- 历史阶段的分析报告
- 大量一次性实验脚本和 `vN` 变体

这份说明的目标是把“当前该看什么”和“哪些只是历史痕迹”分开，避免继续被旧脚本命名污染判断。

2026-05-04 已执行一次整理：

- 历史 Markdown 工作副本移到 `../docs/tools-archive/root-copies-2026-05-04/`
- 旧的 Frida/getAppSalt/patch/pipe 迭代脚本移到 `archive/old-analysis-2026-05-04/`
- `tools/` 根目录优先保留当前仍可复用的探针、验证脚本和新一轮 OAuth/refresh 相关工具

## 当前主线文件

优先看这些：

- `../lingma_client.py`
  - 当前最稳的本地 `37010` 客户端
- `../lingma_remote_api.py`
  - 当前远端直连客户端
- `lingma_probe.py`
  - 最小本地协议探针
- `offprocess_model_list.ps1`
  - 早期远端 `model/list` GET PoC
- `lingma_capture_server.py`
  - 抓取和转发相关辅助工具

## 当前主线文档

优先看这些：

- `../docs/README.md`
- `../docs/lingma-analysis-overview.md`
- `../docs/lingma-analysis-final-status.md`
- `../docs/remote-api-direct-connection.md`
- `../docs/lingma-analysis-request-flow-pruned.md`

## 历史报告

以下 Markdown 仍有证据价值，但不再代表当前总状态。整理后的归档副本统一放在 `../docs/tools-archive/`，原 `tools/` 根目录工作副本已移到 `../docs/tools-archive/root-copies-2026-05-04/`：

- `auth_final_report.md`
- `signing_final.md`
- `next_steps.md`
- `getappsalt_analysis.md`
- `getappsalt_analysis_v2.md`
- `signing_analysis.md`

使用方式：

- 把它们当专项阶段记录
- 不要再把里面的“未打通”“当前阻塞”直接当成今天的最终结论

## 历史实验脚本

以下命名模式默认视为一次性实验，不应作为当前入口。旧 getAppSalt、Frida pipe、patch 和地址定位迭代产物已集中到 `archive/old-analysis-2026-05-04/`：

- `*_v2.py`, `*_v3.py`, `*_v4.py`
- `test_*.py`
- `final_*.py`
- `analyze_*2.py`, `analyze_*3.py`
- `frida_hook_v*.py`
- `frida_hook_appsalt_v*.py`
- `frida_hook_pipe_v*.py`

这类脚本的常见问题：

- 只针对某一轮样本或某个地址
- 假设条件写死在代码里
- 结论后来已经被更高置信证据覆盖

## 当前建议

- 继续新增脚本时，优先新增明确职责的主线文件，不要再叠 `vN` 变体。
- 需要保留实验过程时，优先把结论收敛进 `docs/`，而不是再堆一个新的 `final` 或 `test` 文件。
- 如果只是为了验证某一条新猜想，优先修改或复制最接近的主线探针，并在文档里说明它解决的具体问题。
