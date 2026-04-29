# Lingma 分析总览

更新时间：2026-04-27

## 这份文档负责什么

- 作为当前仓库的总入口
- 只保留已经被代码或实测坐实的主结论
- 把“当前可用主线”和“历史阶段结论”明确分开，避免继续被旧判断污染

如果要看目录分层和推荐阅读顺序，请先看：

- [README.md](./README.md)

如果要追逐轮证据、运行时样本和长链推导，请看：

- [lingma-analysis-endpoint-auth.md](./lingma-analysis-endpoint-auth.md)
- [archive/lingma-analysis-snapshots.md](./archive/lingma-analysis-snapshots.md)

## 当前最稳的结论

### 1. `plugin` 仍然只是入口和交互层

- `cosy-intellij-2.11.1.jar` 中可以直接看到 `BaseChatPanel`、`InlineChatPanel`、`CosyServiceImpl`、`LanguageWebSocketService` 等 UI 和本地桥接类。
- 当前没有证据表明 plugin 自己在直接构造最终远端聊天请求。
- 当前更稳的模型仍然是：
  - plugin / IDE 负责上下文采集、UI、会话入口
  - `~/.lingma` 本地程序负责本地协议、鉴权材料、远端 HTTP/SSE 发送

### 2. 现在有两条可用自动化路线，不要再混成一个结论

#### 路线 A：本地 `37010` WebSocket/LSP

- 入口：`ws://127.0.0.1:37010`
- 当前状态：稳定、泛化能力最强、仍然是首选主线
- 已实测可复用：
  - `initialize`
  - `auth/status`
  - `config/queryModels`
  - `chat/ask`
- 当前仓库主实现：
  - [../lingma_client.py](../lingma_client.py)

这条路线已经脱离 plugin UI，但没有脱离本地 `Lingma` 运行时。

#### 路线 B：直接远端 HTTP API

- 当前状态：已成立，且 Chat API 已可自由构造
- 已实测成立：
  - `GET /algo/api/v2/model/list`
  - `POST /algo/api/v2/service/pro/sse/agent_chat_generation`
- 当前仓库主实现：
  - [../lingma_remote_api.py](../lingma_remote_api.py)
  - [remote-api-direct-connection.md](./remote-api-direct-connection.md)

这条路线已经脱离 plugin，也可以在不启动本地 `Lingma` 进程的情况下直接请求远端。当前已经成立的是：

- Chat body 直接发送原始 JSON
- `messages`、系统提示词和模型选择可自由构造
- Bearer 签名和请求头可独立生成

当前仍然存在的约束是：

- 仍依赖现有 Lingma 登录态导出的凭据
- OAuth 登录 / 刷新链未完全独立化
- TLS 指纹仍需要 `curl` 或等价能力

### 3. 当前真正剩下的硬问题已经收窄

当前已经不该再把阻塞点表述成：

- 不知道远端 endpoint
- 不知道 bearer 公式
- 不知道 `Encode=1` 字母表
- 不能离进程访问任何远端接口

当前真正剩下的问题是：

- 如何独立实现 OAuth 登录与刷新链
- 如何摆脱对现有 `~/.lingma/cache` 凭据材料的依赖
- 哪些非 Chat 端点仍然必须保留 `Encode=1` / 本地运行时能力

### 4. `tools/` 目录里大量编号脚本是历史实验，不是当前事实源

- `frida_插桩观察_v7` 到 `frida_插桩观察_v15`
- `frida_插桩观察_appsalt_v2` 到 `frida_插桩观察_appsalt_v7`
- `analyze_heartbeat2` 到 `analyze_heartbeat6`
- `patch_getappsalt_v2` / `v3`
- 各类 `test_*`、`final_*`、`*_analysis*`

这些文件保留了推导过程，但它们并不等于当前主结论。

整理后的使用规则是：

- 结论先看 `docs/`
- 当前实现先看根目录两个客户端
- `tools/` 只把无版本或最新版本脚本当作候选执行入口
- 旧报告只保留证据价值，不再当“最终状态”

## 当前推荐阅读顺序

### 1. 先看当前状态和边界

- [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
- [remote-api-direct-connection.md](./remote-api-direct-connection.md)

### 2. 再看本地主链为什么成立

- [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)
- [lingma-analysis-endpoint-auth.md](./lingma-analysis-endpoint-auth.md)

### 3. 最后再看专项细节

- [topics/encoding-alphabet-decoded.md](./topics/encoding-alphabet-decoded.md)
- [topics/encryption-analysis.md](./topics/encryption-analysis.md)
- [archive/lingma-analysis-snapshots.md](./archive/lingma-analysis-snapshots.md)

## 当前最稳的工程建议

- 如果目标是“稳定地自动调用 Lingma 能力”，优先继续沿 `37010` 主线工程化。
- 如果目标是“彻底脱离 plugin 和本地进程”，当前远端直连已经可工作，下一步应集中在凭据独立化、登录刷新链和 TLS 指纹能力，而不是继续回头证明 Chat body 还能不能自由构造。
- 如果继续扩展 `tools/`，优先新增明确命名的主线脚本，不要再堆新的 `vN` 和 `test_*` 变体而不收口。

## 当前主文件

- [../lingma_client.py](../lingma_client.py)
- [../lingma_remote_api.py](../lingma_remote_api.py)
- [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
- [remote-api-direct-connection.md](./remote-api-direct-connection.md)
- [../tools/README.md](../tools/README.md)
