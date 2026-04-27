# Lingma 请求链精简分析

## 目的

这份文档只保留当前问题需要的最小证据集：

- 当前 plugin 如何进入本地 `Lingma` 程序
- `~/.lingma` 如何把本地请求翻译成真实模型 API 请求
- 当前本地 `37010` 主线哪些环节已经能直接复用

不再重复保留：

- `docs/archive/lingma-analysis-snapshots.md` 里的多轮快照堆
- 与主聊天链无直接关系的历史增量记录
- 旧版本目录的噪声

## 使用边界

这份文档现在只负责本地 `37010` 主线。

如果你要看“已经脱离本地进程的远端直连”现状，请直接看：

- [remote-api-direct-connection.md](./remote-api-direct-connection.md)

不要再把这里的“本地主线最稳”误读成“远端直连完全没成立”。

## 当前活跃版本与入口

当前机器在 `2026-04-25` 的活跃版本来自：

- `C:\Users\Zipper\.lingma\bin\config.json`
  - `cosy.core.version = 2.11.1`

对应当前活跃目录：

- `C:\Users\Zipper\.lingma\bin\2.11.1\extension\main.js`
- `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\Lingma.exe`
- `C:\Users\Zipper\.lingma\bin\2.11.1\x86_64_windows\LingmaLocal.exe`

## 精简结论

### 1. plugin 不直接请求远端模型接口

当前最稳的链路仍然是：

1. plugin 侧组装聊天参数
2. plugin 通过本地 websocket/LSP 调 `ws://127.0.0.1:37010`
3. `~/.lingma` 本地服务接收 `chat/ask`
4. 本地服务内部 remoting + auth + transport 组装远端请求
5. 真实模型调用发往远端接口
6. 远端 SSE 结果再由本地服务异步回推给 plugin

### 2. `37010` 是当前最稳定的程序化入口

当前已知最小本地协议链：

1. `initialize`
2. `auth/status`
3. `config/queryModels`
4. `chat/ask`

其中：

- `auth/status` 用于读取当前登录态
- `config/queryModels` 用于读取模型注册表
- `chat/ask` 用于触发真实聊天链

### 3. 当前有两种不同层级的脱离方式

当前已经成立：

- 可以不走 plugin UI，直接复用本地 `37010`
- 可以直接调用远端 HTTP API，且 Chat body 已可自由构造

但这份文档不负责展开远端直连最新状态；那部分请直接看：

- [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
- [remote-api-direct-connection.md](./remote-api-direct-connection.md)

## plugin 到本地服务

plugin 侧主聊天链，当前可收敛为：

1. `BaseChatPanel/InlineChatPanel` 组装 `ChatAskParam`
2. `CosyServiceImpl` 维护本地会话状态
3. `LanguageWebSocketService.chatAsk()` 通过本地 websocket/LSP 调 `37010`

而当前活跃扩展包 `C:\Users\Zipper\.lingma\bin\2.11.1\extension\main.js` 的角色更像：

- 本地桥接层
- 本地 JSON-RPC 请求处理器
- 不是直接朝远端模型服务发 HTTP 的那一层

## 本地服务到远端模型 API

如果只看 `~/.lingma` 本地程序内部，当前最稳的五段模型是：

1. communication server 暴露本地入口
2. 本地 API handler 接收结构化请求
3. remoting 层决定远端 path、`Encode=1`、body 改写
4. auth provider 生成 `Authorization/Cosy-*`
5. transport 层发出真实 HTTP/SSE，并把结果回流给本地会话

这里最关键的工程判断是：

- 本地服务不是简单转发 `chat/ask`
- 它会重建远端请求形态
- 远端头和 body 都是在本地程序里重新生成的

## 当前最重要的远端接口

与模型请求最直接相关的是：

- `GET /algo/api/v2/model/list`
- `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`

## 当前最小可复用协议

仓库里已经有一个最小探针：

- `tools/lingma_probe.py`

它保留的最小调用顺序是：

1. 建立 `ws://127.0.0.1:37010`
2. 发送 `initialize`
3. 发送 `auth/status`
4. 发送 `config/queryModels`
5. 发送 `chat/ask`

当前最小 `chat/ask` 形状保留为：

```json
{
  "requestId": "<uuid>",
  "chatTask": "FREE_INPUT",
  "chatContext": null,
  "sessionId": "",
  "codeLanguage": "",
  "isReply": false,
  "source": 1,
  "questionText": "Reply with exactly: pong",
  "stream": true,
  "taskDefinitionType": "",
  "extra": null,
  "sessionType": "chat",
  "targetAgent": "",
  "pluginPayloadConfig": null,
  "mode": "normal",
  "shellType": "",
  "customModel": null
}
```

## 对当前问题的最终回答

如果问题是：

- `~/.lingma` 是如何通过 API 接口调用模型请求的

那么当前最稳的回答是：

1. plugin 并不直接请求模型远端接口
2. plugin 通过本地 websocket/LSP 调 `37010` 的 `chat/ask`
3. `Lingma` 本地程序接收后进入本地 handler
4. remoting 层决定远端 path、query、`Encode=1` 与 body 处理
5. auth provider 生成 `Authorization: Bearer COSY...` 和 `Cosy-*`
6. transport 层向远端发起真实 HTTP/SSE
7. 返回结果再由本地程序异步推回 plugin

补充一条当前已经成立的新边界：

- 现在仓库里也已经存在可工作的远端直连实现
- 但那条线解决的是“能否脱离本地进程发送远端请求”
- 这份文档解决的是“本地 `37010` 主线到底怎么工作”

## 后续建议

1. 先把 `37010` 封成稳定 client
2. 继续把 `chat/process_step_callback` / `chat/answer` 的 ack 语义补齐
3. 并行推进远端直连的 body 构造，但不要再重复证明本地主链已成立
