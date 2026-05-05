# Lingma 请求链精简分析

更新时间：2026-04-30

## 目的

这份文档只保留本地 `37010` 主线需要的最小证据集：

- plugin 如何把请求送进本地 `Lingma` 运行时
- 本地 `37010` 路线目前已经能直接复用到什么程度
- 当前仓库里的本地客户端实现到底做了哪些关键补丁

不再在这里展开：

- 远端直连的完整现状
- 历史多轮样本堆
- 独立 OAuth / `client_id` / `refresh_token` 设计

对应实现：

- [../lingma_client.py](../lingma_client.py)
- [../tools/lingma_probe.py](../tools/lingma_probe.py)

## 使用边界

这份文档只负责本地 `37010` 路线。

如果你要看“已经脱离本地进程的远端直连”现状，请直接看：

- [remote-api-direct-connection.md](./remote-api-direct-connection.md)

不要再把这里的“本地主线最稳”误读成“远端直连没有成立”。

## 当前活跃结论

### 1. plugin 不是最终远端调用层

当前最稳的链路仍然是：

1. plugin / IDE 侧组装聊天参数
2. plugin 通过本地 WebSocket/LSP 调 `ws://127.0.0.1:37010`
3. 本地 `Lingma` 运行时接收 `chat/ask`
4. 本地运行时内部重建远端 HTTP 请求、请求头和会话状态
5. 返回结果再通过 `chat/answer` 等事件推回调用端

因此：

- plugin 可以绕过
- 本地 `Lingma` 运行时在这条链里仍然是执行主体

### 2. 当前最稳的程序化入口是 `ws://127.0.0.1:37010`

当前已知最小协议链是：

1. 建立 websocket 连接
2. 发送 `initialize`
3. 发送 `auth/status`
4. 发送 `chat/ask`

常用补充方法：

- `config/queryModels`

### 3. 当前仓库已经把这条链做成可直接运行的客户端

[../lingma_client.py](../lingma_client.py) 当前不是一个简单 PoC，而是已经包含几个关键实现决策：

- `connect()`：
  - 建立连接
  - 发送 `initialize`
  - 读取 `auth/status`
- `_send()`：
  - 按 LSP framing 发送 `Content-Length: <n>\r\n\r\n<json>`
- `_parse_lsp()`：
  - 解析服务端返回的 LSP framing
- `ask()`：
  - 先发送真实问题
  - 等待 `chat/process_step_callback.step == "step_end"`
  - 再发一次 trigger 请求拿到真正文本
- `_collect_answer()`：
  - 只拼接目标 `requestId` 的 `chat/answer`

这说明当前仓库已经不只是“证明本地端口存在”，而是已经把交互细节写成了稳定实现。

## 当前最小协议模板

### 协议要求

- 连接目标：
  - `ws://127.0.0.1:37010`
- 消息格式：
  - `Content-Length: <n>\r\n\r\n<json>`

### 当前最小顺序

1. `initialize`
2. `auth/status`
3. `config/queryModels`（可选）
4. `chat/ask`

### 当前最小 `chat/ask` 形状

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

### 已知边界

- 裸 JSON 不行，会触发 `Unknown message header`
- 当前服务端对 `initialized` 不敏感，但 `initialize` 仍然是事实上的前置步骤

## 本地主线与远端直连的边界

这是当前文档里最容易被混读的一点：

- 从本地运行时历史抓包看，`chat/ask` 内部确实曾被重建成带特定 query 参数的远端请求。
- 但这不再自动推出“今天独立远端直连时也必须保留完全相同的 body 编码策略”。

当前应统一成下面这个表述：

1. 本地 `37010` 路线解决的是：
   - plugin 如何进入本地运行时
   - 本地运行时如何把结果回推给调用端
2. 远端直连路线解决的是：
   - 能否在没有本地进程参与发送的情况下独立请求远端 Chat API
3. 这两条路线共享部分认证材料，但不是同一层实现

因此这份文档不再把远端 Chat 的当前可行性绑死在旧的 `Encode=1` 阶段结论上。

## 对当前问题的精简回答

如果问题是：

- 本地 `Lingma` 程序到底怎么通过 API 接口调用模型

当前最稳的回答是：

1. plugin 并不直接请求远端模型接口
2. plugin 通过本地 websocket/LSP 调 `37010` 的 `chat/ask`
3. 本地 `Lingma` 运行时接收后进入本地 handler
4. 本地运行时内部决定远端 path、请求头、会话状态和结果回流
5. 远端结果再通过 `chat/answer` 等事件异步推回

如果问题是：

- 当前仓库有没有把这条链做成可以直接用的代码

答案也是肯定的：

- [../lingma_client.py](../lingma_client.py) 已经把连接、初始化、鉴权状态读取、提问、回流文本拼接都落地了

## 后续建议

1. 本地主线继续围绕 [../lingma_client.py](../lingma_client.py) 做工程化，不要再回到一次性探针堆里找入口。
2. 如果需要展开登录态、缓存和 token 同步链，转去看 [lingma-analysis-token-flow.md](./lingma-analysis-token-flow.md)。
3. 如果需要展开完全脱离本地进程的远端直连，转去看 [remote-api-direct-connection.md](./remote-api-direct-connection.md)。
