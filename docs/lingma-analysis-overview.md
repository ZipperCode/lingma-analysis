# Lingma 分析总览

更新时间：2026-04-30

## 这份文档负责什么

这份总览只负责三件事：

1. 给出当前仓库已经被代码和实测坐实的主结论。
2. 把“本地 `37010` 路线”和“远端 HTTP 直连路线”拆开说明。
3. 把实现入口、凭据边界、`Encode=1` 适用范围和后续专题文档串起来。

如果你想看文档分层和阅读顺序，请先看：

- [README.md](./README.md)

如果你想看长链证据和阶段性推导，请看：

- [lingma-analysis-endpoint-auth.md](./lingma-analysis-endpoint-auth.md)
- [lingma-analysis-token-flow.md](./lingma-analysis-token-flow.md)
- [archive/lingma-analysis-snapshots.md](./archive/lingma-analysis-snapshots.md)

## 当前最稳的结论

### 1. 当前仓库已经有两条可工作的实现链

#### 路线 A：本地 `37010` WebSocket/LSP

- 入口：`ws://127.0.0.1:37010`
- 当前主实现：[../lingma_client.py](../lingma_client.py)
- 当前最小调用顺序：
  1. `initialize`
  2. `auth/status`
  3. `chat/ask`
- 当前额外可用方法：
  - `config/queryModels`

这条路线的特点是：

- 已脱离 plugin UI
- 仍依赖本地 `Lingma` 运行时和登录态
- 适合做最稳定的工程化接入

`lingma_client.py` 当前已经把关键交互补齐到了可直接复用的程度：

- `connect()` 负责连上 `37010` 并完成 `initialize + auth/status`
- `ask()` 负责真实提问、等待 `step_end`、再发一次 trigger 解决返回延迟
- `_parse_lsp()` 负责解析 `Content-Length` framing
- `_collect_answer()` 负责拼接 `chat/answer` 增量文本

#### 路线 B：直接远端 HTTP API

- 入口：`https://lingma.alibabacloud.com/algo/api/...`
- 当前主实现：[../lingma_remote_api.py](../lingma_remote_api.py)
- 当前已直接打通的端点：
  - `GET /algo/api/v2/model/list`
  - `POST /algo/api/v2/service/pro/sse/agent_chat_generation`

这条路线的特点是：

- 已脱离 plugin
- 也可以在不启动本地 `Lingma` 进程时直接请求远端
- 当前真正的前提是“拿到有效凭据”，不是“再去证明 Chat body 能不能自由构造”

`lingma_remote_api.py` 当前已经包含完整的远端最小实现：

- `_read_credentials()` 负责按优先级读取凭据
- `_make_bearer()` 负责生成 COSY Bearer
- `_make_headers()` 负责构造远端请求头
- `_build_chat_body()` 负责生成原始 JSON chat body
- `chat()` 负责通过 `curl` 发送请求并解析 SSE
- `get_models()` 负责读取模型列表

### 2. 远端 Chat API 当前以“原始 JSON body”实现为准

这是当前最需要统一口径的一点：

- 当前仓库的远端直连实现以 [../lingma_remote_api.py](../lingma_remote_api.py) 为准。
- `chat()` 发送的是原始 JSON body，不依赖 `Encode=1`。
- SSE 响应按 `data:` 行解析，外层是 `{"body":"<inner-json>","statusCodeValue":200}`，内层是接近 OpenAI chat chunk 的结构。

因此不应再把下面两句话混成一个结论：

- “历史抓包里，本地运行时某些聊天请求形态里出现过 `Encode=1`”
- “今天独立远端直连时，Chat API 仍必须手工做 `Encode=1`”

前者是阶段性证据，后者已经被当前实现否定。

### 3. `Encode=1` 已解析，但不再是当前远端 Chat 主线的前置条件

[../lingma_remote_api.py](../lingma_remote_api.py) 仍保留了：

- `lingma_encode()`
- `lingma_decode()`
- `aes_encrypt()`
- `aes_decrypt()`

它们的意义现在应该这样理解：

- `lingma_encode()` / `lingma_decode()`：
  - 对应 `Encode=1` 的自定义 base64 + 三块重排逻辑
  - 对某些历史端点和专项验证仍然有价值
- `aes_encrypt()` / `aes_decrypt()`：
  - 对应本地缓存的 AES-128-CBC 逻辑
  - 不是当前远端 Chat API 的 body 加密层

也就是说：

- `Encode=1` 是已解析能力
- 不是当前远端直连聊天必须经过的步骤

### 4. 当前最关键的共享边界是“凭据材料”，不是“协议未知”

当前两条路线的真正共同点不是调用形式，而是它们都绕不开凭据边界：

- 本地路线依赖本地 Lingma 登录态
- 远端路线依赖有效的 `cosy_key`、`encrypt_user_info`、`user_id`、`machine_id`

当前仓库已经把这部分边界落到了代码里：

- [../lingma_remote_api.py](../lingma_remote_api.py) 中 `_read_credentials()`
- [../lingma_remote_api.py](../lingma_remote_api.py) 中本地缓存解密逻辑

当前已坐实的规则是：

- 本地缓存优先材料在 `~/.lingma/cache/id` 和 `~/.lingma/cache/user`
- `cache/user` 为 base64 后的 AES-128-CBC 密文
- 解密使用 `machine_id[:16]` 同时作为 key 和 IV
- 解密后可得到：
  - `key` → `Cosy-Key`
  - `encrypt_user_info` → Bearer payload 中的 `info`
  - `uid` → `Cosy-User`

## 当前推荐阅读顺序

### 1. 先看当前状态

- [lingma-analysis-final-status.md](./lingma-analysis-final-status.md)
- [remote-api-direct-connection.md](./remote-api-direct-connection.md)

### 2. 再看本地主链为什么成立

- [lingma-analysis-request-flow-pruned.md](./lingma-analysis-request-flow-pruned.md)
- [lingma-analysis-endpoint-auth.md](./lingma-analysis-endpoint-auth.md)

### 3. 最后再看专项细节

- [topics/encode1-complete-analysis.md](./topics/encode1-complete-analysis.md)
- [topics/encoding-alphabet-decoded.md](./topics/encoding-alphabet-decoded.md)
- [topics/encryption-analysis.md](./topics/encryption-analysis.md)
- [topics/heartbeat-body-structure.md](./topics/heartbeat-body-structure.md)

### 4. 如果目标是继续做完全独立化

这部分请明确它属于“下游设计与后续工程”，不要和当前仓库已落地实现混读：

- [topics/client-id-extraction.md](./topics/client-id-extraction.md)
- [topics/session-key-analysis.md](./topics/session-key-analysis.md)
- [topics/refresh-token-flow.md](./topics/refresh-token-flow.md)
- [topics/standalone-oauth-analysis.md](./topics/standalone-oauth-analysis.md)
- [superpowers/specs/](./superpowers/specs/)

## 当前最稳的工程建议

- 如果目标是“稳定地自动调用 Lingma 能力”，优先继续沿本地 `37010` 主线工程化。
- 如果目标是“尽量脱离本地运行时”，当前远端直连已经可用，重点应放在凭据独立化、OAuth 登录刷新链和 TLS 指纹能力，而不是继续重复证明 Chat body 能不能自由构造。
- 如果要继续扩展文档，优先把结论收敛进根层主文档，再把长链证据放进 `topics/`、`archive/` 或 `tools-archive/`，不要再让不同阶段的口径在同一阅读层并列。
