# `lingma2api` 项目设计文档

> 说明（2026-04-27）：
> 本文中的运行态认证来源设计已被 [2026-04-27-lingma2api-project-auth-design.md](/Users/Zipper/Github/lingma-analysis/docs/plans/2026-04-27-lingma2api-project-auth-design.md) 取代。
> 当前有效边界是：运行态只读取项目内认证文件，不再读取 `~/.lingma/*`。

更新时间：`2026-04-27`

## 1. 项目目标

`lingma2api` 是一个 Go 编写的代理服务，对外暴露最小 OpenAI 兼容接口，对内调用 Lingma 远端 HTTP/SSE 接口。

项目首期目标：

1. 让 `Claude Code`、`Codex`、`OpenCode` 等 OpenAI 兼容客户端直接使用 Lingma 聊天模型。
2. 运行时不依赖 Lingma plugin，也不依赖本地 Lingma 进程。
3. 复用当前已经验证可工作的 Lingma 远端请求结构、签名链和 SSE 返回格式。
4. 以最小可实现范围先交付稳定聊天代理，再逐步补齐增强能力。

## 2. 设计范围

### 2.1 首期范围

首期只实现以下能力：

1. `POST /v1/chat/completions`
2. `GET /v1/models`
3. 凭据加载与热重读
4. 服务端会话管理
5. 远端 SSE 转 OpenAI SSE
6. 最小管理接口

### 2.2 非目标

首期明确不做：

1. 独立 OAuth 登录、PKCE、token 刷新
2. OpenAI `tool_calls` 与 Lingma 私有 agent/tool 协议桥接
3. 图片、多模态、embedding、代码库索引等扩展能力
4. 国内站与国际站双栈自动切换
5. 多租户、多用户强隔离

## 3. 设计输入与前置假设

本设计基于当前已验证事实，但这里不展开分析过程，只保留实现会直接依赖的前提：

1. 远端模型列表接口可用：
   - `GET /algo/api/v2/model/list`
2. 远端聊天接口可用：
   - `POST /algo/api/v2/service/pro/sse/agent_chat_generation`
3. Chat body 直接发送原始 JSON，不需要 `Encode=1`。
4. 远端鉴权依赖 COSY Bearer 和 `Cosy-*` 请求头。
5. 当前可行的凭据来源是：
   - 显式注入
   - 环境变量
   - 便携配置
   - `cache/user + cache/id`
6. 当前没有证据支持“首期即可独立实现 OAuth 登录刷新”，因此该能力不纳入设计边界。

实现时若需回看证据，参考：

- [lingma_remote_api.py](/Users/Zipper/Github/lingma-analysis/lingma_remote_api.py)
- [lingma_client.py](/Users/Zipper/Github/lingma-analysis/lingma_client.py)
- [docs/remote-api-direct-connection.md](/Users/Zipper/Github/lingma-analysis/docs/remote-api-direct-connection.md)
- [docs/lingma-analysis-overview.md](/Users/Zipper/Github/lingma-analysis/docs/lingma-analysis-overview.md)

## 4. 成功标准

首期完成的判定标准：

1. 代理服务可在未启动本地 Lingma 进程时正常工作。
2. 代理服务可用有效凭据返回 Lingma 模型列表。
3. 代理服务可完成流式和非流式聊天。
4. OpenAI 客户端可通过 `model` 和 `messages` 发起请求，不需要了解 Lingma 私有 body 结构。
5. 会话模式下，代理可持续维护多轮上下文。
6. 错误能准确区分为：
   - 凭据问题
   - 模型问题
   - 远端连接问题
   - SSE 中断问题

## 5. 设计原则

### 5.1 运行时独立，凭据引导不独立

本项目追求的是“代理运行时独立”，不是“首次授权链独立”。

这意味着：

1. 代理运行时不需要 plugin。
2. 代理运行时不需要本地 Lingma 进程。
3. 代理仍然允许依赖一次性凭据导出或本地缓存材料。

### 5.2 最小兼容优先

OpenAI 兼容层只覆盖当前后续接入真正需要的最小子集，不主动过度模拟全部 OpenAI 能力。

### 5.3 先稳定，再原生优化

首期先实现稳定可用版本，再考虑替换传输层或扩展协议能力。不能为了“更原生”牺牲首期可交付性。

### 5.4 未验证能力不写进首期实现承诺

凡是当前仓库还没有验证成功的链路，只能作为后续增强，不应写成首期必做项。

## 6. 用户与使用场景

### 6.1 目标用户

1. 使用 OpenAI 兼容接口的本地开发工具
2. 需要以服务化方式复用 Lingma 模型能力的脚本或客户端
3. 后续要在新项目里集成 Lingma 能力的开发者

### 6.2 核心场景

#### 场景 A：列出模型

客户端调用 `/v1/models`，代理拉取或返回缓存的 Lingma 模型列表。

#### 场景 B：单轮聊天

客户端调用 `/v1/chat/completions`，代理将 OpenAI 风格消息转换为 Lingma Chat body，向远端发起请求并返回结果。

#### 场景 C：多轮聊天

客户端通过 `session_id` 绑定上下文，代理维护历史消息，并在每次请求时构造完整远端 `messages`。

#### 场景 D：凭据热更新

管理员更新凭据来源后，调用 `/admin/refresh`，代理重新加载凭据并刷新模型表。

## 7. 外部接口设计

### 7.1 `POST /v1/chat/completions`

#### 请求子集

首期接受以下字段：

- `model`
- `messages`
- `stream`
- `temperature`
- `extra_body.session_id`

同时支持请求头：

- `X-Session-Id`

请求示例：

```json
{
  "model": "qwen3-coder",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello"}
  ],
  "stream": true,
  "temperature": 0.1
}
```

#### 行为规则

1. `messages` 是唯一可信对话输入。
2. `session_id` 只影响代理侧历史拼装，不直接透传为 Lingma 的长期会话机制。
3. 当 `stream=false` 时，代理消费完整 SSE 后返回标准非流式 OpenAI 响应。
4. 当 `stream=true` 时，代理逐块转发 OpenAI SSE。

#### 首期不支持

- `tool_calls`
- `parallel_tool_calls`
- `response_format`
- 图片输入
- OpenAI Responses API 语义

### 7.2 `GET /v1/models`

#### 目标

返回当前代理可用的模型集合。

#### 数据优先级

1. 最近一次成功拉取的远端模型表
2. 内存缓存
3. 静态兜底别名表

### 7.3 管理接口

首期保留：

- `GET /admin/status`
- `POST /admin/refresh`
- `GET /admin/sessions`
- `DELETE /admin/sessions/{id}`

#### 管理接口语义

1. `/admin/status`
   - 查看当前凭据加载状态、模型表状态、会话数量
2. `/admin/refresh`
   - 重新读取凭据源
   - 重新刷新模型表
3. `/admin/sessions`
   - 查看活跃会话摘要
4. `/admin/sessions/{id}`
   - 删除指定会话

注意：

- `/admin/refresh` 不是 OAuth refresh 接口

## 8. 端到端请求流程

### 8.1 聊天请求流程

```text
Client
  -> POST /v1/chat/completions
  -> API Handler 校验输入
  -> Session Manager 合并历史消息
  -> Model Mapper 解析模型 key
  -> Credential Manager 读取当前凭据
  -> Signature Engine 生成 Bearer 和 Cosy-* 头
  -> Lingma Transport 发起远端 SSE
  -> SSE Parser 转换为 OpenAI 格式
  -> 返回给 Client
```

### 8.2 模型列表流程

```text
Client
  -> GET /v1/models
  -> API Handler
  -> Credential Manager
  -> Signature Engine
  -> Lingma Transport 请求远端模型表
  -> Model Mapper 标准化输出
  -> 返回给 Client
```

## 9. 核心模块设计

### 9.1 API Handler

职责：

1. 提供 HTTP 路由
2. 解析 OpenAI 风格请求
3. 做参数校验与错误映射
4. 组织流式与非流式响应

输出边界：

1. 不直接关心凭据来源细节
2. 不直接关心 Bearer 计算细节
3. 不直接关心远端 SSE 原始结构

### 9.2 Session Manager

职责：

1. 维护 `session_id -> message history`
2. 支持无状态和有状态两种模式
3. 定时清理超时会话

数据结构建议：

```text
Session {
  id: string
  messages: []Message
  updated_at: time.Time
}
```

规则：

1. 如果没有 `session_id`，只使用当前请求 `messages`
2. 如果有 `session_id`，按顺序追加并构造完整远端 `messages`
3. TTL 默认 `30` 分钟

### 9.3 Model Mapper

职责：

1. 维护别名到远端 key 的映射
2. 处理默认模型语义
3. 标准化 `/v1/models` 输出

关键规则：

1. 如果客户端传入远端已知 key，直接透传
2. 如果传入代理别名，转换成远端 key
3. 如果传入 `auto` 或空值，转换成 `model_config.key = ""`
4. 如果模型未知，返回 `400`

首期内置别名建议：

| 外部模型名 | 远端 key |
|---|---|
| `qwen3-coder` | `dashscope_qwen3_coder` |
| `qwen3-coder-default` | `dashscope_qwen3_coder_default` |
| `qwen-plus-thinking` | `dashscope_qwen_plus_20250428_thinking` |
| `qwen-max` | `dashscope_qwen_max_latest` |
| `auto` | `""` |

### 9.4 Credential Manager

职责：

1. 从多种来源加载凭据
2. 解密 `cache/user`
3. 提供线程安全的当前凭据快照
4. 支持热重载

来源优先级：

1. `config.yaml` 显式字段
2. 环境变量
3. `portable_config.json`
4. `cache/user + cache/id`

环境变量：

- `LINGMA_COSY_KEY`
- `LINGMA_ENCRYPT_USER_INFO`
- `LINGMA_USER_ID`
- `LINGMA_MACHINE_ID`

缓存解密规则：

```text
machineKey = read(cache/id)
aesKey = machineKey[:16]
iv = aesKey
plaintext = AES-128-CBC.decrypt(base64decode(cache/user), aesKey, iv)
```

首期只提取这些字段：

- `key`
- `encrypt_user_info`
- `uid`
- `machine_id`

### 9.5 Signature Engine

职责：

1. 生成 Bearer payload
2. 生成 MD5 签名
3. 生成完整 `Cosy-*` 请求头

Bearer 结构：

```text
COSY.<base64_payload>.<md5_signature>
```

payload：

```json
{
  "cosyVersion": "2.11.2",
  "ideVersion": "",
  "info": "<encrypt_user_info>",
  "requestId": "<uuid>",
  "version": "v1"
}
```

签名公式：

```text
normalized_path = strip "/algo" prefix from path
preimage =
  base64(payload) + "\n" +
  cosy_key + "\n" +
  unix_timestamp + "\n" +
  slot4 + "\n" +
  normalized_path
signature = md5(preimage).hex()
```

其中：

1. `GET` 请求 `slot4 = ""`
2. `POST` 请求 `slot4 = 原始 JSON body`

### 9.6 Lingma Transport

职责：

1. 发送远端 HTTP 请求
2. 支持 SSE 流式读取
3. 为上层提供统一 transport 接口

传输层分两阶段：

#### Phase 1：`curl bridge`

首期使用 `curl` 子进程作为远端传输实现。

原因：

1. 当前仓库已有稳定验证样本
2. 能规避首期 TLS 指纹不确定性
3. 实现成本最低

#### Phase 2：Go 原生 `utls`

在首期稳定后，再补原生实现：

1. `utls` 连接池
2. 原生 SSE 解析
3. 更细粒度重试、超时、连接复用

### 9.7 关键内部接口

为了避免实现阶段再次发散，建议从一开始就把内部边界固定成接口，而不是让 `handler` 直接依赖具体实现。

建议接口草图：

```go
type SessionStore interface {
    BuildMessages(ctx context.Context, sessionID string, incoming []Message) ([]Message, error)
    Delete(ctx context.Context, sessionID string) error
    List(ctx context.Context) ([]SessionState, error)
    SweepExpired(ctx context.Context) error
}

type CredentialProvider interface {
    Current(ctx context.Context) (CredentialSnapshot, error)
    Refresh(ctx context.Context) (CredentialSnapshot, error)
}

type ModelResolver interface {
    ResolveChatModel(ctx context.Context, requested string) (string, error)
    ListModels(ctx context.Context) ([]OpenAIModel, error)
    Refresh(ctx context.Context) error
}

type Transport interface {
    ListModels(ctx context.Context, cred CredentialSnapshot) ([]RemoteModel, error)
    StreamChat(ctx context.Context, req RemoteChatRequest, cred CredentialSnapshot) (ChatStream, error)
}
```

设计要求：

1. `API Handler` 只依赖这些接口
2. `curl bridge` 和后续 `utls` 实现共用同一个 `Transport` 接口
3. `ModelResolver` 负责 `auto -> ""` 以及别名解析
4. `CredentialProvider` 只返回脱敏后的结构体快照，不暴露原始文件处理逻辑给上层

## 10. 远端请求契约

### 10.1 远端端点

- 模型列表：
  - `GET /algo/api/v2/model/list`
- 聊天：
  - `POST /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common`

### 10.2 关键请求头

```text
Authorization: Bearer COSY.<payload>.<signature>
Cosy-Date: <unix_timestamp>
Cosy-Key: <key>
Cosy-User: <uid>
Cosy-Machineid: <machine_id>
Cosy-Clientip: 198.18.0.1
Cosy-Clienttype: 2
Cosy-Machineos: x86_64_windows
Cosy-Machinetoken: ""
Cosy-Machinetype: ""
Cosy-Version: 2.11.2
Appcode: cosy
Login-Version: v2
User-Agent: Go-http-client/1.1
```

### 10.3 Chat body 设计

远端 Chat body 由代理完整构造，不依赖调用方提供 Lingma 私有字段。

设计要求：

1. `messages` 由代理根据 OpenAI 请求生成
2. `model_config.key` 由 `Model Mapper` 生成
3. 保留当前已验证稳定字段，如：
   - `request_id`
   - `chat_record_id`
   - `stream`
   - `parameters`
   - `agent_id`
   - `task_id`
   - `business`
4. 首期不要主动删减那些已知稳定、但短期内没有成本收益的字段

实现基线直接对齐：

- [lingma_remote_api.py](/Users/Zipper/Github/lingma-analysis/lingma_remote_api.py:230)

### 10.4 SSE 解析设计

远端 SSE 解析流程：

1. 逐行读取 `data:`
2. 解析外层 JSON：
   - `{"body":"<inner-json>","statusCodeValue":200}`
3. 过滤 `[DONE]`
4. 解析内层 JSON
5. 抽取 `choices[].delta.content`
6. 输出 OpenAI 兼容 SSE chunk

## 11. 数据模型

### 11.1 内部消息模型

```text
Message {
  role: "system" | "user" | "assistant"
  content: string
}
```

### 11.2 凭据模型

```text
CredentialSnapshot {
  cosy_key: string
  encrypt_user_info: string
  user_id: string
  machine_id: string
  source: string
  loaded_at: time.Time
}
```

### 11.3 模型注册表模型

```text
ModelRegistry {
  fetched_at: time.Time
  models_by_key: map[string]RemoteModel
  alias_to_key: map[string]string
}
```

### 11.4 会话模型

```text
SessionState {
  id: string
  messages: []Message
  updated_at: time.Time
}
```

### 11.5 远端聊天请求模型

实现层建议在内部显式定义 `RemoteChatRequest`，避免在多个模块里散落拼 JSON 的逻辑。

```text
RemoteChatRequest {
  path: string
  query: string
  body_json: string
  request_id: string
  model_key: string
}
```

## 12. 错误处理设计

错误必须能帮助调用方定位问题来源，不能只返回“请求失败”。

建议最小映射：

| 场景 | 代理返回 |
|---|---|
| 凭据缺失 | `500` |
| 凭据解密失败 | `500` |
| 模型未知 | `400` |
| 上游鉴权失败 | `401` 或 `502` |
| TLS / 网络失败 | `502` |
| SSE 中途断流 | 流式终止并输出错误结束块，或非流式返回 `502` |
| 模型表拉取失败 | 使用旧缓存并记录错误 |

禁止行为：

1. 模型未知时静默切到默认模型
2. 凭据失效时返回模糊“无响应”
3. SSE 被截断时假装成功完成

## 13. 可观测性设计

首期至少记录：

1. 请求 ID
2. 远端路径
3. 选中的模型 key
4. 凭据来源
5. 会话 ID
6. 请求耗时
7. 远端状态码或错误摘要

日志中禁止输出：

1. 完整 `cosy_key`
2. 完整 `encrypt_user_info`
3. 完整 Bearer token

## 14. 配置设计

建议最小配置：

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  admin_token: ""

credential:
  cosy_key: ""
  encrypt_user_info: ""
  user_id: ""
  machine_id: ""
  lingma_dir: ""
  portable_config: ""

session:
  ttl_minutes: 30
  max_sessions: 100

lingma:
  base_url: "https://lingma.alibabacloud.com"
  cosy_version: "2.11.2"
  transport: "curl"
```

配置原则：

1. 显式字段优先，便于容器部署
2. `transport` 可切换，便于后续引入 `utls`

## 15. 项目结构建议

```text
lingma2api/
├── main.go
├── go.mod
├── config.yaml
├── internal/
│   ├── api/
│   │   ├── chat.go
│   │   ├── models.go
│   │   └── admin.go
│   ├── config/
│   │   └── config.go
│   ├── credential/
│   │   └── manager.go
│   ├── session/
│   │   └── manager.go
│   ├── modelmap/
│   │   └── mapper.go
│   ├── signature/
│   │   └── engine.go
│   └── lingma/
│       ├── client.go
│       ├── transport.go
│       ├── body.go
│       └── sse.go
└── README.md
```

## 16. 测试策略

### 16.1 单元测试

至少覆盖：

1. 模型别名解析
2. `auto -> ""` 转换
3. `cache/user` 解密
4. Bearer 签名计算
5. SSE 外层 / 内层解析
6. session 合并逻辑

### 16.2 集成测试

至少覆盖：

1. `/v1/models` 代理返回
2. `/v1/chat/completions` 流式
3. `/v1/chat/completions` 非流式
4. `/admin/refresh`
5. 错误凭据场景

### 16.3 Mock 策略

为了降低测试成本：

1. `Transport` 必须可 mock
2. `CredentialProvider` 必须可 mock
3. `ModelResolver` 必须可 mock
4. SSE 解析逻辑要能脱离真实网络做纯数据测试

## 17. 分阶段交付

### Phase 1：最小可用版本

交付内容：

1. 凭据加载
2. 模型列表
3. 流式 / 非流式聊天
4. `curl bridge`
5. 基础错误处理

### Phase 2：代理能力完善

交付内容：

1. 会话管理
2. 管理接口
3. 模型表缓存与刷新
4. 更细的日志与状态输出

### Phase 3：传输层增强

交付内容：

1. Go 原生 `utls`
2. 更稳定的 SSE 与连接管理
3. 重试、超时、指标

## 18. 验收标准

在声称首期完成前，至少要通过这些验证：

1. 使用显式凭据或便携配置可以启动服务
2. `/v1/models` 能返回模型列表
3. `stream=true` 时能持续输出 chunk
4. `stream=false` 时能输出完整响应
5. `model=auto` 会映射成空 key，而不是字面量 `auto`
6. 显式模型 key 能正确透传
7. 使用 `session_id` 的第二轮请求能带上第一轮上下文
8. 错误凭据会产生明确鉴权失败
9. `/admin/refresh` 能重读凭据并刷新模型表

## 19. 风险与后续问题

这些问题需要记录，但不阻塞首期：

1. Go 原生 `utls` 是否能完全替代 `curl`
2. 长对话历史是否会触发远端长度或稳定性问题
3. 国内站凭据体系是否值得单独支持
4. 哪些非 Chat 端点未来仍需要 `Encode=1`
5. 是否需要在二期以后设计 `tool_calls` 桥接层

## 20. 结论

这份设计文档的目的，不是复述 Lingma 已经分析出了什么，而是把这些已知事实转成一个可直接指导实现的工程方案。

后续如果按本设计进入实现，应严格以这些边界推进：

1. 首期只做最小聊天代理
2. 不把 OAuth 独立化混入首期范围
3. 先交付稳定可用的 `curl bridge` 版本
4. 再迭代原生 `utls`、工具调用桥接和更多能力
