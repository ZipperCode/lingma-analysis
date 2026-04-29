# Lingma Tool Call Bridge 设计文档

> 日期：2026-04-28
> 目标：在 lingma2api 代理层中桥接 OpenAI/Anthropic 工具调用协议

## 1. 目标

在现有 lingma2api OpenAI 兼容代理的基础上，扩展支持：

- **OpenAI 工具调用**：接受 `tools` 参数，透传 `tool_calls`/`tool` 角色消息，在 SSE 流中解析并回传工具调用增量
- **Lingma 内置工具协议研究**：通过 Frida 逐步发现 Lingma IDE 原生工具能力并映射为 OpenAI 工具定义
- **Anthropic 格式**（后续）：在 OpenAI 跑通后，基于统一的 Message IR 添加 Anthropic `/v1/messages` 端点

## 2. 架构

```
OpenAI Handler (/v1/chat/completions)  ──┐
                                          ├── Message IR ── BodyBuilder ── CurlTransport ── Lingma 远端
Anthropic Handler (/v1/messages) (后续) ──┘                    SSE Parser ──┘
```

### 改动边界

| 文件 | 改动类型 | 说明 |
|------|---------|------|
| `proxy/types.go` | 修改 | Message 加 tool_calls/tool_call_id/name；OpenAIChatRequest 加 tools/tool_choice |
| `proxy/body.go` | 修改 | 序列化 messages 时透传 tool_calls 和 tool_call_id |
| `proxy/sse.go` | 修改 | 解析 delta.tool_calls 增量，聚合 arguments 片段 |
| `api/server.go` | 修改 | validateChatRequest 扩展 tool 角色校验 |
| `proxy/tool_registry.go` | 新增 | 空工具注册表，为后续内置工具映射预留接口 |
| `proxy/message_ir.go` | 新增 | Message IR 与 OpenAI/Anthropic 格式互转（Anthropic 后续用） |

## 3. 消息格式

### 3.1 扩展的 Message IR

```go
type Message struct {
    Role       string     `json:"role"`
    Content    string     `json:"content,omitempty"`
    Name       string     `json:"name,omitempty"`
    ToolCallID string     `json:"tool_call_id,omitempty"`
    ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

type ToolCall struct {
    ID       string       `json:"id"`
    Type     string       `json:"type"`
    Function FunctionCall `json:"function"`
}

type FunctionCall struct {
    Name      string `json:"name"`
    Arguments string `json:"arguments"`
}
```

### 3.2 OpenAI 请求扩展

```go
type OpenAIChatRequest struct {
    // 现有字段保持不变
    Tools      []Tool `json:"tools,omitempty"`
    ToolChoice any    `json:"tool_choice,omitempty"`
}

type Tool struct {
    Type     string       `json:"type"`
    Function ToolFunction `json:"function"`
}
```

### 3.3 透传策略（Phase 1）

不校验、不转换 tools 定义。Phase 1 先尝试将 tools 数组也透传入 Lingma body，如果远端接受（200）则保持；如果返回 400/422 则摘掉 tools 字段重试。仅透传 messages 中的 tool_calls 和 tool_call_id 字段。工具调用由模型自主决定。

如果 Lingma 返回 400/422 表示不接受 tool_calls 字段，则进入 Phase 2 用 Frida 抓取实际格式修正。

## 4. 响应转换

### 4.1 SSE 解析扩展

```go
type innerSSEPayload struct {
    Choices []struct {
        Delta struct {
            Content   string           `json:"content"`
            ToolCalls []toolCallDelta  `json:"tool_calls"`
        } `json:"delta"`
    } `json:"choices"`
}

type toolCallDelta struct {
    Index    int               `json:"index"`
    ID       string            `json:"id,omitempty"`
    Type     string            `json:"type,omitempty"`
    Function functionCallDelta `json:"function,omitempty"`
}
```

### 4.2 Tool Calls 增量聚合

按 `index` 聚合同一个 tool_call 的多个 SSE chunk：

```
chunk 1: {index:0, id:"c2", type:"function", function:{name:"read_file", arguments:""}}
chunk 2: {index:0, function:{arguments:"{\"p\":"}}  
chunk 3: {index:0, function:{arguments:"\"util.go\"}"}}
→ 聚合为: {id:"c2", type:"function", function:{name:"read_file", arguments:"{\"p\":\"util.go\"}"}}
```

流式输出时按聚合进度增量 emit，保持 OpenAI 兼容的 SSE chunk 格式。

## 5. 校验规则

| 规则 | 场景 | 错误码 |
|------|------|--------|
| messages 非空 | len(messages) == 0 | 400 |
| tool 角色需 tool_call_id | role=="tool" && tool_call_id=="" | 400 |
| assistant tool_calls 非空时 function.name 必填 | tool_calls[].function.name=="" | 400 |
| tool_calls arguments 合法 JSON | json.Unmarshal 失败 | 400 |

## 6. 工具注册表（空壳）

```go
type ToolRegistry struct {
    tools map[string]ToolDefinition
}

type ToolDefinition struct {
    Name        string
    Description string
    Parameters  map[string]any // JSON Schema
    Handler     ToolHandler    // nil = 透传
}
```

Phase 1 注册表为空，所有工具透传。Phase 3 协议研究出内置工具后填充注册表。

## 7. Phase 计划

| Phase | 内容 | 交付物 |
|-------|------|--------|
| Phase 1 | 消息格式扩展 + SSE 解析 + 校验 | lingma2api 支持 OpenAI tool_calls |
| Phase 2 | Frida 动态追踪 Lingma IDE 工具调用 | 原生格式修正 + 内置工具列表 |
| Phase 3 | 内置工具映射 + Anthropic 格式 | 完整的双格式工具调用桥接 |

## 8. 不做什么

- Phase 1 不在代理层执行工具（只透传）
- Phase 1 不支持 Anthropic 格式
- 不修改 COSY Bearer 签名逻辑
- 不修改凭据管理
- 不引入新的外部依赖
