# Lingma Tool Call Bridge 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 lingma2api 代理层中扩展 OpenAI tool_calls 支持，实现消息透传 + SSE 解析 + 校验

**Architecture:** 扩展现有 `proxy/types.go` 的 Message/OpenAIChatRequest 结构体，修改 `proxy/body.go` 的序列化逻辑透传 tool_calls 字段，扩展 `proxy/sse.go` 的 SSE 解析器处理 tool_calls 增量流，在 `api/server.go` 增加 tool 消息校验

**Tech Stack:** Go 1.24, stdlib (无新依赖)

**Spec:** `docs/superpowers/specs/2026-04-28-lingma-tool-call-bridge-design.md`

---

## 文件结构

| 文件 | 职责 | 改动 |
|------|------|------|
| `proxy/types.go` | Message IR, ToolCall, Tool, 请求/响应类型 | 修改 |
| `proxy/body.go` | OpenAI Message → Lingma Remote Body 序列化 | 修改 |
| `proxy/body_test.go` | body 序列化单元测试 | 修改 |
| `proxy/sse.go` | Lingma SSE → OpenAI SSE Event 解析 | 修改 |
| `proxy/sse_test.go` | SSE 解析单元测试 | 修改 |
| `api/server.go` | HTTP handler + validateChatRequest | 修改 |
| `api/server_test.go` | HTTP handler 测试 | 修改 |
| `proxy/tool_registry.go` | 空工具注册表 | 新增 |
| `proxy/message_ir.go` | Message IR 转换工具函数 | 新增 |

---

### Task 1: 扩展 proxy/types.go — 工具调用类型定义

**Files:**
- Modify: `lingma2api/internal/proxy/types.go`

- [ ] **Step 1: 添加 ToolCall, FunctionCall, Tool, ToolFunction 类型**

在 `Message` 结构体定义之前（约第22行）插入：

```go
// ToolCall represents an OpenAI-compatible tool call from an assistant message.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall holds the function name and JSON-encoded arguments.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Tool is an OpenAI-compatible tool definition passed in a chat request.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction describes a tool's function schema.
type ToolFunction struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
}
```

- [ ] **Step 2: 扩展 Message 结构体**

把现有的 Message 结构体（约第22行）：

```go
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
```

替换为：

```go
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	Name       string     `json:"name,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}
```

- [ ] **Step 3: 扩展 OpenAIChatRequest 结构体**

把现有的 OpenAIChatRequest 结构体（约第32行）：

```go
type OpenAIChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	Temperature *float64  `json:"temperature,omitempty"`
	ExtraBody   ExtraBody `json:"extra_body,omitempty"`
}
```

替换为：

```go
type OpenAIChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	Temperature *float64  `json:"temperature,omitempty"`
	ExtraBody   ExtraBody `json:"extra_body,omitempty"`
	Tools       []Tool    `json:"tools,omitempty"`
	ToolChoice  any       `json:"tool_choice,omitempty"`
}
```

- [ ] **Step 4: 运行现有测试确认无回归**

```bash
cd lingma2api && go test ./internal/proxy/ ./internal/api/ -v
```

预期：全部 PASS（新增字段带 `omitempty`，不影响现有序列化/反序列化）

- [ ] **Step 5: Commit**

```bash
git add lingma2api/internal/proxy/types.go
git commit -m "feat(proxy): add ToolCall, Tool, and tool-related fields to Message and OpenAIChatRequest"
```

---

### Task 2: 编写 body_test.go 工具调用序列化测试

**Files:**
- Modify: `lingma2api/internal/proxy/body_test.go`

- [ ] **Step 1: 添加 tool_calls 透传测试**

在 `body_test.go` 末尾追加：

```go
func TestBodyBuilderPreservesToolCallsInMessages(t *testing.T) {
	builder := NewBodyBuilder("2.11.2", func() time.Time { return time.UnixMilli(10) }, func() string {
		return "uuid-1"
	}, func() string {
		return "hex-1"
	})

	messages := []Message{
		{Role: "user", Content: "read main.go"},
		{
			Role:    "assistant",
			Content: "",
			ToolCalls: []ToolCall{{
				ID:   "c1",
				Type: "function",
				Function: FunctionCall{
					Name:      "read_file",
					Arguments: `{"path":"main.go"}`,
				},
			}},
		},
		{
			Role:       "tool",
			Content:    "package main\nfunc main() {}",
			ToolCallID: "c1",
		},
	}

	request, err := builder.Build(OpenAIChatRequest{
		Model:    "auto",
		Messages: messages,
		Stream:   true,
	}, messages, "")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(request.BodyJSON), &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	msgs, ok := payload["messages"].([]any)
	if !ok || len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %#v", payload["messages"])
	}

	// Check assistant message has tool_calls
	assistant, ok := msgs[1].(map[string]any)
	if !ok {
		t.Fatal("assistant message not a map")
	}
	toolCalls, ok := assistant["tool_calls"].([]any)
	if !ok || len(toolCalls) != 1 {
		t.Fatalf("expected 1 tool_call in assistant message, got %#v", assistant["tool_calls"])
	}
	tc := toolCalls[0].(map[string]any)
	if tc["id"] != "c1" {
		t.Fatalf("expected tool_call id c1, got %q", tc["id"])
	}

	// Check tool message has tool_call_id
	toolMsg, ok := msgs[2].(map[string]any)
	if !ok {
		t.Fatal("tool message not a map")
	}
	toolCallID, ok := toolMsg["tool_call_id"].(string)
	if !ok || toolCallID != "c1" {
		t.Fatalf("expected tool_call_id c1, got %#v", toolMsg["tool_call_id"])
	}
}
```

- [ ] **Step 2: 运行测试确认失败（缺少序列化逻辑）**

```bash
cd lingma2api && go test ./internal/proxy/ -run TestBodyBuilderPreservesToolCallsInMessages -v
```

预期：FAIL（tool_calls/tool_call_id 未被序列化）

- [ ] **Step 3: Commit**

```bash
git add lingma2api/internal/proxy/body_test.go
git commit -m "test(proxy): add tool_calls serialization test for BodyBuilder"
```

---

### Task 3: 修改 proxy/body.go — 透传 tool_calls

**Files:**
- Modify: `lingma2api/internal/proxy/body.go:44-59`

- [ ] **Step 1: 修改消息序列化循环**

把 `body.go` 第44-59行的消息序列化：

```go
serializedMessages := make([]map[string]any, 0, len(messages))
for _, message := range messages {
    serializedMessages = append(serializedMessages, map[string]any{
        "role":    message.Role,
        "content": message.Content,
        "response_meta": map[string]any{
            "id": "",
            "usage": map[string]int{
                "prompt_tokens":     0,
                "completion_tokens": 0,
                "total_tokens":      0,
            },
        },
        "reasoning_content_signature": "",
    })
}
```

替换为：

```go
serializedMessages := make([]map[string]any, 0, len(messages))
for _, message := range messages {
    m := map[string]any{
        "role":    message.Role,
        "content": message.Content,
        "response_meta": map[string]any{
            "id": "",
            "usage": map[string]int{
                "prompt_tokens":     0,
                "completion_tokens": 0,
                "total_tokens":      0,
            },
        },
        "reasoning_content_signature": "",
    }
    if message.Name != "" {
        m["name"] = message.Name
    }
    if message.ToolCallID != "" {
        m["tool_call_id"] = message.ToolCallID
    }
    if len(message.ToolCalls) > 0 {
        m["tool_calls"] = message.ToolCalls
    }
    serializedMessages = append(serializedMessages, m)
}
```

- [ ] **Step 2: 添加 tools 和 tool_choice 到 body payload**

在 body.go 的 `payload` map (第61-109行) 中，`"messages": serializedMessages,` 这行之后，添加：

```go
if len(request.Tools) > 0 {
    payload["tools"] = request.Tools
}
if request.ToolChoice != nil {
    payload["tool_choice"] = request.ToolChoice
}
```

- [ ] **Step 3: 运行测试确认通过**

```bash
cd lingma2api && go test ./internal/proxy/ -run TestBodyBuilder -v
```

预期：全部 PASS（TestBodyBuilderBuildsRemoteRequest + TestBodyBuilderPreservesToolCallsInMessages）

- [ ] **Step 4: Commit**

```bash
git add lingma2api/internal/proxy/body.go
git commit -m "feat(proxy): serialize tool_calls, tool_call_id, name in message body"
```

---

### Task 4: 编写 sse_test.go tool_calls 解析测试

**Files:**
- Modify: `lingma2api/internal/proxy/sse_test.go`

- [ ] **Step 1: 添加 tool_calls delta 解析测试**

在 `sse_test.go` 末尾追加：

```go
func TestParseSSELineExtractsToolCallDelta(t *testing.T) {
	line := `data:{"body":"{\"choices\":[{\"delta\":{\"content\":\"\",\"tool_calls\":[{\"index\":0,\"id\":\"c2\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"main.go\\\"}\"}}]}}]}","statusCodeValue":200}`

	event, ok, err := ParseSSELine(line)
	if err != nil {
		t.Fatalf("ParseSSELine() error = %v", err)
	}
	if !ok {
		t.Fatal("expected line to be parsed")
	}
	if len(event.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool_call, got %d", len(event.ToolCalls))
	}
	tc := event.ToolCalls[0]
	if tc.ID != "c2" {
		t.Fatalf("expected tool_call id c2, got %q", tc.ID)
	}
	if tc.Function.Name != "read_file" {
		t.Fatalf("expected function name read_file, got %q", tc.Function.Name)
	}
	if tc.Function.Arguments != `{"path":"main.go"}` {
		t.Fatalf("expected arguments, got %q", tc.Function.Arguments)
	}
}

func TestParseSSELineMergesToolCallFragmentArguments(t *testing.T) {
	// Simulate incremental tool call delivery across two SSE lines
	line1 := `data:{"body":"{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c3\",\"type\":\"function\",\"function\":{\"name\":\"search\",\"arguments\":\"{\\\"q\\\":\"}}]}}]}","statusCodeValue":200}`
	line2 := `data:{"body":"{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"hello\\\"}\"}}]}}]}","statusCodeValue":200}`

	event1, ok1, _ := ParseSSELine(line1)
	event2, ok2, _ := ParseSSELine(line2)

	if !ok1 || !ok2 {
		t.Fatal("expected both lines to parse")
	}
	if len(event1.ToolCalls) != 1 {
		t.Fatalf("line1: expected 1 tool_call, got %d", len(event1.ToolCalls))
	}
	// Arguments fragments should be present individually
	if event1.ToolCalls[0].Function.Arguments != `{"q":"` {
		t.Fatalf("line1: expected partial arguments, got %q", event1.ToolCalls[0].Function.Arguments)
	}
	if event2.ToolCalls[0].Function.Arguments != `hello"}` {
		t.Fatalf("line2: expected fragment arguments, got %q", event2.ToolCalls[0].Function.Arguments)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd lingma2api && go test ./internal/proxy/ -run TestParseSSELineExtractsToolCallDelta -v
```

预期：FAIL（ParseSSELine 未解析 tool_calls）

- [ ] **Step 3: Commit**

```bash
git add lingma2api/internal/proxy/sse_test.go
git commit -m "test(proxy): add tool_calls delta parsing tests for SSE"
```

---

### Task 5: 修改 proxy/sse.go — 解析 tool_calls delta

**Files:**
- Modify: `lingma2api/internal/proxy/sse.go`
- Modify: `lingma2api/internal/proxy/types.go` (给 SSEEvent 加 ToolCalls 字段)

- [ ] **Step 1: 扩展 SSEEvent 结构体**

在 `types.go` 中，把 SSEEvent（约第119行）：

```go
type SSEEvent struct {
	Content string
	Done    bool
}
```

替换为：

```go
type SSEEvent struct {
	Content   string
	ToolCalls []ToolCall
	Done      bool
}
```

- [ ] **Step 2: 扩展 innerSSEPayload 和新增类型**

在 `sse.go` 中，把 `innerSSEPayload`（约第16-22行）：

```go
type innerSSEPayload struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}
```

替换为：

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

type functionCallDelta struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}
```

- [ ] **Step 3: 修改 ParseSSELine 函数，填充 ToolCalls**

把 `ParseSSELine` 的结尾部分（当前约第53-58行，inner 解析后的逻辑）：

```go
var builder strings.Builder
for _, choice := range inner.Choices {
    builder.WriteString(choice.Delta.Content)
}
return SSEEvent{Content: builder.String()}, true, nil
```

替换为：

```go
var builder strings.Builder
for _, choice := range inner.Choices {
    builder.WriteString(choice.Delta.Content)
}
var toolCalls []ToolCall
for _, choice := range inner.Choices {
    for _, tc := range choice.Delta.ToolCalls {
        toolCalls = append(toolCalls, ToolCall{
            ID:   tc.ID,
            Type: tc.Type,
            Function: FunctionCall{
                Name:      tc.Function.Name,
                Arguments: tc.Function.Arguments,
            },
        })
    }
}
return SSEEvent{Content: builder.String(), ToolCalls: toolCalls}, true, nil
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd lingma2api && go test ./internal/proxy/ -run TestParseSSE -v
```

预期：全部 PASS

- [ ] **Step 5: Commit**

```bash
git add lingma2api/internal/proxy/sse.go lingma2api/internal/proxy/types.go
git commit -m "feat(proxy): parse tool_calls delta from Lingma SSE response"
```

---

### Task 6: 扩展 api/server.go — tool 消息校验和 SSE 工具调用输出

**Files:**
- Modify: `lingma2api/internal/api/server.go`

- [ ] **Step 1: 扩展 validateChatRequest — 添加 tool 角色和 tool_calls 校验**

在 `validateChatRequest` 函数（约第394行）中，现有的 for 循环：

```go
for _, message := range request.Messages {
    if message.Content == "" {
        return errors.New("message content must not be empty")
    }
    switch message.Role {
    case "system", "user", "assistant":
    default:
        return fmt.Errorf("unsupported role %q", message.Role)
    }
}
```

替换为：

```go
for _, message := range request.Messages {
    switch message.Role {
    case "system", "user":
        if message.Content == "" {
            return errors.New("message content must not be empty")
        }
    case "assistant":
        // assistant may have empty content when it contains tool_calls
        if message.Content == "" && len(message.ToolCalls) == 0 {
            return errors.New("assistant message must have content or tool_calls")
        }
        for _, tc := range message.ToolCalls {
            if tc.Function.Name == "" {
                return errors.New("tool_call function name must not be empty")
            }
        }
    case "tool":
        if message.ToolCallID == "" {
            return errors.New("tool message must have tool_call_id")
        }
    default:
        return fmt.Errorf("unsupported role %q", message.Role)
    }
}
```

- [ ] **Step 2: 扩展 streamChatResponse — 输出 tool_calls 到 SSE chunk**

在 `streamChatResponse` 函数（第214行）中，`ScanSSE` 的回调里，把现有的写 delta content 的逻辑（约第248-267行）：

```go
err := proxy.ScanSSE(stream, func(event proxy.SSEEvent) error {
    if event.Done || event.Content == "" {
        return nil
    }
    contentBuilder.WriteString(event.Content)
    if err := writeSSEChunk(writer, chatCompletionResponse{
        ID:      responseID,
        Object:  "chat.completion.chunk",
        Created: server.deps.Now().Unix(),
        Model:   chatRequest.Model,
        Choices: []chatCompletionChoice{{
            Index: 0,
            Delta:  &deltaPayload{Content: event.Content},
        }},
    }); err != nil {
        return err
    }
    flusher.Flush()
    return nil
})
```

替换为：

```go
err := proxy.ScanSSE(stream, func(event proxy.SSEEvent) error {
    if event.Done {
        return nil
    }
    if event.Content == "" && len(event.ToolCalls) == 0 {
        return nil
    }
    if event.Content != "" {
        contentBuilder.WriteString(event.Content)
    }
    choice := chatCompletionChoice{Index: 0}
    if len(event.ToolCalls) > 0 {
        choice.Delta = &deltaPayload{
            Role:      "assistant",
            ToolCalls: event.ToolCalls,
        }
    } else {
        choice.Delta = &deltaPayload{Content: event.Content}
    }
    if err := writeSSEChunk(writer, chatCompletionResponse{
        ID:      responseID,
        Object:  "chat.completion.chunk",
        Created: server.deps.Now().Unix(),
        Model:   chatRequest.Model,
        Choices: []chatCompletionChoice{choice},
    }); err != nil {
        return err
    }
    flusher.Flush()
    return nil
})
```

- [ ] **Step 3: 扩展 deltaPayload — 添加 tool_calls 字段**

在 `server.go` 中，把 `deltaPayload`（约第74-77行）：

```go
type deltaPayload struct {
    Role    string `json:"role,omitempty"`
    Content string `json:"content,omitempty"`
}
```

替换为：

```go
type deltaPayload struct {
    Role      string           `json:"role,omitempty"`
    Content   string           `json:"content,omitempty"`
    ToolCalls []proxy.ToolCall `json:"tool_calls,omitempty"`
}
```

- [ ] **Step 4: 扩展 chatCompletionChoice — 添加 tool_calls 字段（非流式）**

在 `server.go` 中，把 `chatCompletionChoice`（约第67-72行）：

```go
type chatCompletionChoice struct {
    Index        int            `json:"index"`
    Message      *proxy.Message `json:"message,omitempty"`
    Delta        *deltaPayload  `json:"delta,omitempty"`
    FinishReason *string        `json:"finish_reason"`
}
```

替换为：

```go
type chatCompletionChoice struct {
    Index        int              `json:"index"`
    Message      *proxy.Message   `json:"message,omitempty"`
    Delta        *deltaPayload    `json:"delta,omitempty"`
    FinishReason *string          `json:"finish_reason"`
    ToolCalls    []proxy.ToolCall `json:"tool_calls,omitempty"`
}
```

- [ ] **Step 5: 运行所有测试**

```bash
cd lingma2api && go test ./... -v
```

预期：全部 PASS

- [ ] **Step 6: Commit**

```bash
git add lingma2api/internal/api/server.go
git commit -m "feat(api): add tool role validation and tool_calls SSE output"
```

---

### Task 7: 编写 api/server_test.go tool 校验测试

**Files:**
- Modify: `lingma2api/internal/api/server_test.go`

- [ ] **Step 1: 添加 tool 角色校验测试**

在 `server_test.go` 末尾追加：

```go
func TestChatCompletionsRejectsToolMessageWithoutToolCallID(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport:   fakeTransport{},
		Builder:     fakeBuilder{},
	})

	body := `{"model":"auto","messages":[{"role":"tool","content":"result"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for tool message without tool_call_id, got %d", recorder.Code)
	}
}

func TestChatCompletionsAllowsAssistantWithToolCalls(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport: fakeTransport{
			lines: []string{`data:{"body":"{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}","statusCodeValue":200}`, `data:[DONE]`},
		},
		Builder: fakeBuilder{},
		Now:     func() time.Time { return time.Unix(1, 0) },
	})

	body := `{"model":"auto","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{}"}}]},{"role":"tool","content":"result","tool_call_id":"c1"}],"stream":false}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid tool message chain, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestChatCompletionsRejectsToolCallWithoutFunctionName(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport:   fakeTransport{},
		Builder:     fakeBuilder{},
	})

	body := `{"model":"auto","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"","arguments":"{}"}}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for tool_call without function name, got %d", recorder.Code)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd lingma2api && go test ./internal/api/ -run TestChatCompletionsRejectsToolMessageWithoutToolCallID -v
```

预期：FAIL（400 vs 200 — 新校验未生效）

- [ ] **Step 3: Commit**

```bash
git add lingma2api/internal/api/server_test.go
git commit -m "test(api): add tool message validation tests"
```

---

### Task 8: 创建 proxy/tool_registry.go — 空工具注册表

**Files:**
- Create: `lingma2api/internal/proxy/tool_registry.go`

- [ ] **Step 1: 创建 tool_registry.go**

```go
package proxy

// ToolRegistry holds known Lingma built-in tools.
// Phase 1: empty — all tools are transparently passed through.
// Phase 3: populated with reverse-engineered Lingma IDE tools.
type ToolRegistry struct {
	tools map[string]ToolDefinition
}

// ToolDefinition describes a Lingma built-in tool available for mapping.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// NewToolRegistry creates an empty tool registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools: make(map[string]ToolDefinition),
	}
}

// Lookup returns the tool definition by name, or nil if not registered.
func (r *ToolRegistry) Lookup(name string) (*ToolDefinition, bool) {
	def, ok := r.tools[name]
	return &def, ok
}

// Register adds a tool definition to the registry.
func (r *ToolRegistry) Register(def ToolDefinition) {
	r.tools[def.Name] = def
}

// List returns all registered tool definitions.
func (r *ToolRegistry) List() []ToolDefinition {
	defs := make([]ToolDefinition, 0, len(r.tools))
	for _, def := range r.tools {
		defs = append(defs, def)
	}
	return defs
}
```

- [ ] **Step 2: 运行编译检查**

```bash
cd lingma2api && go build ./...
```

- [ ] **Step 3: Commit**

```bash
git add lingma2api/internal/proxy/tool_registry.go
git commit -m "feat(proxy): add empty ToolRegistry placeholder for future built-in tools"
```

---

### Task 9: 创建 proxy/message_ir.go — Message IR 转换工具

**Files:**
- Create: `lingma2api/internal/proxy/message_ir.go`

- [ ] **Step 1: 创建 message_ir.go**

```go
package proxy

// ConvertMessagesToIR normalizes incoming messages for downstream processing.
// Phase 1: identity pass-through (OpenAI messages are already in IR format).
// Phase 3: adds Anthropic content-block ↔ OpenAI IR conversion.
func ConvertMessagesToIR(messages []Message) []Message {
	return messages
}

// ConvertIRToMessages converts IR messages back to the target format.
// Phase 1: identity pass-through.
// Phase 3: adds OpenAI IR ↔ Anthropic content-block conversion.
func ConvertIRToMessages(ir []Message) []Message {
	return ir
}

// HasToolCalls returns true if any message in the slice contains tool_calls.
func HasToolCalls(messages []Message) bool {
	for _, m := range messages {
		if len(m.ToolCalls) > 0 {
			return true
		}
	}
	return false
}

// LastAssistantToolCalls returns the tool_calls from the most recent assistant message, if any.
func LastAssistantToolCalls(messages []Message) []ToolCall {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "assistant" && len(messages[i].ToolCalls) > 0 {
			return messages[i].ToolCalls
		}
	}
	return nil
}
```

- [ ] **Step 2: 运行编译检查**

```bash
cd lingma2api && go build ./...
```

- [ ] **Step 3: Commit**

```bash
git add lingma2api/internal/proxy/message_ir.go
git commit -m "feat(proxy): add Message IR conversion utilities (Phase 1 passthrough)"
```

---

### Task 10: 端到端集成测试 — 完整工具调用流

**Files:**
- Modify: `lingma2api/internal/api/server_test.go`

- [ ] **Step 1: 添加流式工具调用 SSE 输出测试**

在 `server_test.go` 末尾追加：

```go
func TestChatCompletionsStreamWithToolCalls(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport: fakeTransport{
			lines: []string{
				`data:{"body":"{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c2\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"\"}}]}}]}","statusCodeValue":200}`,
				`data:{"body":"{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"main.go\\\"}\"}}]}}]}","statusCodeValue":200}`,
				`data:[DONE]`,
			},
		},
		Builder: fakeBuilder{},
		Now:     func() time.Time { return time.Unix(1, 0) },
	})

	body := `{"model":"auto","messages":[{"role":"user","content":"read main.go"}],"stream":true}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	responseBody := recorder.Body.String()
	if !strings.Contains(responseBody, `"tool_calls"`) {
		t.Fatalf("expected tool_calls in SSE response, got: %s", responseBody)
	}
	if !strings.Contains(responseBody, `"read_file"`) {
		t.Fatalf("expected read_file function name, got: %s", responseBody)
	}
}

func TestChatCompletionsStreamWithContentOnlyNoToolCalls(t *testing.T) {
	// Sanity check: normal content-only SSE still works after tool_calls changes
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport: fakeTransport{
			lines: []string{
				`data:{"body":"{\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}","statusCodeValue":200}`,
				`data:{"body":"{\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}","statusCodeValue":200}`,
				`data:[DONE]`,
			},
		},
		Builder: fakeBuilder{},
		Now:     func() time.Time { return time.Unix(1, 0) },
	})

	body := `{"model":"auto","messages":[{"role":"user","content":"hi"}],"stream":true}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"content":"Hel"`) {
		t.Fatalf("expected content in SSE, got: %s", recorder.Body.String())
	}
	// Should NOT emit tool_calls for content-only response
	if strings.Contains(recorder.Body.String(), `"tool_calls"`) {
		t.Fatalf("unexpected tool_calls in content-only response: %s", recorder.Body.String())
	}
}
```

- [ ] **Step 2: 运行全部测试**

```bash
cd lingma2api && go test ./... -v
```

预期：全部 PASS（10+ 测试）

- [ ] **Step 3: Commit**

```bash
git add lingma2api/internal/api/server_test.go
git commit -m "test(api): add end-to-end streaming tool_calls integration tests"
```

---

### Task 11: 手动验证 — 用 curl 发真实请求测试

- [ ] **Step 1: 构建并启动 lingma2api**

```bash
cd lingma2api && go build -o lingma2api.exe . && ./lingma2api.exe
```

- [ ] **Step 2: 发送普通内容请求，确认无回归**

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"say hi"}],"stream":false}' | jq .
```

预期：`{"choices":[{"message":{"role":"assistant","content":"..."}}]}` — content 正常返回

- [ ] **Step 3: 发送带 tools 定义的请求**

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"read main.go"}],"tools":[{"type":"function","function":{"name":"read_file","description":"Read a file","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}}],"stream":false}' | jq .
```

预期：200 OK（无论 Lingma 是否实际支持 tools，请求格式应正确透传）

- [ ] **Step 4: 发送带 tool_calls 的多轮对话**

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"read main.go"},{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"main.go\"}"}}]},{"role":"tool","content":"package main\nfunc main() {}","tool_call_id":"c1"},{"role":"user","content":"what does this file do?"}],"stream":false}' | jq .
```

预期：200 OK（tool 消息被正确校验和序列化）

---

## 自审清单

**1. Spec 覆盖检查：**
- ✅ 消息格式扩展 → Task 1 (types.go)
- ✅ Body 序列化透传 → Task 3 (body.go)
- ✅ SSE 解析 tool_calls → Task 5 (sse.go)
- ✅ 校验规则 → Task 6 (server.go validateChatRequest)
- ✅ 工具注册表空壳 → Task 8 (tool_registry.go)
- ✅ Message IR → Task 9 (message_ir.go)
- ✅ 流式 SSE 输出 → Task 6 (streamChatResponse)
- ✅ 非流式输出 → 已有的 writeNonStreamResponse 继续工作

**2. Placeholder 扫描：** 无 TBD/TODO/placeholder

**3. 类型一致性：**
- `ToolCall` 定义在 Task 1 types.go，在 Task 5 sse.go、Task 6 server.go、Task 9 message_ir.go 中使用 — 一致
- `SSEEvent.ToolCalls` 在 Task 5 types.go 添加，在 Task 6 server.go 使用 — 一致
- `deltaPayload.ToolCalls` 在 Task 6 server.go 添加 — 正确

**4. 文件完整性：**
- 每个修改/新增的文件都有对应的 Task
- 测试在实现之前编写 (TDD)
- 每个 Task 最后一步是 commit
