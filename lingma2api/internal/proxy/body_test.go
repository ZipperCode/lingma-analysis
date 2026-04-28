package proxy

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBodyBuilderBuildsRemoteRequest(t *testing.T) {
	temperature := 0.2
	builder := NewBodyBuilder("2.11.2", func() time.Time { return time.UnixMilli(10) }, func() string {
		return "uuid-1"
	}, func() string {
		return "hex-1"
	})

	request, err := builder.Build(OpenAIChatRequest{
		Model:       "auto",
		Messages:    []Message{{Role: "user", Content: "hi"}},
		Stream:      true,
		Temperature: &temperature,
	}, []Message{{Role: "user", Content: "hi"}}, "")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if request.Path != ChatPath {
		t.Fatalf("expected chat path, got %q", request.Path)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(request.BodyJSON), &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if payload["request_id"] != "hex-1" {
		t.Fatalf("expected fixed request_id, got %#v", payload["request_id"])
	}
}

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
