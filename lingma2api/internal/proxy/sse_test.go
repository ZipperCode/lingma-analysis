package proxy

import "testing"

func TestParseSSELineExtractsDeltaContent(t *testing.T) {
	line := `data:{"body":"{\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}","statusCodeValue":200}`
	event, ok, err := ParseSSELine(line)
	if err != nil {
		t.Fatalf("ParseSSELine() error = %v", err)
	}
	if !ok {
		t.Fatal("expected line to be parsed")
	}
	if event.Content != "Hi" {
		t.Fatalf("expected content Hi, got %q", event.Content)
	}
}

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
	if tc.Index != 0 {
		t.Fatalf("expected tool_call index 0, got %d", tc.Index)
	}
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
	if event1.ToolCalls[0].Index != 0 {
		t.Fatalf("line1: expected tool_call index 0, got %d", event1.ToolCalls[0].Index)
	}
	// Arguments fragments should be present individually
	arg1 := event1.ToolCalls[0].Function.Arguments
	if len(arg1) == 0 {
		t.Fatal("line1: expected non-empty arguments fragment")
	}
	if event2.ToolCalls[0].Index != 0 {
		t.Fatalf("line2: expected tool_call index 0, got %d", event2.ToolCalls[0].Index)
	}
	arg2 := event2.ToolCalls[0].Function.Arguments
	if len(arg2) == 0 {
		t.Fatal("line2: expected non-empty arguments fragment")
	}
}
