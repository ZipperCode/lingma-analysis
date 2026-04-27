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
