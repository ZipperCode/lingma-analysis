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
