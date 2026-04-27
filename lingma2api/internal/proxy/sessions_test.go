package proxy

import (
	"context"
	"testing"
	"time"
)

func TestSessionStoreUsesIncomingFullHistoryAsAuthority(t *testing.T) {
	now := time.Unix(10, 0)
	store := NewSessionStore(30*time.Minute, 100, func() time.Time { return now })
	first := []Message{{Role: "user", Content: "hi"}}
	second := []Message{
		{Role: "user", Content: "hi"},
		{Role: "assistant", Content: "hello"},
		{Role: "user", Content: "again"},
	}

	merged, err := store.BuildMessages(context.Background(), "s1", first)
	if err != nil {
		t.Fatalf("BuildMessages() error = %v", err)
	}
	if err := store.SaveResponse(context.Background(), "s1", merged, Message{Role: "assistant", Content: "hello"}); err != nil {
		t.Fatalf("SaveResponse() error = %v", err)
	}

	merged, err = store.BuildMessages(context.Background(), "s1", second)
	if err != nil {
		t.Fatalf("BuildMessages() error = %v", err)
	}
	if len(merged) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(merged))
	}
}
