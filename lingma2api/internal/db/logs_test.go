package db

import (
	"context"
	"os"
	"testing"
	"time"
)

func tempStore(t *testing.T) (*Store, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "lingma2api-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	store, err := Open(f.Name())
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}
	if err := store.Migrate(); err != nil {
		store.Close()
		os.Remove(f.Name())
		t.Fatal(err)
	}
	return store, func() {
		store.Close()
		os.Remove(f.Name())
	}
}

func TestInsertAndGetLog(t *testing.T) {
	store, cleanup := tempStore(t)
	defer cleanup()

	ctx := context.Background()
	log := &RequestLog{
		ID: "test-1", CreatedAt: time.Now(), Model: "gpt-4o", MappedModel: "lingma-gpt4",
		Status: "success", DownstreamMethod: "POST", DownstreamPath: "/v1/chat/completions",
		DownstreamReq: `{}`, DownstreamResp: `{}`, UpstreamReq: `{}`, UpstreamResp: `{}`,
		UpstreamStatus: 200, PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150,
		TTFTMs: 200, UpstreamMs: 1500, DownstreamMs: 1600,
	}
	if err := store.InsertLog(ctx, log); err != nil {
		t.Fatalf("InsertLog: %v", err)
	}

	got, err := store.GetLog(ctx, "test-1")
	if err != nil {
		t.Fatalf("GetLog: %v", err)
	}
	if got.Model != "gpt-4o" || got.PromptTokens != 100 {
		t.Fatalf("unexpected: model=%s prompt=%d", got.Model, got.PromptTokens)
	}
}

func TestListLogsWithFilter(t *testing.T) {
	store, cleanup := tempStore(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()
	store.InsertLog(ctx, &RequestLog{ID: "a", CreatedAt: now.Add(-time.Hour), Model: "m1", Status: "success",
		DownstreamMethod: "POST", DownstreamPath: "/", DownstreamReq: `{}`, DownstreamResp: `{}`,
		UpstreamReq: `{}`, UpstreamResp: `{}`})
	store.InsertLog(ctx, &RequestLog{ID: "b", CreatedAt: now, Model: "m2", Status: "error",
		DownstreamMethod: "POST", DownstreamPath: "/", DownstreamReq: `{}`, DownstreamResp: `{}`,
		UpstreamReq: `{}`, UpstreamResp: `{}`})

	result, err := store.ListLogs(ctx, LogFilter{Status: "error"}, 1, 10)
	if err != nil {
		t.Fatalf("ListLogs: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected 1 error log, got %d", result.Total)
	}
	if result.Items[0].ID != "b" {
		t.Fatalf("expected log b, got %s", result.Items[0].ID)
	}
}

func TestCleanupExpiredLogs(t *testing.T) {
	store, cleanup := tempStore(t)
	defer cleanup()

	ctx := context.Background()
	old := time.Now().AddDate(0, 0, -60)
	store.InsertLog(ctx, &RequestLog{ID: "old", CreatedAt: old, Model: "m", Status: "ok",
		DownstreamMethod: "POST", DownstreamPath: "/", DownstreamReq: `{}`, DownstreamResp: `{}`,
		UpstreamReq: `{}`, UpstreamResp: `{}`})
	store.InsertLog(ctx, &RequestLog{ID: "new", CreatedAt: time.Now(), Model: "m", Status: "ok",
		DownstreamMethod: "POST", DownstreamPath: "/", DownstreamReq: `{}`, DownstreamResp: `{}`,
		UpstreamReq: `{}`, UpstreamResp: `{}`})

	affected, err := store.CleanupExpiredLogs(ctx, 30)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if affected != 1 {
		t.Fatalf("expected 1 deleted, got %d", affected)
	}
	result, _ := store.ListLogs(ctx, LogFilter{}, 1, 10)
	if result.Total != 1 || result.Items[0].ID != "new" {
		t.Fatalf("expected only new log remaining")
	}
}
