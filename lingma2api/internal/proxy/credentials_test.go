package proxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lingma2api/internal/config"
)

func TestCredentialManagerReadsProjectCredentialFile(t *testing.T) {
	path := writeCredentialFile(t, map[string]any{
		"schema_version": 1,
		"source":         "project_bootstrap",
		"obtained_at":    "2026-04-27T11:30:00+08:00",
		"updated_at":     "2026-04-27T11:30:00+08:00",
		"auth": map[string]string{
			"cosy_key":          "sentinel-key",
			"encrypt_user_info": "sentinel-info",
			"user_id":           "u-123",
			"machine_id":        "m-123",
		},
	})

	manager := NewCredentialManager(config.CredentialConfig{AuthFile: path}, func() time.Time {
		return time.Unix(1, 0)
	})
	snapshot, err := manager.Current(context.Background())
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}

	if snapshot.Source != "project_bootstrap" {
		t.Fatalf("expected project source, got %q", snapshot.Source)
	}
	if snapshot.CosyKey != "sentinel-key" {
		t.Fatalf("expected cosy key from project file, got %q", snapshot.CosyKey)
	}
	if snapshot.MachineID != "m-123" {
		t.Fatalf("expected machine id from project file, got %q", snapshot.MachineID)
	}
}

func TestCredentialManagerRejectsMissingProjectCredentialFields(t *testing.T) {
	path := writeCredentialFile(t, map[string]any{
		"schema_version": 1,
		"source":         "project_bootstrap",
		"auth": map[string]string{
			"cosy_key": "sentinel-key",
		},
	})

	manager := NewCredentialManager(config.CredentialConfig{AuthFile: path}, func() time.Time {
		return time.Unix(1, 0)
	})
	if _, err := manager.Current(context.Background()); err == nil {
		t.Fatal("expected validation error")
	}
}

func writeCredentialFile(t *testing.T, payload map[string]any) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
