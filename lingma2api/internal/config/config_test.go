package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigOverridesDefaults(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`
server:
  host: "0.0.0.0"
  port: 9090
credential:
  auth_file: "./auth/credentials.json"
session:
  ttl_minutes: 5
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Fatalf("expected host override, got %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 9090 {
		t.Fatalf("expected port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Session.TTLMinutes != 5 {
		t.Fatalf("expected ttl 5, got %d", cfg.Session.TTLMinutes)
	}
	if cfg.Credential.AuthFile != "./auth/credentials.json" {
		t.Fatalf("expected auth file override, got %q", cfg.Credential.AuthFile)
	}
}
