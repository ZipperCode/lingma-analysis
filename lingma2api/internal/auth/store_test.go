package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"lingma2api/internal/proxy"
)

func TestSaveCredentialFileWritesJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	payload := proxy.StoredCredentialFile{
		SchemaVersion: 1,
		Source:        "project_bootstrap",
		Auth: proxy.StoredAuthFields{
			CosyKey:         "k",
			EncryptUserInfo: "info",
			UserID:          "u",
			MachineID:       "m",
		},
	}

	if err := SaveCredentialFile(path, payload); err != nil {
		t.Fatalf("SaveCredentialFile() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var got proxy.StoredCredentialFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Source != "project_bootstrap" {
		t.Fatalf("expected source project_bootstrap, got %q", got.Source)
	}
}
