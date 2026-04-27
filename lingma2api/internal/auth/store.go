package auth

import (
	"encoding/json"
	"os"
	"path/filepath"

	"lingma2api/internal/proxy"
)

func SaveCredentialFile(path string, payload proxy.StoredCredentialFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}
