package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestImportCredentialFileFromLingmaDir(t *testing.T) {
	machineID := "43303747-3630-492d-8151-366d4e59432d"
	payload := map[string]any{
		"key":                  "sentinel-key",
		"encrypt_user_info":    "sentinel-info",
		"uid":                  "u-123",
		"security_oauth_token": "pt-123",
		"refresh_token":        "rt-123",
		"expire_time":          "1782449727519",
	}

	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(cache) error = %v", err)
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(logs) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "lingma.log"), []byte("INFO using machine id from file: "+machineID+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(log) error = %v", err)
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	encrypted := encryptForImportTest(t, raw, machineID[:16])
	if err := os.WriteFile(filepath.Join(cacheDir, "user"), []byte(base64.StdEncoding.EncodeToString(encrypted)), 0o644); err != nil {
		t.Fatalf("WriteFile(user) error = %v", err)
	}

	got, err := ImportCredentialFileFromLingmaDir(dir, time.Date(2026, 4, 27, 13, 10, 0, 0, time.FixedZone("CST", 8*3600)))
	if err != nil {
		t.Fatalf("ImportCredentialFileFromLingmaDir() error = %v", err)
	}

	if got.Auth.CosyKey != "sentinel-key" {
		t.Fatalf("expected cosy key, got %q", got.Auth.CosyKey)
	}
	if got.Auth.EncryptUserInfo != "sentinel-info" {
		t.Fatalf("expected encrypt_user_info, got %q", got.Auth.EncryptUserInfo)
	}
	if got.OAuth.AccessToken != "pt-123" {
		t.Fatalf("expected access token, got %q", got.OAuth.AccessToken)
	}
	if got.Auth.MachineID != machineID {
		t.Fatalf("expected machine id, got %q", got.Auth.MachineID)
	}
}

func encryptForImportTest(t *testing.T, data []byte, key string) []byte {
	t.Helper()

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padded := append(append([]byte{}, data...), bytesRepeat(byte(padding), padding)...)
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, []byte(key)).CryptBlocks(encrypted, padded)
	return encrypted
}

func bytesRepeat(value byte, count int) []byte {
	data := make([]byte, count)
	for index := range data {
		data[index] = value
	}
	return data
}
