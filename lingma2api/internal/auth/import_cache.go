package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lingma2api/internal/proxy"
)

type cacheUserPayload struct {
	Key                string `json:"key"`
	EncryptUserInfo    string `json:"encrypt_user_info"`
	UserID             string `json:"uid"`
	SecurityOAuthToken string `json:"security_oauth_token"`
	RefreshToken       string `json:"refresh_token"`
	ExpireTime         any    `json:"expire_time"`
}

// TryImportFromLingmaCache attempts to auto-detect and import credentials from
// the standard ~/.lingma directory. Returns the imported credentials on success.
func TryImportFromLingmaCache(outputPath string) (proxy.StoredCredentialFile, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return proxy.StoredCredentialFile{}, fmt.Errorf("find home dir: %w", err)
	}

	lingmaDir := filepath.Join(home, ".lingma")
	if _, err := os.Stat(lingmaDir); os.IsNotExist(err) {
		return proxy.StoredCredentialFile{}, fmt.Errorf("~/.lingma not found")
	}

	// Check if cache files exist
	if _, err := os.Stat(filepath.Join(lingmaDir, "cache", "user")); os.IsNotExist(err) {
		return proxy.StoredCredentialFile{}, fmt.Errorf("~/.lingma/cache/user not found")
	}
	if _, err := os.Stat(filepath.Join(lingmaDir, "cache", "id")); os.IsNotExist(err) {
		// Try to find machine ID from logs
		logPath := filepath.Join(lingmaDir, "logs", "lingma.log")
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			return proxy.StoredCredentialFile{}, fmt.Errorf("~/.lingma/cache/id not found and no logs available")
		}
	}

	stored, err := ImportCredentialFileFromLingmaDir(lingmaDir, time.Now())
	if err != nil {
		return proxy.StoredCredentialFile{}, fmt.Errorf("import from lingma dir: %w", err)
	}

	if err := SaveCredentialFile(outputPath, stored); err != nil {
		return proxy.StoredCredentialFile{}, fmt.Errorf("save imported credentials: %w", err)
	}

	return stored, nil
}

func ImportCredentialFileFromLingmaDir(lingmaDir string, now time.Time) (proxy.StoredCredentialFile, error) {
	if lingmaDir == "" {
		return proxy.StoredCredentialFile{}, errors.New("missing lingma dir")
	}

	machineID, err := loadMachineIDForImport(lingmaDir)
	if err != nil {
		return proxy.StoredCredentialFile{}, err
	}

	encryptedData, err := os.ReadFile(filepath.Join(lingmaDir, "cache", "user"))
	if err != nil {
		return proxy.StoredCredentialFile{}, fmt.Errorf("read cache/user: %w", err)
	}

	rawCiphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encryptedData)))
	if err != nil {
		return proxy.StoredCredentialFile{}, fmt.Errorf("decode cache/user: %w", err)
	}

	plaintext, err := decryptCacheUserForImport(machineID, rawCiphertext)
	if err != nil {
		return proxy.StoredCredentialFile{}, err
	}

	var payload cacheUserPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return proxy.StoredCredentialFile{}, fmt.Errorf("parse cache/user json: %w", err)
	}

	tokenExpireTime := ""
	switch value := payload.ExpireTime.(type) {
	case string:
		tokenExpireTime = value
	case float64:
		tokenExpireTime = fmt.Sprintf("%.0f", value)
	case int64:
		tokenExpireTime = fmt.Sprintf("%d", value)
	case int:
		tokenExpireTime = fmt.Sprintf("%d", value)
	}

	timestamp := now.Format(time.RFC3339)
	return proxy.StoredCredentialFile{
		SchemaVersion:     1,
		Source:            "lingma_cache_migration",
		LingmaVersionHint: "2.11.1",
		ObtainedAt:        timestamp,
		UpdatedAt:         timestamp,
		TokenExpireTime:   tokenExpireTime,
		Auth: proxy.StoredAuthFields{
			CosyKey:         payload.Key,
			EncryptUserInfo: payload.EncryptUserInfo,
			UserID:          payload.UserID,
			MachineID:       machineID,
		},
		OAuth: proxy.StoredOAuthFields{
			AccessToken:  payload.SecurityOAuthToken,
			RefreshToken: payload.RefreshToken,
		},
	}, nil
}

func loadMachineIDForImport(lingmaDir string) (string, error) {
	idPath := filepath.Join(lingmaDir, "cache", "id")
	if machineIDBytes, err := os.ReadFile(idPath); err == nil {
		return strings.TrimSpace(string(machineIDBytes)), nil
	}

	logPath := filepath.Join(lingmaDir, "logs", "lingma.log")
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		return "", fmt.Errorf("read cache/id and lingma.log failed: %w", err)
	}

	const marker = "using machine id from file:"
	logText := string(logBytes)
	index := strings.LastIndex(logText, marker)
	if index < 0 {
		return "", errors.New("machine id not found in cache/id or log")
	}

	line := logText[index+len(marker):]
	if newline := strings.IndexByte(line, '\n'); newline >= 0 {
		line = line[:newline]
	}
	machineID := strings.TrimSpace(line)
	if machineID == "" {
		return "", errors.New("empty machine id in log")
	}
	return machineID, nil
}

func decryptCacheUserForImport(machineID string, ciphertext []byte) ([]byte, error) {
	if len(machineID) < 16 {
		return nil, errors.New("machine id too short")
	}

	key := []byte(machineID[:16])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext size")
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, key).CryptBlocks(plaintext, ciphertext)
	return unpadPKCS7ForImport(plaintext)
}

func unpadPKCS7ForImport(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty plaintext")
	}
	padLen := int(data[len(data)-1])
	if padLen <= 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, errors.New("invalid padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid padding bytes")
		}
	}
	return data[:len(data)-padLen], nil
}
