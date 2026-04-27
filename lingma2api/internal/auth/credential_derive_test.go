package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecryptCacheUser_RoundTrip(t *testing.T) {
	machineID := "43303747-3630-492d-8151-366d4e59432d"
	plaintext := []byte(`{"key":"test-cosy-key","encrypt_user_info":"test-info","uid":"123","security_oauth_token":"pt-xxx","refresh_token":"rt-xxx","expire_time":1234567890}`)

	ciphertext, err := EncryptCacheUser(machineID, plaintext)
	if err != nil {
		t.Fatalf("EncryptCacheUser: %v", err)
	}

	decrypted, err := DecryptCacheUser(machineID, ciphertext)
	if err != nil {
		t.Fatalf("DecryptCacheUser: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip mismatch:\n  got: %s\n  want: %s", string(decrypted), string(plaintext))
	}
}

func TestDecryptCacheUser_ShortMachineID(t *testing.T) {
	_, err := DecryptCacheUser("short", []byte("dummy"))
	if err == nil {
		t.Fatal("expected error for short machine_id")
	}
}

func TestDecryptCacheUser_InvalidCiphertextSize(t *testing.T) {
	machineID := "43303747-3630-492d-8151-366d4e59432d"
	_, err := DecryptCacheUser(machineID, []byte("not-a-valid-size"))
	if err == nil {
		t.Fatal("expected error for invalid ciphertext size")
	}
}

func TestDecodeAndDecryptCacheUser(t *testing.T) {
	machineID := "43303747-3630-492d-8151-366d4e59432d"
	plaintext := map[string]any{
		"key":                  "test-cosy-key-value",
		"encrypt_user_info":    "test-encrypt-info-value",
		"uid":                  "5930676910898027",
		"security_oauth_token": "pt-access-token",
		"refresh_token":        "rt-refresh-token",
		"expire_time":          float64(1782451685723),
	}
	plainBytes, _ := json.Marshal(plaintext)

	ciphertext, err := EncryptCacheUser(machineID, plainBytes)
	if err != nil {
		t.Fatalf("EncryptCacheUser: %v", err)
	}

	base64Data := base64.StdEncoding.EncodeToString(ciphertext)

	result, err := DecodeAndDecryptCacheUser(machineID, base64Data)
	if err != nil {
		t.Fatalf("DecodeAndDecryptCacheUser: %v", err)
	}

	if result.Auth.CosyKey != "test-cosy-key-value" {
		t.Errorf("CosyKey: got %q, want %q", result.Auth.CosyKey, "test-cosy-key-value")
	}
	if result.Auth.EncryptUserInfo != "test-encrypt-info-value" {
		t.Errorf("EncryptUserInfo mismatch")
	}
	if result.Auth.UserID != "5930676910898027" {
		t.Errorf("UserID: got %q, want %q", result.Auth.UserID, "5930676910898027")
	}
	if result.Auth.MachineID != machineID {
		t.Errorf("MachineID: got %q, want %q", result.Auth.MachineID, machineID)
	}
	if result.OAuth.AccessToken != "pt-access-token" {
		t.Errorf("AccessToken mismatch")
	}
	if result.OAuth.RefreshToken != "rt-refresh-token" {
		t.Errorf("RefreshToken mismatch")
	}
	if result.TokenExpireTime != "1782451685723" {
		t.Errorf("TokenExpireTime: got %q, want %q", result.TokenExpireTime, "1782451685723")
	}
	if result.Source != "project_bootstrap" {
		t.Errorf("Source: got %q, want %q", result.Source, "project_bootstrap")
	}
}

func TestDecodeAndDecryptCacheUser_ExpireTimeString(t *testing.T) {
	machineID := "43303747-3630-492d-8151-366d4e59432d"
	plaintext := map[string]any{
		"key":                  "key1",
		"encrypt_user_info":    "info1",
		"uid":                  "uid1",
		"security_oauth_token": "tok1",
		"refresh_token":        "ref1",
		"expire_time":          "2026-12-31T23:59:59Z",
	}
	plainBytes, _ := json.Marshal(plaintext)
	ciphertext, _ := EncryptCacheUser(machineID, plainBytes)
	base64Data := base64.StdEncoding.EncodeToString(ciphertext)

	result, err := DecodeAndDecryptCacheUser(machineID, base64Data)
	if err != nil {
		t.Fatalf("DecodeAndDecryptCacheUser: %v", err)
	}
	if result.TokenExpireTime != "2026-12-31T23:59:59Z" {
		t.Errorf("TokenExpireTime: got %q", result.TokenExpireTime)
	}
}

func TestEncryptCacheUser_Padding(t *testing.T) {
	machineID := "43303747-3630-492d-8151-366d4e59432d"

	for _, size := range []int{1, 15, 16, 17, 31, 32, 33, 64} {
		plaintext := make([]byte, size)
		for i := range plaintext {
			plaintext[i] = byte('a' + i%26)
		}

		ciphertext, err := EncryptCacheUser(machineID, plaintext)
		if err != nil {
			t.Fatalf("EncryptCacheUser(size=%d): %v", size, err)
		}

		if len(ciphertext)%16 != 0 {
			t.Errorf("ciphertext size=%d not multiple of 16 (plaintext was %d bytes)", len(ciphertext), size)
		}

		decrypted, err := DecryptCacheUser(machineID, ciphertext)
		if err != nil {
			t.Fatalf("DecryptCacheUser(size=%d): %v", size, err)
		}
		if string(decrypted) != string(plaintext) {
			t.Errorf("round-trip mismatch for size %d", size)
		}
	}
}

func TestExtractMachineIDFromURL(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://lingma.alibabacloud.com/lingma/login?machine_id=abc-123&port=37510", "abc-123"},
		{"http://127.0.0.1:37510/profile?state=x&machine_id=def-456", "def-456"},
		{"https://example.com/no-machine-id?foo=bar", ""},
	}
	for _, tt := range tests {
		t.Run(tt.url[:min(len(tt.url), 50)], func(t *testing.T) {
			result := extractMachineIDFromLoginURL(tt.url)
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestNewMachineID_Format(t *testing.T) {
	for range 10 {
		id := NewMachineID()
		if len(id) != 36 {
			t.Errorf("expected 36 chars, got %d: %q", len(id), id)
		}
		if strings.Count(id, "-") != 4 {
			t.Errorf("expected 4 dashes, got %q", id)
		}
	}
}
