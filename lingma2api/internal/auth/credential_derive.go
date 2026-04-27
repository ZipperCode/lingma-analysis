package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"lingma2api/internal/proxy"
)

type LingmaBridgeConfig struct {
	LingmaBinary  string
	WorkDir       string
	SocketPort    int
	HTTPPort      int
	AccessToken   string
	RefreshToken  string
	UserID        string
	Username      string
	TokenExpireMs string
	StartTimeout  time.Duration
	SyncTimeout   time.Duration
}

func DefaultLingmaBinary() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home dir: %w", err)
	}

	binDir := filepath.Join(home, ".lingma", "bin")
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return "", fmt.Errorf("read lingma bin dir %s: %w", binDir, err)
	}

	for i := len(entries) - 1; i >= 0; i-- {
		if !entries[i].IsDir() {
			continue
		}
		candidate := filepath.Join(binDir, entries[i].Name(), "aarch64_darwin", "Lingma")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		candidate = filepath.Join(binDir, entries[i].Name(), "x86_64_windows", "Lingma.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		candidate = filepath.Join(binDir, entries[i].Name(), "x86_64_linux", "Lingma")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("no Lingma binary found in %s", binDir)
}

type lingmaBridge struct {
	cfg LingmaBridgeConfig
	cmd *exec.Cmd
}

func newLingmaBridge(cfg LingmaBridgeConfig) *lingmaBridge {
	if cfg.SocketPort == 0 {
		cfg.SocketPort = 37099
	}
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 37599
	}
	if cfg.StartTimeout == 0 {
		cfg.StartTimeout = 30 * time.Second
	}
	if cfg.SyncTimeout == 0 {
		cfg.SyncTimeout = 60 * time.Second
	}
	return &lingmaBridge{cfg: cfg}
}

func (b *lingmaBridge) start() error {
	if b.cfg.LingmaBinary == "" {
		return fmt.Errorf("missing lingma binary path")
	}

	workDir := b.cfg.WorkDir
	if workDir == "" {
		tmpDir, err := os.MkdirTemp("", "lingma-bootstrap-*")
		if err != nil {
			return fmt.Errorf("create temp workdir: %w", err)
		}
		workDir = tmpDir
		b.cfg.WorkDir = workDir
	}

	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("create workdir: %w", err)
	}

	args := []string{
		"start",
		fmt.Sprintf("--workDir=%s", workDir),
		fmt.Sprintf("--socketPort=%d", b.cfg.SocketPort),
		fmt.Sprintf("--httpPort=%d", b.cfg.HTTPPort),
	}

	b.cmd = exec.Command(b.cfg.LingmaBinary, args...)
	if err := b.cmd.Start(); err != nil {
		return fmt.Errorf("start lingma: %w", err)
	}

	if err := b.waitReady(); err != nil {
		b.stop()
		return err
	}
	return nil
}

func (b *lingmaBridge) waitReady() error {
	deadline := time.Now().Add(b.cfg.StartTimeout)
	wsURL := fmt.Sprintf("ws://127.0.0.1:%d", b.cfg.SocketPort)

	for time.Now().Before(deadline) {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("lingma did not become ready within %v", b.cfg.StartTimeout)
}

func (b *lingmaBridge) deviceLogin() error {
	wsURL := fmt.Sprintf("ws://127.0.0.1:%d", b.cfg.SocketPort)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("connect to lingma: %w", err)
	}
	defer conn.Close()

	if err := b.wsInitialize(conn); err != nil {
		return err
	}

	loginParams := map[string]string{
		"token":        b.cfg.AccessToken,
		"refreshToken": b.cfg.RefreshToken,
		"expiresIn":    "",
		"expireTime":   b.cfg.TokenExpireMs,
		"userId":       b.cfg.UserID,
		"username":     b.cfg.Username,
	}
	if err := wsSendMethod(conn, "auth/device_login", loginParams, 4); err != nil {
		return fmt.Errorf("device_login: %w", err)
	}

	deadline := time.Now().Add(b.cfg.SyncTimeout)
	for time.Now().Before(deadline) {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		text := string(raw)
		if strings.Contains(text, `"result"`) {
			break
		}
		if strings.Contains(text, `"error"`) {
			return fmt.Errorf("device_login error: %s", text)
		}
	}

	cacheUserPath := filepath.Join(b.cfg.WorkDir, "cache", "user")
	cacheIDPath := filepath.Join(b.cfg.WorkDir, "cache", "id")
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cacheUserPath); err == nil {
			if _, err := os.Stat(cacheIDPath); err == nil {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("cache/user not created within timeout")
}

func (b *lingmaBridge) wsInitialize(conn *websocket.Conn) error {
	params := map[string]any{
		"processId":   nil,
		"clientInfo":  map[string]string{"name": "lingma-auth-bootstrap", "version": "1.0"},
		"rootUri":     "file:///tmp/bootstrap",
		"capabilities": map[string]any{},
		"workspaceFolders": []map[string]string{
			{"uri": "file:///tmp/bootstrap", "name": "bootstrap"},
		},
	}
	return wsSendMethod(conn, "initialize", params, 1)
}

func (b *lingmaBridge) readCredentials() (proxy.StoredCredentialFile, error) {
	return ImportCredentialFileFromLingmaDir(b.cfg.WorkDir, time.Now())
}

func (b *lingmaBridge) stop() {
	if b.cmd == nil || b.cmd.Process == nil {
		return
	}
	_ = b.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() {
		_ = b.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = b.cmd.Process.Kill()
	}
	b.cmd = nil
}

func (b *lingmaBridge) cleanup() {
	b.stop()
	if b.cfg.WorkDir != "" {
		os.RemoveAll(b.cfg.WorkDir)
	}
}

func DeriveCredentialsWithLingma(cfg LingmaBridgeConfig) (proxy.StoredCredentialFile, error) {
	bridge := newLingmaBridge(cfg)
	defer bridge.cleanup()

	if err := bridge.start(); err != nil {
		return proxy.StoredCredentialFile{}, err
	}

	if err := bridge.deviceLogin(); err != nil {
		return proxy.StoredCredentialFile{}, err
	}

	cred, err := bridge.readCredentials()
	if err != nil {
		return proxy.StoredCredentialFile{}, fmt.Errorf("read credentials from lingma workdir: %w", err)
	}

	cred.Source = "project_bootstrap"
	return cred, nil
}

func wsSendMethod(conn *websocket.Conn, method string, params any, id int) error {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	frame := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(data), data)
	return conn.WriteMessage(websocket.TextMessage, []byte(frame))
}

func extractMachineIDFromLoginURL(loginURL string) string {
	parsed, err := url.Parse(loginURL)
	if err != nil {
		return ""
	}

	current := loginURL
	for range 5 {
		decoded, err := url.QueryUnescape(current)
		if err != nil || decoded == current {
			break
		}
		current = decoded
	}

	parsed, err = url.Parse(current)
	if err == nil {
		if mid := parsed.Query().Get("machine_id"); mid != "" {
			return mid
		}
	}

	idx := strings.Index(current, "machine_id=")
	if idx < 0 {
		return ""
	}
	value := current[idx+len("machine_id="):]
	if end := strings.IndexAny(value, "&'\""); end >= 0 {
		value = value[:end]
	}
	return value
}

// AES-128-CBC decryption keyed by machine_id[:16], used for cache/user.
func DecryptCacheUser(machineID string, ciphertext []byte) ([]byte, error) {
	if len(machineID) < 16 {
		return nil, fmt.Errorf("machine id too short")
	}

	key := []byte(machineID[:16])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext size")
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, key).CryptBlocks(plaintext, ciphertext)

	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen <= 0 || padLen > aes.BlockSize || padLen > len(plaintext) {
		return nil, fmt.Errorf("invalid padding")
	}
	for _, b := range plaintext[len(plaintext)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return plaintext[:len(plaintext)-padLen], nil
}

func EncryptCacheUser(machineID string, plaintext []byte) ([]byte, error) {
	if len(machineID) < 16 {
		return nil, fmt.Errorf("machine id too short")
	}

	key := []byte(machineID[:16])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}

	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, key).CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func DecodeAndDecryptCacheUser(machineID string, base64Data string) (*proxy.StoredCredentialFile, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(base64Data))
	if err != nil {
		return nil, fmt.Errorf("decode cache/user base64: %w", err)
	}

	plaintext, err := DecryptCacheUser(machineID, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt cache/user: %w", err)
	}

	var payload struct {
		Key                string `json:"key"`
		EncryptUserInfo    string `json:"encrypt_user_info"`
		UID                string `json:"uid"`
		SecurityOAuthToken string `json:"security_oauth_token"`
		RefreshToken       string `json:"refresh_token"`
		ExpireTime         any    `json:"expire_time"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("parse cache/user json: %w", err)
	}

	tokenExpireTime := ""
	switch v := payload.ExpireTime.(type) {
	case string:
		tokenExpireTime = v
	case float64:
		tokenExpireTime = fmt.Sprintf("%.0f", v)
	}

	now := time.Now().Format(time.RFC3339)
	return &proxy.StoredCredentialFile{
		SchemaVersion:     1,
		Source:            "project_bootstrap",
		LingmaVersionHint: "2.11.1",
		ObtainedAt:        now,
		UpdatedAt:         now,
		TokenExpireTime:   tokenExpireTime,
		Auth: proxy.StoredAuthFields{
			CosyKey:         payload.Key,
			EncryptUserInfo: payload.EncryptUserInfo,
			UserID:          payload.UID,
			MachineID:       machineID,
		},
		OAuth: proxy.StoredOAuthFields{
			AccessToken:  payload.SecurityOAuthToken,
			RefreshToken: payload.RefreshToken,
		},
	}, nil
}
