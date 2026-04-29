package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"lingma2api/internal/config"
)

// TokenRefreshFn is called when credentials need refreshing.
type TokenRefreshFn func(ctx context.Context) error

type CredentialManager struct {
	mu      sync.RWMutex
	cfg     config.CredentialConfig
	now     func() time.Time
	current CredentialSnapshot
	loaded  bool
	// refreshFn is called when token is expired; if nil, no auto-refresh.
	refreshFn TokenRefreshFn
}

func NewCredentialManager(cfg config.CredentialConfig, now func() time.Time) *CredentialManager {
	if now == nil {
		now = time.Now
	}
	if cfg.AuthFile == "" {
		cfg.AuthFile = "./auth/credentials.json"
	}
	return &CredentialManager{
		cfg: cfg,
		now: now,
	}
}

// SetRefreshFn sets the callback used for auto-refreshing expired tokens.
func (manager *CredentialManager) SetRefreshFn(fn TokenRefreshFn) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.refreshFn = fn
}

func (manager *CredentialManager) Current(ctx context.Context) (CredentialSnapshot, error) {
	manager.mu.RLock()
	snapshot := manager.current
	loaded := manager.loaded
	refreshFn := manager.refreshFn
	manager.mu.RUnlock()

	if loaded {
		// Check if token is expired and auto-refresh if possible
		if snapshot.IsTokenExpired(5*time.Minute) && refreshFn != nil {
			if err := refreshFn(ctx); err == nil {
				// Refresh successful, reload snapshot
				return manager.Refresh(ctx)
			}
			// Refresh failed, return current (caller may retry or use anyway)
		}
		return snapshot, nil
	}

	return manager.Refresh(ctx)
}

func (manager *CredentialManager) Refresh(_ context.Context) (CredentialSnapshot, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	snapshot, err := manager.loadSnapshot()
	if err != nil {
		return CredentialSnapshot{}, err
	}

	manager.current = snapshot
	manager.loaded = true
	return snapshot, nil
}

func (manager *CredentialManager) Status() CredentialStatus {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	return CredentialStatus{
		Loaded:         manager.loaded,
		HasCredentials: manager.current.CosyKey != "" && manager.current.EncryptUserInfo != "",
		Source:         manager.current.Source,
		LoadedAt:       manager.current.LoadedAt,
		TokenExpired:   manager.current.IsTokenExpired(5 * time.Minute),
	}
}

func (manager *CredentialManager) loadSnapshot() (CredentialSnapshot, error) {
	if manager.cfg.AuthFile == "" {
		return CredentialSnapshot{}, fmt.Errorf("%w: missing auth_file", ErrCredentialsUnavailable)
	}

	data, err := os.ReadFile(manager.cfg.AuthFile)
	if err != nil {
		return CredentialSnapshot{}, fmt.Errorf("%w: read auth file: %v", ErrCredentialsUnavailable, err)
	}

	var stored StoredCredentialFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return CredentialSnapshot{}, fmt.Errorf("%w: parse auth file: %v", ErrCredentialsUnavailable, err)
	}
	if stored.Source == "" {
		stored.Source = "project_auth_file"
	}

	expireTime := parseExpireTime(stored.TokenExpireTime)

	snapshot := CredentialSnapshot{
		CosyKey:         stored.Auth.CosyKey,
		EncryptUserInfo: stored.Auth.EncryptUserInfo,
		UserID:          stored.Auth.UserID,
		MachineID:       stored.Auth.MachineID,
		Source:          stored.Source,
		LoadedAt:        manager.now(),
		TokenExpireTime: expireTime,
	}
	return snapshot, validateSnapshot(snapshot)
}

func parseExpireTime(s string) int64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func validateSnapshot(snapshot CredentialSnapshot) error {
	if snapshot.CosyKey == "" {
		return fmt.Errorf("%w: missing cosy key", ErrCredentialsUnavailable)
	}
	if snapshot.EncryptUserInfo == "" {
		return fmt.Errorf("%w: missing encrypt_user_info", ErrCredentialsUnavailable)
	}
	if snapshot.UserID == "" {
		return fmt.Errorf("%w: missing user id", ErrCredentialsUnavailable)
	}
	if snapshot.MachineID == "" {
		return fmt.Errorf("%w: missing machine id", ErrCredentialsUnavailable)
	}
	return nil
}
