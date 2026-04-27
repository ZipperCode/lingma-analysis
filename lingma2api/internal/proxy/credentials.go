package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"lingma2api/internal/config"
)

type CredentialManager struct {
	mu      sync.RWMutex
	cfg     config.CredentialConfig
	now     func() time.Time
	current CredentialSnapshot
	loaded  bool
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

func (manager *CredentialManager) Current(_ context.Context) (CredentialSnapshot, error) {
	manager.mu.RLock()
	if manager.loaded {
		snapshot := manager.current
		manager.mu.RUnlock()
		return snapshot, nil
	}
	manager.mu.RUnlock()

	return manager.Refresh(context.Background())
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

	snapshot := CredentialSnapshot{
		CosyKey:         stored.Auth.CosyKey,
		EncryptUserInfo: stored.Auth.EncryptUserInfo,
		UserID:          stored.Auth.UserID,
		MachineID:       stored.Auth.MachineID,
		Source:          stored.Source,
		LoadedAt:        manager.now(),
	}
	return snapshot, validateSnapshot(snapshot)
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
