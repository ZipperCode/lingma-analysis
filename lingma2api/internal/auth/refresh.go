package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"lingma2api/internal/proxy"
)

// TokenRefreshResult holds the result of a token refresh operation.
type TokenRefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpireTime   int64 // unix millis
	UserID       string
	Source       string
}

// TokenRefresher defines the interface for token refresh strategies.
type TokenRefresher interface {
	Refresh(ctx context.Context, stored proxy.StoredCredentialFile) (TokenRefreshResult, error)
	Name() string
}

// OAuthRefresher uses direct OAuth refresh_token grant (requires client_id).
type OAuthRefresher struct {
	ClientID string
}

func (r *OAuthRefresher) Name() string { return "oauth" }

func (r *OAuthRefresher) Refresh(ctx context.Context, stored proxy.StoredCredentialFile) (TokenRefreshResult, error) {
	if r.ClientID == "" {
		return TokenRefreshResult{}, fmt.Errorf("client_id not configured")
	}
	if stored.OAuth.RefreshToken == "" {
		return TokenRefreshResult{}, fmt.Errorf("refresh_token missing")
	}

	tokens, err := RefreshTokens(ctx, RefreshTokenConfig{
		RefreshToken: stored.OAuth.RefreshToken,
		ClientID:     r.ClientID,
	})
	if err != nil {
		return TokenRefreshResult{}, fmt.Errorf("oauth refresh: %w", err)
	}

	expireMs := int64(0)
	if tokens.ExpiresIn > 0 {
		expireMs = time.Now().UnixMilli() + int64(tokens.ExpiresIn)*1000
	}

	return TokenRefreshResult{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpireTime:   expireMs,
		Source:       "oauth_refresh",
	}, nil
}

// WSRefresher uses local Lingma WebSocket for token refresh.
type WSRefresher struct {
	SocketPort int
}

func (r *WSRefresher) Name() string { return "websocket" }

func (r *WSRefresher) Refresh(_ context.Context, stored proxy.StoredCredentialFile) (TokenRefreshResult, error) {
	if stored.OAuth.AccessToken == "" || stored.OAuth.RefreshToken == "" {
		return TokenRefreshResult{}, fmt.Errorf("oauth tokens missing")
	}

	var expireTime int64
	if stored.TokenExpireTime != "" {
		if v, err := parseInt64(stored.TokenExpireTime); err == nil {
			expireTime = v
		}
	}

	result, err := RefreshTokensViaWebSocket(WSRefreshConfig{
		SecurityOauthToken: stored.OAuth.AccessToken,
		RefreshToken:       stored.OAuth.RefreshToken,
		TokenExpireTime:    expireTime,
		SocketPort:         r.SocketPort,
		Timeout:            30 * time.Second,
	})
	if err != nil {
		return TokenRefreshResult{}, fmt.Errorf("websocket refresh: %w", err)
	}

	return TokenRefreshResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpireTime:   result.ExpireTime,
		UserID:       result.UserID,
		Source:       "websocket_refresh",
	}, nil
}

// MultiRefresher tries multiple strategies in order.
type MultiRefresher struct {
	strategies []TokenRefresher
}

func NewMultiRefresher(strategies ...TokenRefresher) *MultiRefresher {
	return &MultiRefresher{strategies: strategies}
}

func (m *MultiRefresher) Name() string { return "multi" }

func (m *MultiRefresher) Refresh(ctx context.Context, stored proxy.StoredCredentialFile) (TokenRefreshResult, error) {
	var lastErr error
	for _, s := range m.strategies {
		result, err := s.Refresh(ctx, stored)
		if err == nil {
			return result, nil
		}
		lastErr = fmt.Errorf("%s: %w", s.Name(), err)
	}
	return TokenRefreshResult{}, fmt.Errorf("all refresh strategies failed: %w", lastErr)
}

// RefreshAndSave performs token refresh and updates the credentials file.
func RefreshAndSave(ctx context.Context, authFile string, refresher TokenRefresher, useLingma bool, lingmaBin string) error {
	data, err := os.ReadFile(authFile)
	if err != nil {
		return fmt.Errorf("read credentials: %w", err)
	}

	var stored proxy.StoredCredentialFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}

	result, err := refresher.Refresh(ctx, stored)
	if err != nil {
		return err
	}

	stored.OAuth.AccessToken = result.AccessToken
	stored.OAuth.RefreshToken = result.RefreshToken
	if result.ExpireTime > 0 {
		stored.TokenExpireTime = fmt.Sprintf("%d", result.ExpireTime)
	}
	stored.UpdatedAt = time.Now().Format(time.RFC3339)

	// Derive cosy_key and encrypt_user_info if missing
	if stored.Auth.CosyKey == "" || stored.Auth.EncryptUserInfo == "" {
		newStored, err := deriveAfterRefresh(result, stored, useLingma, lingmaBin)
		if err != nil {
			return fmt.Errorf("derive after refresh: %w", err)
		}
		stored.Auth = newStored.Auth
		if newStored.Source != "" {
			stored.Source = newStored.Source
		}
	}

	if result.UserID != "" && stored.Auth.UserID == "" {
		stored.Auth.UserID = result.UserID
	}

	return SaveCredentialFile(authFile, stored)
}

func deriveAfterRefresh(result TokenRefreshResult, stored proxy.StoredCredentialFile, useLingma bool, lingmaBin string) (proxy.StoredCredentialFile, error) {
	machineID := stored.Auth.MachineID
	if machineID == "" {
		machineID = NewMachineID()
	}

	expireMs := ""
	if result.ExpireTime > 0 {
		expireMs = fmt.Sprintf("%d", result.ExpireTime)
	} else {
		expireMs = fmt.Sprintf("%d", time.Now().UnixMilli()+3600*1000)
	}

	if useLingma {
		if lingmaBin == "" {
			var err error
			lingmaBin, err = DefaultLingmaBinary()
			if err != nil {
				return proxy.StoredCredentialFile{}, fmt.Errorf("auto-detect Lingma binary: %w", err)
			}
		}
		return DeriveCredentialsWithLingma(LingmaBridgeConfig{
			LingmaBinary:  lingmaBin,
			AccessToken:   result.AccessToken,
			RefreshToken:  result.RefreshToken,
			UserID:        stored.Auth.UserID,
			TokenExpireMs: expireMs,
		})
	}

	return DeriveCredentialsRemotely(RemoteLoginConfig{
		AccessToken:   result.AccessToken,
		RefreshToken:  result.RefreshToken,
		UserID:        stored.Auth.UserID,
		MachineID:     machineID,
		TokenExpireMs: expireMs,
	})
}

func parseInt64(s string) (int64, error) {
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}
