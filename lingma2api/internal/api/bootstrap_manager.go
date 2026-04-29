package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"lingma2api/internal/auth"
	"lingma2api/internal/proxy"
)

type BootstrapSession struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Method    string    `json:"method"`
	AuthURL   string    `json:"auth_url,omitempty"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
}

type BootstrapManager struct {
	mu         sync.Mutex
	sessions   map[string]*BootstrapSession
	authFile   string
	clientID   string
	listenAddr string
	lingmaVer  string
}

func NewBootstrapManager(authFile, clientID, listenAddr, lingmaVer string) *BootstrapManager {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:37510"
	}
	return &BootstrapManager{
		sessions:   make(map[string]*BootstrapSession),
		authFile:   authFile,
		clientID:   clientID,
		listenAddr: listenAddr,
		lingmaVer:  lingmaVer,
	}
}

func (m *BootstrapManager) StartOAuth() (*BootstrapSession, error) {
	if m.clientID == "" {
		return nil, fmt.Errorf("client_id not configured")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	redirectURL, err := auth.CallbackURLFromListenAddr(m.listenAddr)
	if err != nil {
		return nil, err
	}

	authorizeURL, state, verifier, err := auth.BuildAuthorizeURL(auth.AuthorizeConfig{
		ClientID:    m.clientID,
		RedirectURL: redirectURL,
	})
	if err != nil {
		return nil, fmt.Errorf("build authorize url: %w", err)
	}

	id := newSessionID()
	sess := &BootstrapSession{
		ID:        id,
		Status:    "running",
		Method:    "oauth",
		AuthURL:   authorizeURL,
		StartedAt: time.Now(),
	}
	m.sessions[id] = sess

	go m.runOAuthFlow(id, state, verifier, redirectURL)

	return sess, nil
}

func (m *BootstrapManager) runOAuthFlow(id, state, verifier, redirectURL string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	capture, err := auth.WaitForCallback(ctx, m.listenAddr, "/callback")
	if err != nil {
		m.updateSession(id, "error", fmt.Sprintf("wait for callback: %v", err))
		return
	}

	code := capture.Query.Get("code")
	if code == "" {
		m.updateSession(id, "error", "callback did not contain authorization code")
		return
	}

	tokens, err := auth.ExchangeCodeForTokens(ctx, auth.TokenExchangeConfig{
		Code:         code,
		RedirectURL:  redirectURL,
		ClientID:     m.clientID,
		CodeVerifier: verifier,
	})
	if err != nil {
		m.updateSession(id, "error", fmt.Sprintf("token exchange: %v", err))
		return
	}

	userID := ""
	username := ""
	if tokens.IDToken != "" {
		claims, err := auth.DecodeIDTokenClaims(tokens.IDToken)
		if err == nil {
			userID = claims.Sub
			username = claims.Name
			if username == "" {
				username = claims.Email
			}
		}
	}

	expireMs := ""
	if tokens.ExpiresIn > 0 {
		expireMs = fmt.Sprintf("%d", time.Now().UnixMilli()+int64(tokens.ExpiresIn)*1000)
	}

	machineID := auth.NewMachineID()

	stored, err := auth.DeriveCredentialsRemotely(auth.RemoteLoginConfig{
		AccessToken:   tokens.AccessToken,
		RefreshToken:  tokens.RefreshToken,
		UserID:        userID,
		Username:      username,
		MachineID:     machineID,
		TokenExpireMs: expireMs,
	})
	if err != nil {
		m.updateSession(id, "error", fmt.Sprintf("derive credentials: %v", err))
		return
	}

	if userID != "" && stored.Auth.UserID == "" {
		stored.Auth.UserID = userID
	}
	if stored.Auth.MachineID == "" {
		stored.Auth.MachineID = machineID
	}

	if err := auth.SaveCredentialFile(m.authFile, stored); err != nil {
		m.updateSession(id, "error", fmt.Sprintf("save credentials: %v", err))
		return
	}

	m.updateSession(id, "completed", "")
}

func (m *BootstrapManager) StartWS() (*BootstrapSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.authFile)
	if err != nil {
		return nil, fmt.Errorf("no existing credentials to refresh: %w", err)
	}

	var stored proxy.StoredCredentialFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}

	if stored.OAuth.AccessToken == "" || stored.OAuth.RefreshToken == "" {
		return nil, fmt.Errorf("existing credentials missing oauth tokens (not a remote-login credential)")
	}

	id := newSessionID()
	sess := &BootstrapSession{
		ID:        id,
		Status:    "running",
		Method:    "ws",
		StartedAt: time.Now(),
	}
	m.sessions[id] = sess

	go m.runWSFlow(id, stored)

	return sess, nil
}

func (m *BootstrapManager) runWSFlow(id string, stored proxy.StoredCredentialFile) {
	var expireTime int64
	if stored.TokenExpireTime != "" {
		if v, err := strconv.ParseInt(stored.TokenExpireTime, 10, 64); err == nil {
			expireTime = v
		}
	}

	refresher := &auth.WSRefresher{}
	result, err := refresher.Refresh(context.Background(), stored)
	if err != nil {
		m.updateSession(id, "error", fmt.Sprintf("WebSocket refresh: %v", err))
		return
	}

	expireMs := fmt.Sprintf("%d", result.ExpireTime)
	if result.ExpireTime == 0 && expireTime > 0 {
		expireMs = fmt.Sprintf("%d", expireTime)
	}

	machineID := stored.Auth.MachineID
	if machineID == "" {
		machineID = auth.NewMachineID()
	}

	userID := stored.Auth.UserID
	if result.UserID != "" {
		userID = result.UserID
	}

	// Derive fresh cosy_key and encrypt_user_info. Use the Lingma binary
	// when available (most reliable), fall back to remote API.
	newStored, err := m.deriveCredentials(result.AccessToken, result.RefreshToken, userID, machineID, expireMs)
	if err != nil {
		m.updateSession(id, "error", fmt.Sprintf("derive credentials: %v", err))
		return
	}

	if err := auth.SaveCredentialFile(m.authFile, newStored); err != nil {
		m.updateSession(id, "error", fmt.Sprintf("save credentials: %v", err))
		return
	}

	m.updateSession(id, "completed", "")
}

func (m *BootstrapManager) deriveCredentials(accessToken, refreshToken, userID, machineID, expireMs string) (proxy.StoredCredentialFile, error) {
	// Prefer Lingma binary when available — it has the proper encryption keys.
	lingmaBin, binErr := auth.DefaultLingmaBinary()
	if binErr == nil {
		stored, err := auth.DeriveCredentialsWithLingma(auth.LingmaBridgeConfig{
			LingmaBinary:  lingmaBin,
			AccessToken:   accessToken,
			RefreshToken:  refreshToken,
			UserID:        userID,
			TokenExpireMs: expireMs,
		})
		if err == nil {
			return stored, nil
		}
	}

	// Fall back to remote derivation.
	return auth.DeriveCredentialsRemotely(auth.RemoteLoginConfig{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		UserID:        userID,
		MachineID:     machineID,
		TokenExpireMs: expireMs,
	})
}

func (m *BootstrapManager) GetStatus(id string) *BootstrapSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[id]
	if !ok {
		return nil
	}

	// Clean up sessions older than 10 minutes
	if time.Since(sess.StartedAt) > 10*time.Minute {
		delete(m.sessions, id)
	}

	return sess
}

func (m *BootstrapManager) updateSession(id, status, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		s.Status = status
		s.Error = errMsg
	}
}

func newSessionID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
