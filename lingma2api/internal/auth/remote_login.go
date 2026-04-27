package auth

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"lingma2api/internal/proxy"
)

const (
	userLoginURL    = "https://lingma.alibabacloud.com/algo/api/v3/user/login?Encode=1"
	userLoginAESKey = "QbgzpWzN7tfe43gf"
)

type userLoginRequest struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
	UserID       string `json:"userId"`
	Username     string `json:"username"`
	MachineID    string `json:"machineId"`
	ExpireTime   string `json:"expireTime"`
}

type userLoginResponse struct {
	Success          bool   `json:"success"`
	Key              string `json:"key"`
	EncryptUserInfo  string `json:"encrypt_user_info"`
	UID              string `json:"uid"`
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorMessage"`
}

type RemoteLoginConfig struct {
	AccessToken   string
	RefreshToken  string
	UserID        string
	Username      string
	MachineID     string
	TokenExpireMs string
	SessionKey    string // old Signature session_key; empty = try without Signature
	HTTPClient    *http.Client
}

func DeriveCredentialsRemotely(cfg RemoteLoginConfig) (proxy.StoredCredentialFile, error) {
	if cfg.AccessToken == "" {
		return proxy.StoredCredentialFile{}, fmt.Errorf("missing access token")
	}
	if cfg.MachineID == "" {
		return proxy.StoredCredentialFile{}, fmt.Errorf("missing machine id")
	}

	bodyJSON, err := json.Marshal(userLoginRequest{
		Token:        cfg.AccessToken,
		RefreshToken: cfg.RefreshToken,
		UserID:       cfg.UserID,
		Username:     cfg.Username,
		MachineID:    cfg.MachineID,
		ExpireTime:   cfg.TokenExpireMs,
	})
	if err != nil {
		return proxy.StoredCredentialFile{}, fmt.Errorf("marshal login body: %w", err)
	}

	aesKey := []byte(userLoginAESKey)
	encodedBody, err := lingmaEncodeAES(bodyJSON, aesKey)
	if err != nil {
		return proxy.StoredCredentialFile{}, fmt.Errorf("encode login body: %w", err)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	strategies := buildSignatureStrategies(cfg.SessionKey)

	var lastErr error
	for i, st := range strategies {
		req, err := http.NewRequest(http.MethodPost, userLoginURL, strings.NewReader(encodedBody))
		if err != nil {
			return proxy.StoredCredentialFile{}, err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Appcode", "cosy")
		req.Header.Set("User-Agent", "Go-http-client/1.1")

		st.apply(req)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("strategy %d (%s): %w", i, st.name, err)
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var loginResp userLoginResponse
			if err := json.Unmarshal(respBody, &loginResp); err != nil {
				lastErr = fmt.Errorf("parse login response: %w", err)
				continue
			}
			if loginResp.Key != "" && loginResp.EncryptUserInfo != "" {
				return buildCredentialFromLogin(loginResp, cfg)
			}
			if loginResp.ErrorCode != "" {
				lastErr = fmt.Errorf("login error: %s (%s)", loginResp.ErrorDescription, loginResp.ErrorCode)
				continue
			}
		}

		lastErr = fmt.Errorf("strategy %d (%s): http %d: %s", i, st.name, resp.StatusCode, string(respBody[:min(200, len(respBody))]))
	}

	return proxy.StoredCredentialFile{}, fmt.Errorf("all remote login strategies failed: %w", lastErr)
}

type signatureStrategy struct {
	name  string
	apply func(req *http.Request)
}

func buildSignatureStrategies(sessionKey string) []signatureStrategy {
	now := time.Now().UTC()
	rfc1123 := now.Format(time.RFC1123)
	unixTS := fmt.Sprintf("%d", now.Unix())

	strategies := []signatureStrategy{
		{
			name: "no-signature",
			apply: func(req *http.Request) {
				req.Header.Set("Date", rfc1123)
			},
		},
	}

	if sessionKey != "" {
		preimage := rfc1123 + sessionKey
		sig := fmt.Sprintf("%x", md5.Sum([]byte(preimage)))
		strategies = append(strategies, signatureStrategy{
			name: "md5-rfc1123",
			apply: func(req *http.Request) {
				req.Header.Set("Date", rfc1123)
				req.Header.Set("Signature", sig)
			},
		})

		preimage2 := unixTS + sessionKey
		sig2 := fmt.Sprintf("%x", md5.Sum([]byte(preimage2)))
		strategies = append(strategies, signatureStrategy{
			name: "md5-unix",
			apply: func(req *http.Request) {
				req.Header.Set("Date", rfc1123)
				req.Header.Set("Signature", sig2)
			},
		})
	}

	return strategies
}

func buildCredentialFromLogin(resp userLoginResponse, cfg RemoteLoginConfig) (proxy.StoredCredentialFile, error) {
	now := time.Now().Format(time.RFC3339)
	return proxy.StoredCredentialFile{
		SchemaVersion:     1,
		Source:            "project_bootstrap_remote",
		LingmaVersionHint: "2.11.1",
		ObtainedAt:        now,
		UpdatedAt:         now,
		TokenExpireTime:   cfg.TokenExpireMs,
		Auth: proxy.StoredAuthFields{
			CosyKey:         resp.Key,
			EncryptUserInfo: resp.EncryptUserInfo,
			UserID:          firstNonEmpty(resp.UID, cfg.UserID),
			MachineID:       cfg.MachineID,
		},
		OAuth: proxy.StoredOAuthFields{
			AccessToken:  cfg.AccessToken,
			RefreshToken: cfg.RefreshToken,
		},
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
