package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TokenExchangeConfig struct {
	Code         string
	RedirectURL  string
	ClientID     string
	CodeVerifier string
	TokenURL     string
	HTTPClient   *http.Client
}

type RefreshTokenConfig struct {
	RefreshToken string
	ClientID     string
	TokenURL     string
	HTTPClient   *http.Client
}

type ExchangedTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

type IDTokenClaims struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type TokenExchangeError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e *TokenExchangeError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("token exchange: %s (%s)", e.ErrorDescription, e.ErrorCode)
	}
	return fmt.Sprintf("token exchange: %s", e.ErrorCode)
}

func ExchangeCodeForTokens(ctx context.Context, cfg TokenExchangeConfig) (ExchangedTokens, error) {
	if cfg.Code == "" {
		return ExchangedTokens{}, fmt.Errorf("missing authorization code")
	}
	if cfg.RedirectURL == "" {
		return ExchangedTokens{}, fmt.Errorf("missing redirect url")
	}
	if cfg.ClientID == "" {
		return ExchangedTokens{}, fmt.Errorf("missing client id")
	}
	if cfg.CodeVerifier == "" {
		return ExchangedTokens{}, fmt.Errorf("missing code verifier")
	}

	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth.alibabacloud.com/v1/token"
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", cfg.Code)
	form.Set("redirect_uri", cfg.RedirectURL)
	form.Set("client_id", cfg.ClientID)
	form.Set("code_verifier", cfg.CodeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return ExchangedTokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ExchangedTokens{}, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ExchangedTokens{}, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var tokenErr TokenExchangeError
		if json.Unmarshal(body, &tokenErr) == nil && tokenErr.ErrorCode != "" {
			return ExchangedTokens{}, &tokenErr
		}
		return ExchangedTokens{}, fmt.Errorf("token exchange http %d: %s", resp.StatusCode, string(body))
	}

	var tokens ExchangedTokens
	if err := json.Unmarshal(body, &tokens); err != nil {
		return ExchangedTokens{}, fmt.Errorf("parse token response: %w", err)
	}
	if tokens.AccessToken == "" {
		return ExchangedTokens{}, fmt.Errorf("token response missing access_token")
	}
	return tokens, nil
}

func RefreshTokens(ctx context.Context, cfg RefreshTokenConfig) (ExchangedTokens, error) {
	if cfg.RefreshToken == "" {
		return ExchangedTokens{}, fmt.Errorf("missing refresh token")
	}
	if cfg.ClientID == "" {
		return ExchangedTokens{}, fmt.Errorf("missing client id")
	}

	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth.alibabacloud.com/v1/token"
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", cfg.RefreshToken)
	form.Set("client_id", cfg.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return ExchangedTokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ExchangedTokens{}, fmt.Errorf("refresh token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ExchangedTokens{}, fmt.Errorf("read refresh token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var tokenErr TokenExchangeError
		if json.Unmarshal(body, &tokenErr) == nil && tokenErr.ErrorCode != "" {
			return ExchangedTokens{}, &tokenErr
		}
		return ExchangedTokens{}, fmt.Errorf("refresh token http %d: %s", resp.StatusCode, string(body))
	}

	var tokens ExchangedTokens
	if err := json.Unmarshal(body, &tokens); err != nil {
		return ExchangedTokens{}, fmt.Errorf("parse refresh token response: %w", err)
	}
	if tokens.AccessToken == "" {
		return ExchangedTokens{}, fmt.Errorf("refresh token response missing access_token")
	}
	return tokens, nil
}

func DecodeIDTokenClaims(idToken string) (IDTokenClaims, error) {
	if idToken == "" {
		return IDTokenClaims{}, fmt.Errorf("missing id_token")
	}

	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return IDTokenClaims{}, fmt.Errorf("invalid id_token format")
	}

	payload := parts[1]
	decoded, err := base64DecodeIDToken(payload)
	if err != nil {
		return IDTokenClaims{}, fmt.Errorf("decode id_token payload: %w", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return IDTokenClaims{}, fmt.Errorf("parse id_token claims: %w", err)
	}
	return claims, nil
}

func base64DecodeIDToken(encoded string) ([]byte, error) {
	// JWT payload uses base64 raw URL encoding (no padding).
	// Add padding if needed for the standard decoder.
	padding := (4 - len(encoded)%4) % 4
	padded := encoded + strings.Repeat("=", padding)
	decoded, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
