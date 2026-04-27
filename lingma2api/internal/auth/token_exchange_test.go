package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExchangeCodeForTokens_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  TokenExchangeConfig
	}{
		{"missing code", TokenExchangeConfig{RedirectURL: "http://x", ClientID: "c", CodeVerifier: "v"}},
		{"missing redirect", TokenExchangeConfig{Code: "c", ClientID: "c", CodeVerifier: "v"}},
		{"missing client_id", TokenExchangeConfig{Code: "c", RedirectURL: "http://x", CodeVerifier: "v"}},
		{"missing verifier", TokenExchangeConfig{Code: "c", RedirectURL: "http://x", ClientID: "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExchangeCodeForTokens(t.Context(), tt.cfg)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestExchangeCodeForTokens_Success(t *testing.T) {
	expectedAccess := "pt-test-access-token"
	expectedRefresh := "rt-test-refresh-token"
	expectedID := buildTestIDToken("5930676910898027", "testuser")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("expected grant_type=authorization_code, got %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code") != "test-code" {
			t.Errorf("expected code=test-code, got %s", r.Form.Get("code"))
		}
		if r.Form.Get("code_verifier") != "test-verifier" {
			t.Errorf("unexpected code_verifier")
		}

		resp := map[string]any{
			"access_token":  expectedAccess,
			"refresh_token": expectedRefresh,
			"expires_in":    3600,
			"token_type":    "Bearer",
			"id_token":      expectedID,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	tokens, err := ExchangeCodeForTokens(t.Context(), TokenExchangeConfig{
		Code:         "test-code",
		RedirectURL:  "http://127.0.0.1:37510/callback",
		ClientID:     "test-client-id",
		CodeVerifier: "test-verifier",
		TokenURL:     server.URL,
	})
	if err != nil {
		t.Fatalf("ExchangeCodeForTokens: %v", err)
	}
	if tokens.AccessToken != expectedAccess {
		t.Errorf("access_token: got %q, want %q", tokens.AccessToken, expectedAccess)
	}
	if tokens.RefreshToken != expectedRefresh {
		t.Errorf("refresh_token: got %q, want %q", tokens.RefreshToken, expectedRefresh)
	}
	if tokens.IDToken != expectedID {
		t.Errorf("id_token mismatch")
	}
}

func TestExchangeCodeForTokens_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(TokenExchangeError{
			ErrorCode:        "invalid_grant",
			ErrorDescription: "Authorization code has expired",
		})
	}))
	defer server.Close()

	_, err := ExchangeCodeForTokens(t.Context(), TokenExchangeConfig{
		Code:         "expired-code",
		RedirectURL:  "http://127.0.0.1:37510/callback",
		ClientID:     "test-client-id",
		CodeVerifier: "test-verifier",
		TokenURL:     server.URL,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	tokenErr, ok := err.(*TokenExchangeError)
	if !ok {
		t.Fatalf("expected *TokenExchangeError, got %T: %v", err, err)
	}
	if tokenErr.ErrorCode != "invalid_grant" {
		t.Errorf("error code: got %q, want %q", tokenErr.ErrorCode, "invalid_grant")
	}
}

func TestDecodeIDTokenClaims(t *testing.T) {
	idToken := buildTestIDToken("12345", "alice")
	claims, err := DecodeIDTokenClaims(idToken)
	if err != nil {
		t.Fatalf("DecodeIDTokenClaims: %v", err)
	}
	if claims.Sub != "12345" {
		t.Errorf("sub: got %q, want %q", claims.Sub, "12345")
	}
	if claims.Name != "alice" {
		t.Errorf("name: got %q, want %q", claims.Name, "alice")
	}
}

func TestDecodeIDTokenClaims_Invalid(t *testing.T) {
	_, err := DecodeIDTokenClaims("")
	if err == nil {
		t.Fatal("expected error for empty id_token")
	}

	_, err = DecodeIDTokenClaims("not.a.jwt")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}

	_, err = DecodeIDTokenClaims("header.!@#$.sig")
	if err == nil {
		t.Fatal("expected error for invalid base64 payload")
	}
}

func buildTestIDToken(sub, name string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"sub":"` + sub + `","name":"` + name + `","iss":"https://signin.alibabacloud.com"}`,
	))
	return header + "." + payload + ".fake-signature"
}

func TestDecodeIDTokenClaims_PaddingVariant(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"42","name":"test"}`))
	raw := "eyJhbGciOiJSUzI1NiJ9." + payload + ".sig"

	claims, err := DecodeIDTokenClaims(raw)
	if err != nil {
		t.Fatalf("DecodeIDTokenClaims: %v", err)
	}
	if claims.Sub != "42" {
		t.Errorf("sub: got %q, want %q", claims.Sub, "42")
	}
}

func TestNewMachineID(t *testing.T) {
	id1 := NewMachineID()
	id2 := NewMachineID()

	if id1 == id2 {
		t.Fatal("expected different machine IDs")
	}
	if !strings.Contains(id1, "-") {
		t.Errorf("expected UUID format, got %q", id1)
	}
	parts := strings.Split(id1, "-")
	if len(parts) != 5 {
		t.Errorf("expected 5 parts in UUID, got %d: %q", len(parts), id1)
	}
}

func TestRefreshTokens_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("grant_type: got %q, want refresh_token", r.FormValue("grant_type"))
		}
		if r.FormValue("refresh_token") != "rt-123" {
			t.Errorf("refresh_token: got %q, want rt-123", r.FormValue("refresh_token"))
		}
		if r.FormValue("client_id") != "client-456" {
			t.Errorf("client_id: got %q, want client-456", r.FormValue("client_id"))
		}

		resp := ExchangedTokens{
			AccessToken:  "at-new",
			RefreshToken: "rt-new",
			ExpiresIn:    3600,
			TokenType:    "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	tokens, err := RefreshTokens(t.Context(), RefreshTokenConfig{
		RefreshToken: "rt-123",
		ClientID:     "client-456",
		TokenURL:     server.URL,
	})
	if err != nil {
		t.Fatalf("RefreshTokens() error = %v", err)
	}
	if tokens.AccessToken != "at-new" {
		t.Errorf("access_token: got %q, want at-new", tokens.AccessToken)
	}
	if tokens.RefreshToken != "rt-new" {
		t.Errorf("refresh_token: got %q, want rt-new", tokens.RefreshToken)
	}
}

func TestRefreshTokens_StructuredError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Refresh token expired"}`))
	}))
	defer server.Close()

	_, err := RefreshTokens(t.Context(), RefreshTokenConfig{
		RefreshToken: "rt-bad",
		ClientID:     "client-456",
		TokenURL:     server.URL,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	tokenErr, ok := err.(*TokenExchangeError)
	if !ok {
		t.Fatalf("expected *TokenExchangeError, got %T: %v", err, err)
	}
	if tokenErr.ErrorCode != "invalid_grant" {
		t.Errorf("error_code: got %q, want invalid_grant", tokenErr.ErrorCode)
	}
	if tokenErr.ErrorDescription != "Refresh token expired" {
		t.Errorf("error_description: got %q, want 'Refresh token expired'", tokenErr.ErrorDescription)
	}
}

func TestRefreshTokens_FallbackError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("raw body without json"))
	}))
	defer server.Close()

	_, err := RefreshTokens(t.Context(), RefreshTokenConfig{
		RefreshToken: "rt-bad",
		ClientID:     "client-456",
		TokenURL:     server.URL,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*TokenExchangeError); ok {
		t.Fatal("expected fallback error, not TokenExchangeError")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("expected error to contain status 400, got: %v", err)
	}
	if !strings.Contains(err.Error(), "raw body without json") {
		t.Errorf("expected error to contain raw body, got: %v", err)
	}
}

func TestRefreshTokens_MissingRefreshToken(t *testing.T) {
	_, err := RefreshTokens(t.Context(), RefreshTokenConfig{
		ClientID: "client-456",
	})
	if err == nil {
		t.Fatal("expected error for missing refresh token")
	}
	if !strings.Contains(err.Error(), "missing refresh token") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRefreshTokens_MissingClientID(t *testing.T) {
	_, err := RefreshTokens(t.Context(), RefreshTokenConfig{
		RefreshToken: "rt-123",
	})
	if err == nil {
		t.Fatal("expected error for missing client id")
	}
	if !strings.Contains(err.Error(), "missing client id") {
		t.Errorf("unexpected error: %v", err)
	}
}
