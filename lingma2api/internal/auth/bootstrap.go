package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func BuildAuthorizeURL(cfg AuthorizeConfig) (string, string, string, error) {
	if cfg.ClientID == "" {
		return "", "", "", errors.New("missing client_id")
	}
	if cfg.RedirectURL == "" {
		return "", "", "", errors.New("missing redirect_url")
	}
	scope := cfg.Scope
	if scope == "" {
		scope = "openid aliuid profile"
	}
	baseURL := cfg.AuthBaseURL
	if baseURL == "" {
		baseURL = "https://signin.alibabacloud.com/oauth2/v1/auth"
	}

	state := GenerateState()
	verifier, challenge := GeneratePKCE()
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", cfg.ClientID)
	values.Set("redirect_uri", cfg.RedirectURL)
	values.Set("scope", scope)
	values.Set("state", state)
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")

	return baseURL + "?" + values.Encode(), state, verifier, nil
}

func WaitForCallback(ctx context.Context, listenAddr, callbackPath string) (CallbackCapture, error) {
	if listenAddr == "" {
		return CallbackCapture{}, errors.New("missing listen address")
	}
	if callbackPath == "" {
		callbackPath = "/callback"
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return CallbackCapture{}, err
	}
	defer listener.Close()

	resultCh := make(chan CallbackCapture, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	handler := func(writer http.ResponseWriter, request *http.Request) {
		resultCh <- CaptureFromRequest(request)
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = writer.Write([]byte("<h1>Authorization received</h1><p>You may close this window.</p>"))
	}
	mux.HandleFunc(callbackPath, handler)
	if callbackPath != "/profile" {
		mux.HandleFunc("/profile", handler)
	}

	server := &http.Server{Handler: mux}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	select {
	case <-ctx.Done():
		_ = server.Shutdown(context.Background())
		return CallbackCapture{}, ctx.Err()
	case err := <-errCh:
		_ = server.Shutdown(context.Background())
		return CallbackCapture{}, err
	case result := <-resultCh:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return result, nil
	}
}

func CallbackURLFromListenAddr(listenAddr string) (string, error) {
	if listenAddr == "" {
		return "", errors.New("missing listen address")
	}
	return fmt.Sprintf("http://%s/callback", listenAddr), nil
}

func WrapLingmaLoginURLForBrowser(loginURL string) (string, error) {
	if loginURL == "" {
		return "", errors.New("missing login url")
	}
	if !strings.Contains(loginURL, "lingma.alibabacloud.com/lingma/login") {
		return loginURL, nil
	}

	inner := "https://account.alibabacloud.com/login/login.htm?oauth_callback=" + url.QueryEscape(loginURL)
	return "https://account.alibabacloud.com/logout/logout.htm?oauth_callback=" + url.QueryEscape(inner), nil
}

func RewriteLingmaLoginURLPort(loginURL, listenAddr string) (string, error) {
	if loginURL == "" {
		return "", errors.New("missing login url")
	}
	if listenAddr == "" {
		return loginURL, nil
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return "", fmt.Errorf("invalid listen addr: %s", listenAddr)
	}

	parsed, err := url.Parse(loginURL)
	if err != nil {
		return "", err
	}
	values := parsed.Query()
	values.Set("port", port)
	parsed.RawQuery = values.Encode()

	_ = host
	return parsed.String(), nil
}

func CaptureFromRequest(request *http.Request) CallbackCapture {
	return CallbackCapture{
		Path:       request.URL.Path,
		Query:      request.URL.Query(),
		ReceivedAt: time.Now(),
	}
}
