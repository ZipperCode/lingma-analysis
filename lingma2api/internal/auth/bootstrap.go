package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

// LingmaLoginEntryConfig 用于生成 Lingma 服务器侧登录入口 URL（不含 client_id）。
// Lingma 服务器在收到该 URL 后会注入 client_id 并 302 到 signin.alibabacloud.com/oauth2/v1/auth，
// 在浏览器抓取该跳转链是目前公认的 client_id 提取路径。
type LingmaLoginEntryConfig struct {
	MachineID string // 留空则自动生成 UUID
	Port      string // 回调端口（用于构造 lingma 登录 URL 的 port 参数）
	BaseURL   string // 默认 https://lingma.alibabacloud.com/lingma/login
}

// BuildLingmaLoginEntryURL 构造一个未注入 client_id 的 Lingma 登录入口 URL。
// 返回 (loginURL, state, verifier, error)。
// 用法：将 loginURL 喂给 WrapLingmaLoginURLForBrowser 得到浏览器入口，复制到浏览器后
// 由 Lingma 服务器在 302 链中注入真正的 client_id。
func BuildLingmaLoginEntryURL(cfg LingmaLoginEntryConfig) (string, string, string, error) {
	machineID := cfg.MachineID
	if machineID == "" {
		machineID = NewMachineID()
	}
	if cfg.Port == "" {
		return "", "", "", errors.New("missing port")
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://lingma.alibabacloud.com/lingma/login"
	}

	state := GenerateState()
	verifier, challenge := GeneratePKCE()
	nonceBuf := make([]byte, 16)
	if _, err := rand.Read(nonceBuf); err != nil {
		return "", "", "", err
	}
	nonce := hex.EncodeToString(nonceBuf)

	values := url.Values{}
	values.Set("state", state)
	values.Set("challenge", challenge)
	values.Set("challenge_method", "S256")
	values.Set("machine_id", machineID)
	values.Set("nonce", nonce)
	values.Set("port", cfg.Port)

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
		captured := CaptureFromRequest(request)
		captured.Referer = request.Header.Get("Referer")
		resultCh <- captured
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = writer.Write([]byte(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Lingma Auth</title></head>
<body>
<h1>Authorization received</h1>
<p>You may close this window.</p>
<p>Run this in console to copy tokens:</p>
<pre style="background:#f0f0f0;padding:8px;border-radius:4px;overflow:auto;max-height:200px">
copy(window.user_info)
</pre>
</body></html>`))
	}
	mux.HandleFunc(callbackPath, handler)
	if callbackPath != "/profile" {
		mux.HandleFunc("/profile", handler)
	}

	// POST /submit-userinfo: bookmarklet submits window.user_info + window.login_url JSON
	mux.HandleFunc("/submit-userinfo", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = writer.Write([]byte(`<h1>Method Not Allowed</h1><p>Use POST with JSON body: {"userInfo":..., "loginUrl":...}</p>`))
			return
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			errCh <- fmt.Errorf("read submit-userinfo body: %w", readErr)
			return
		}
		defer request.Body.Close()

		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`<h1>Token data received</h1><p>You may close this window. Check the terminal for results.</p>`))

		resultCh <- CallbackCapture{
			Path:       "/submit-userinfo",
			ReceivedAt: time.Now(),
			Body:       body,
		}
	})

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
