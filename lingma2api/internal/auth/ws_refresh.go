package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type WSRefreshConfig struct {
	SocketPort          int
	SecurityOauthToken  string
	RefreshToken        string
	TokenExpireTime     int64 // unix millis; 0 = use 24h ago
	Timeout             time.Duration
}

type WSRefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpireTime   int64
	UserID       string
}

func RefreshTokensViaWebSocket(cfg WSRefreshConfig) (WSRefreshResult, error) {
	if cfg.SecurityOauthToken == "" {
		return WSRefreshResult{}, fmt.Errorf("missing security oauth token")
	}
	if cfg.RefreshToken == "" {
		return WSRefreshResult{}, fmt.Errorf("missing refresh token")
	}
	if cfg.SocketPort == 0 {
		cfg.SocketPort = 37010
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.TokenExpireTime == 0 {
		cfg.TokenExpireTime = time.Now().UnixMilli() - 86400000
	}

	wsURL := fmt.Sprintf("ws://127.0.0.1:%d", cfg.SocketPort)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return WSRefreshResult{}, fmt.Errorf("connect to lingma ws: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))

	// Initialize
	if err := wsSendMethod(conn, "initialize", map[string]any{
		"processId":  nil,
		"clientInfo": map[string]string{"name": "lingma2api-refresh", "version": "1.0"},
		"rootUri":    "file:///tmp/refresh",
		"capabilities": map[string]any{},
		"workspaceFolders": []map[string]string{
			{"uri": "file:///tmp/refresh", "name": "refresh"},
		},
	}, 1); err != nil {
		return WSRefreshResult{}, fmt.Errorf("ws initialize: %w", err)
	}

	// Read messages until we receive the initialize response (id=1)
	var initialized bool
	for {
		raw, err := wsReadMessage(conn)
		if err != nil {
			return WSRefreshResult{}, fmt.Errorf("read init response: %w", err)
		}
		var msg struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		if msg.ID == 1 {
			break
		}
		// Handle server->client notifications during init
		if msg.Method == "window/logMessage" || msg.Method == "telemetry/event" {
			continue
		}
	}

	// Send initialized notification (required by LSP)
	initialized = true
	_ = initialized
	initNotif := `{"jsonrpc":"2.0","method":"initialized","params":{}}`
	conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(initNotif), initNotif)))

	// Send refreshToken request
	if err := wsSendMethod(conn, "auth/refreshToken", map[string]any{
		"securityOauthToken": cfg.SecurityOauthToken,
		"refreshToken":       cfg.RefreshToken,
		"tokenExpireTime":    cfg.TokenExpireTime,
	}, 2); err != nil {
		return WSRefreshResult{}, fmt.Errorf("send refreshToken: %w", err)
	}

	// Read responses until we get either:
	// 1. Direct response (id=2) -> tokens are valid, return existing
	// 2. auth/syncTokenUpdate notification -> tokens were renewed, return new
	directOK := false
	for {
		raw, err := wsReadMessage(conn)
		if err != nil {
			// Timeout after direct OK means tokens are still valid, no renewal needed
			if directOK {
				return WSRefreshResult{
					AccessToken:  cfg.SecurityOauthToken,
					RefreshToken: cfg.RefreshToken,
					ExpireTime:   cfg.TokenExpireTime,
				}, nil
			}
			return WSRefreshResult{}, fmt.Errorf("read refresh response: %w", err)
		}

		var msg struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Result json.RawMessage `json:"result"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		// Direct response to our refreshToken request
		if msg.ID == 2 && msg.Result != nil {
			var dirResp struct {
				ErrorCode       string `json:"errorCode"`
				ErrorMessage    string `json:"errorMessage"`
				Success         bool   `json:"success"`
				UID             string `json:"uid"`
				Name            string `json:"name"`
				TokenExpireTime int64  `json:"tokenExpireTime"`
			}
			if err := json.Unmarshal(msg.Result, &dirResp); err != nil {
				continue
			}
			if !dirResp.Success {
				return WSRefreshResult{}, fmt.Errorf("refreshToken: %s (%s)", dirResp.ErrorMessage, dirResp.ErrorCode)
			}
			directOK = true
			// Set short deadline: if no syncTokenUpdate arrives soon, tokens are current
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			continue
		}

		// Server push with updated tokens
		if msg.Method == "auth/syncTokenUpdate" {
			var params struct {
				Status       int    `json:"status"`
				Token        string `json:"token"`
				RefreshToken string `json:"refreshToken"`
				ExpireTime   int64  `json:"expireTime"`
				ID           string `json:"id"`
			}
			if err := json.Unmarshal(msg.Params, &params); err != nil {
				return WSRefreshResult{}, fmt.Errorf("parse syncTokenUpdate: %w", err)
			}
			if params.Status != 0 {
				return WSRefreshResult{}, fmt.Errorf("refreshToken returned status %d", params.Status)
			}
			if params.Token != "" {
				return WSRefreshResult{
					AccessToken:  params.Token,
					RefreshToken: params.RefreshToken,
					ExpireTime:   params.ExpireTime,
					UserID:       params.ID,
				}, nil
			}
		}
	}
}

// wsReadMessage reads a single LSP frame from the websocket and returns the JSON body.
func wsReadMessage(conn *websocket.Conn) ([]byte, error) {
	_, raw, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	text := string(raw)
	if idx := strings.Index(text, "\r\n\r\n"); idx >= 0 {
		return []byte(text[idx+4:]), nil
	}
	return raw, nil
}
