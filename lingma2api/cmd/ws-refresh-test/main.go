package main

import (
	"fmt"
	"time"

	"lingma2api/internal/auth"
)

func main() {
	cfg := auth.WSRefreshConfig{
		SocketPort:          37010,
		SecurityOauthToken:  "pt-LBGnxLfgkfwNhV00Qhl5DqZy",
		RefreshToken:        "rt-Va49QtAtgJ84tHfa5GGSScW6",
		TokenExpireTime:     1782538198262,
		Timeout:             30 * time.Second,
	}

	fmt.Printf("Attempting WebSocket refresh on port %d...\n", cfg.SocketPort)
	result, err := auth.RefreshTokensViaWebSocket(cfg)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}

	fmt.Printf("SUCCESS!\n")
	fmt.Printf("AccessToken:  %s\n", result.AccessToken)
	fmt.Printf("RefreshToken: %s\n", result.RefreshToken)
	fmt.Printf("ExpireTime:   %d (%s)\n", result.ExpireTime,
		time.UnixMilli(result.ExpireTime).Format(time.RFC3339))
	fmt.Printf("UserID:       %s\n", result.UserID)
}
