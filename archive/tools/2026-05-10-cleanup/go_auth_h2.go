package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const cosyKey = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="

type AuthBody struct {
	UserId             string `json:"userId"`
	OrgId              string `json:"orgId"`
	SecurityOauthToken string `json:"securityOauthToken"`
	RefreshToken       string `json:"refreshToken"`
}

func main() {
	uid := os.Getenv("LINGMA_USER_ID")
	mid := os.Getenv("LINGMA_MACHINE_ID")
	oat := os.Getenv("LINGMA_OAUTH_TOKEN")
	rft := os.Getenv("LINGMA_REFRESH_TOKEN")
	if uid == "" || oat == "" {
		data, _ := os.ReadFile(os.Getenv("HOME") + "/.lingma/portable_config.json")
		var cfg map[string]interface{}
		json.Unmarshal(data, &cfg)
		if u, ok := cfg["user_id"].(string); ok { uid = u }
		if m, ok := cfg["machine_id"].(string); ok { mid = m }
		if t, ok := cfg["security_oauth_token"].(string); ok { oat = t }
		if r, ok := cfg["refresh_token"].(string); ok { rft = r }
	}

	// Test: POST /api/v3/user/status with signature mode
	body := AuthBody{
		UserId:             uid,
		OrgId:              "",
		SecurityOauthToken: oat,
		RefreshToken:       rft,
	}
	bodyBytes, _ := json.Marshal(body)
	dateStr := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	encodedB64 := base64.StdEncoding.EncodeToString(bodyBytes)
	sigInput := fmt.Sprintf("%s&%s&%s", encodedB64, cosyKey, dateStr)
	signature := fmt.Sprintf("%x", md5.Sum([]byte(sigInput)))

	url := "https://lingma.alibabacloud.com/algo/api/v3/user/status"
	req, _ := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "Cosy/20")
	req.Header.Set("Cosy-MachineId", mid)
	req.Header.Set("Cosy-MachineOS", "x86_64_windows")
	req.Header.Set("Cosy-ClientType", "2")
	req.Header.Set("Cosy-Version", "20")
	req.Header.Set("Date", dateStr)
	req.Header.Set("Cosy-Date", dateStr)
	req.Header.Set("Cosy-User", encodedB64)
	req.Header.Set("Signature", signature)

	// Force HTTP/2 by specifying TLS config that supports h2
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				// Explicitly enable Go 1.23-like cipher suites
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
			},
			ForceAttemptHTTP2: true, // Force HTTP/2
		},
	}

	fmt.Printf("POST %s\n", url)
	fmt.Printf("Date: %s\n", dateStr)
	fmt.Printf("Signature: %s\n", signature)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("HTTP %d (Proto: %s)\n", resp.StatusCode, resp.Proto)
	fmt.Printf("Body: %s\n", string(respBody[:min(len(respBody), 500)]))
	fmt.Printf("Headers:\n")
	for k, v := range resp.Header {
		fmt.Printf("  %s: %s\n", k, v[0])
	}
}

func min(a, b int) int {
	if a < b { return a }; return b
}
