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

const (
	cosyKey    = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
	endpoint   = "https://lingma.alibabacloud.com/algo"
	statusPath = "/api/v3/user/status"
)

func readCredentials() map[string]string {
	// Try env vars first
	creds := map[string]string{
		"uid":           os.Getenv("LINGMA_USER_ID"),
		"machine_id":    os.Getenv("LINGMA_MACHINE_ID"),
		"oauth_token":   os.Getenv("LINGMA_OAUTH_TOKEN"),
		"refresh_token": os.Getenv("LINGMA_REFRESH_TOKEN"),
	}
	if creds["uid"] != "" && creds["oauth_token"] != "" {
		return creds
	}

	// Try credential extractor output via stdin or embedded config
	// Fallback: read portable_config.json
	data, err := os.ReadFile(os.Getenv("HOME") + "/.lingma/portable_config.json")
	if err == nil {
		var cfg map[string]interface{}
		json.Unmarshal(data, &cfg)
		if u, ok := cfg["user_id"].(string); ok {
			creds["uid"] = u
		}
		if m, ok := cfg["machine_id"].(string); ok {
			creds["machine_id"] = m
		}
		if t, ok := cfg["security_oauth_token"].(string); ok {
			creds["oauth_token"] = t
		}
		if r, ok := cfg["refresh_token"].(string); ok {
			creds["refresh_token"] = r
		}
		if creds["uid"] != "" && creds["oauth_token"] != "" {
			return creds
		}
	}
	return creds
}

func rfc1123Date() string {
	return time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}

type StatusBody struct {
	Ak                 string `json:"ak"`
	Sk                 string `json:"sk"`
	SecurityToken      string `json:"securityToken"`
	UserID             string `json:"userId"`
	OrgID              string `json:"orgId"`
	Token              string `json:"token"`
	PersonalToken      string `json:"personalToken"`
	SecurityOauthToken string `json:"securityOauthToken"`
	RefreshToken       string `json:"refreshToken"`
	NeedRefresh        bool   `json:"needRefresh"`
	AuthInfo           struct {
		UserName string `json:"userName"`
		OrgID    string `json:"orgId"`
	} `json:"authInfo"`
}

func main() {
	creds := readCredentials()
	if creds["uid"] == "" || creds["machine_id"] == "" || creds["oauth_token"] == "" {
		fmt.Println("Missing credentials. Set LINGMA_USER_ID, LINGMA_MACHINE_ID, LINGMA_OAUTH_TOKEN")
		fmt.Println("Or run: python tools/credential_extractor.py --save")
		os.Exit(1)
	}

	fmt.Printf("UserID: %s\n", creds["uid"])
	fmt.Printf("MachineID: %s\n", creds["machine_id"])
	oauthPreview := creds["oauth_token"]
	if len(oauthPreview) > 30 {
		oauthPreview = oauthPreview[:30] + "..."
	}
	fmt.Printf("OAuthToken: %s\n", oauthPreview)

	// Build body
	body := StatusBody{
		Ak:                 "",
		Sk:                 "",
		SecurityToken:      "",
		UserID:             creds["uid"],
		OrgID:              "",
		Token:              "",
		PersonalToken:      "",
		SecurityOauthToken: creds["oauth_token"],
		RefreshToken:       creds["refresh_token"],
		NeedRefresh:        false,
	}
	body.AuthInfo.UserName = ""
	body.AuthInfo.OrgID = ""

	bodyBytes, _ := json.Marshal(body)
	dateStr := rfc1123Date()

	// Signature: MD5(base64(body) + "&" + key + "&" + date)
	encodedB64 := base64.StdEncoding.EncodeToString(bodyBytes)
	sigInput := fmt.Sprintf("%s&%s&%s", encodedB64, cosyKey, dateStr)
	signature := fmt.Sprintf("%x", md5.Sum([]byte(sigInput)))

	fmt.Printf("\nDate: %s\n", dateStr)
	fmt.Printf("Signature: %s\n", signature)

	// Build request
	url := endpoint + statusPath
	req, _ := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "Cosy/20")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("Cosy-MachineId", creds["machine_id"])
	req.Header.Set("Cosy-MachineToken", "")
	req.Header.Set("Cosy-MachineType", "")
	req.Header.Set("Cosy-MachineCode", "")
	req.Header.Set("Cosy-MachineOS", "x86_64_windows")
	req.Header.Set("Cosy-ClientType", "2")
	req.Header.Set("Cosy-Version", "20")
	req.Header.Set("Date", dateStr)
	req.Header.Set("Cosy-Date", dateStr)
	req.Header.Set("Cosy-User", encodedB64)
	req.Header.Set("Signature", signature)

	// Go HTTP client with standard TLS (same as Lingma)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	fmt.Printf("\nPOST %s\n", url)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("HTTP %d\n", resp.StatusCode)
	fmt.Printf("Proto: %s\n", resp.Proto)

	// Try decompress if gzip
	if len(respBody) > 2 && respBody[0] == 0x1f && respBody[1] == 0x8b {
		fmt.Printf("Body (gzipped): %x...\n", respBody[:50])
	} else {
		fmt.Printf("Body: %s\n", string(respBody[:min(len(respBody), 500)]))
	}

	fmt.Printf("\nResponse Headers:\n")
	for k, v := range resp.Header {
		val := v[0]
		if len(val) > 60 {
			val = val[:60] + "..."
		}
		fmt.Printf("  %s: %s\n", k, val)
	}

	if resp.StatusCode == 200 {
		fmt.Printf("\n✅ SUCCESS! Go TLS fingerprint bypassed WAF!\n")
		// Parse and display the COSY credentials
		var result map[string]interface{}
		if json.Unmarshal(respBody, &result) == nil {
			fmt.Printf("Response: %s\n", string(respBody))
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
