package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"lingma2api/internal/auth"
)

func main() {
	freshRefreshToken := "rt-Va49QtAtgJ84tHfa5GGSScW6"
	freshAccessToken := "pt-LBGnxLfgkfwNhV00Qhl5DqZy"
	userID := "5930676910898027"
	machineID := "43303747-3630-492d-8151-366d4e59432d"

	key := "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="
	client := &http.Client{Timeout: 15 * time.Second}

	makeSig := func() (string, string) {
		rfc := time.Now().UTC().Format(time.RFC1123)
		return rfc, fmt.Sprintf("%x", md5.Sum([]byte("cosy&"+key+"&"+rfc)))
	}

	send := func(encName, path, bodyStr string) {
		rfc, sig := makeSig()
		req, _ := http.NewRequest("POST", "https://lingma-api.tongyi.aliyun.com"+path,
			strings.NewReader(bodyStr))
		req.Header.Set("Host", "lingma-api.tongyi.aliyun.com")
		req.Header.Set("Date", rfc)
		req.Header.Set("Signature", sig)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Appcode", "cosy")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[%s] %s: err %v\n", encName, path, err)
			return
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bs := string(respBody)
		if len(bs) > 500 {
			bs = bs[:500]
		}
		if resp.StatusCode != 500 || !strings.Contains(bs, "Internal Server Error") {
			fmt.Printf("[%s] %s: %d - %s\n", encName, path, resp.StatusCode, bs)
		}
	}

	testBody := func(name, bodyStr string) {
		// Encode=0: plain text
		send(name+"-plain-E0", "/algo/api/v3/user/refresh_token?Encode=0", bodyStr)

		// Encode=1: lingmaEncode only
		send(name+"-lingma-E1", "/algo/api/v3/user/refresh_token?Encode=1",
			auth.LingmaEncode([]byte(bodyStr)))

		// Encode=1: AES+lingmaEncode
		enc, _ := auth.LingmaEncodeAES([]byte(bodyStr), []byte("QbgzpWzN7tfe43gf"))
		send(name+"-aesLingma-E1", "/algo/api/v3/user/refresh_token?Encode=1", enc)

		// Encode=1: standard base64
		send(name+"-stdB64-E1", "/algo/api/v3/user/refresh_token?Encode=1",
			base64.StdEncoding.EncodeToString([]byte(bodyStr)))

		// Also test login endpoint with Encode=1
		send(name+"-aesLingma-E1-login", "/algo/api/v3/user/login?Encode=1", enc)
	}

	// Body 1: refreshToken only
	b1, _ := json.Marshal(map[string]string{"refreshToken": freshRefreshToken})
	testBody("refreshOnly", string(b1))

	// Body 2: full
	b2, _ := json.Marshal(map[string]string{
		"token": freshAccessToken, "refreshToken": freshRefreshToken,
		"userId": userID, "machineId": machineID,
	})
	testBody("full", string(b2))

	fmt.Println("Done!")
}
