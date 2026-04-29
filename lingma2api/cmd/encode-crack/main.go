package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	refreshURL = "https://lingma-api.tongyi.aliyun.com/algo/api/v3/user/refresh_token"

	// Known keys
	aesKey1     = "QbgzpWzN7tfe43gf"             // Encode=1 AES key
	hexKey      = "9f1dff714a390b20aeb19175ecc496e6" // potential Encode=2 key
	sigKey      = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==" // base64 of "war, war never changes"
	sigKeyAlt   = "&Q3C3!N5mP5bbNcyryMY@KZtUFLRGbTe"

	// Custom base64 alphabet from Lingma
	customBase64Alphabet = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
)

var (
	accessToken  = "pt-LBGnxLfgkfwNhV00Qhl5DqZy"
	refreshToken = "rt-Va49QtAtgJ84tHfa5GGSScW6"
)

func main() {
	fmt.Println("=== Encoding Analyzer for /api/v3/user/refresh_token ===\n")

	// Build the JSON body
	body := map[string]interface{}{
		"securityOauthToken": accessToken,
		"refreshToken":       refreshToken,
		"tokenExpireTime":    1782538198262,
	}
	bodyJSON, _ := json.Marshal(body)
	fmt.Printf("JSON body (%d bytes): %s\n\n", len(bodyJSON), string(bodyJSON))

	// Prepare AES keys
	key1 := []byte(aesKey1) // 16 bytes
	hexKeyBytes, _ := hex.DecodeString(hexKey) // 16 bytes from hex
	md5OfHexKey := md5.Sum([]byte(hexKey)) // 16 raw bytes (MD5 of the hex string as ASCII)

	httpClient := &http.Client{Timeout: 15 * time.Second}
	now := time.Now().UTC()
	rfc1123 := now.Format(time.RFC1123)
	sigPreimage := "cosy&" + sigKey + "&" + rfc1123
	signature := fmt.Sprintf("%x", md5.Sum([]byte(sigPreimage)))

	fmt.Printf("Date: %s\n", rfc1123)
	fmt.Printf("Signature: %s\n\n", signature)

	tests := []struct {
		name    string
		encode  string
		payload string
	}{
		// === Encode=0: plain JSON ===
		{"Encode=0 plain JSON", "0", string(bodyJSON)},

		// === Encode=1: known AES + custom base64 ===
		{"Encode=1 AES(key1)+customB64+scramble", "1", lingmaEncodeAESWithKey(bodyJSON, key1)},

		// === Encode=2 candidates ===
		// Standard base64 only (no AES)
		{"Encode=2 stdB64(JSON)", "2", base64.StdEncoding.EncodeToString(bodyJSON)},
		// Custom base64 only (no AES)
		{"Encode=2 customB64+scramble(JSON)", "2", lingmaEncodeOnly(bodyJSON)},
		// AES(key1) + standard base64
		{"Encode=2 AES(key1)+stdB64", "2", aesEncryptStdB64(bodyJSON, key1)},
		// AES(hexKey) + standard base64
		{"Encode=2 AES(hexKey)+stdB64", "2", aesEncryptStdB64(bodyJSON, hexKeyBytes)},
		// AES(key1) + custom base64 + scramble (same as Encode=1)
		{"Encode=2 AES(key1)+customB64+scramble", "2", lingmaEncodeAESWithKey(bodyJSON, key1)},
		// AES(hexKey) + custom base64 + scramble
		{"Encode=2 AES(hexKey)+customB64+scramble", "2", lingmaEncodeAESWithKey(bodyJSON, hexKeyBytes)},
		// AES(key1) + standard base64 + gzip
		{"Encode=2 gzip+AES(key1)+stdB64", "2", aesEncryptGzipStdB64(bodyJSON, key1)},
		// AES(hexKey as ASCII string = AES-256) + standard base64
		{"Encode=2 AES(hexKey32bytes)+stdB64", "2", aesEncryptStdB64(bodyJSON, []byte(hexKey))},
		// AES(raw MD5 of hexKey = 16 bytes) + standard base64
		{"Encode=2 AES(MD5ofHexKey)+stdB64", "2", aesEncryptStdB64(bodyJSON, md5OfHexKey[:])},
	}

	for i, test := range tests {
		fmt.Printf("[%d/%d] Testing: %s\n", i+1, len(tests), test.name)
		fmt.Printf("  Encode=%s, Payload len=%d\n", test.encode, len(test.payload))

		url := refreshURL + "?Encode=" + test.encode
		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(test.payload))
		if err != nil {
			fmt.Printf("  ERROR: create request: %v\n\n", err)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Appcode", "cosy")
		req.Header.Set("User-Agent", "Go-http-client/1.1")
		req.Header.Set("Date", rfc1123)
		req.Header.Set("Signature", signature)

		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Printf("  ERROR: %v\n\n", err)
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(respBody)
		if len(bodyStr) > 300 {
			bodyStr = bodyStr[:300] + "..."
		}

		fmt.Printf("  HTTP %d: %s\n", resp.StatusCode, bodyStr)

		if resp.StatusCode == 200 {
			fmt.Printf("  >>> SUCCESS! <<<\n")
			fmt.Printf("  Full response: %s\n", string(respBody))
		}
		fmt.Println()
	}
}

// --- AES helper ---

func aesEncryptStdB64(plaintext, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	// Use first 16 bytes of key as IV (CBC mode)
	iv := make([]byte, aes.BlockSize)
	copy(iv, key)
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func aesEncryptGzipStdB64(plaintext, key []byte) string {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(plaintext)
	gw.Close()
	return aesEncryptStdB64(buf.Bytes(), key)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// --- Custom Lingma encoding ---

var stdToCustom [256]byte
var customToStd [256]byte

func init() {
	std := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := range stdToCustom {
		stdToCustom[i] = byte(i)
		customToStd[i] = byte(i)
	}
	for i := 0; i < len(std); i++ {
		stdToCustom[std[i]] = customBase64Alphabet[i]
		customToStd[customBase64Alphabet[i]] = std[i]
	}
}

func lingmaEncodeOnly(data []byte) string {
	stdB64 := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for _, c := range stdB64 {
		sb.WriteByte(stdToCustom[c])
	}
	custom := sb.String()

	// Block scrambling: b2 + pad + b1 + b0
	parts := strings.Split(custom, "=")
	b0 := parts[0]
	padCount := len(parts) - 1
	var padStr string
	if padCount > 0 {
		padStr = custom[len(b0):]
	}

	if len(b0) < 3 {
		return custom
	}
	blockSize := len(b0) / 3
	b1 := b0[:blockSize]
	b2 := b0[blockSize : 2*blockSize]
	b3 := b0[2*blockSize:]

	scrambled := b2 + padStr + b1 + b3
	return scrambled
}

func lingmaEncodeAESWithKey(plaintext, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, key).CryptBlocks(ciphertext, padded)
	return lingmaEncodeOnly(ciphertext)
}
