package auth

import (
	"encoding/base64"
	"math"
	"strings"
)

const (
	encode1Alpha  = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
	encode1StdB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

var (
	alphaToStd [256]byte
	stdToAlpha [256]byte
)

func init() {
	for i := range alphaToStd {
		alphaToStd[i] = 255
		stdToAlpha[i] = 255
	}
	for i := 0; i < len(encode1Alpha); i++ {
		alphaToStd[encode1Alpha[i]] = encode1StdB64[i]
	}
	for i := 0; i < len(encode1StdB64); i++ {
		stdToAlpha[encode1StdB64[i]] = encode1Alpha[i]
	}
}

func lingmaEncode(data []byte) string {
	std := base64.StdEncoding.EncodeToString(data)
	std = strings.TrimRight(std, "=")

	var custom strings.Builder
	custom.Grow(len(std))
	for i := 0; i < len(std); i++ {
		custom.WriteByte(stdToAlpha[std[i]])
	}
	encoded := custom.String()

	e := len(encoded)
	bs := int(math.Ceil(float64(e) / 3.0))
	pad := (4 - e%4) % 4

	b0 := encoded[:bs]
	var b1, b2 string
	if 2*bs <= e {
		b1 = encoded[bs : 2*bs]
		b2 = encoded[2*bs:]
	} else if bs < e {
		b1 = encoded[bs:]
	}

	return b2 + strings.Repeat("$", pad) + b1 + b0
}

func lingmaDecode(body string) []byte {
	dollarStart := strings.IndexByte(body, '$')
	var rev string

	if dollarStart < 0 {
		rev = body
	} else {
		pad := 0
		pos := dollarStart
		for pos < len(body) && body[pos] == '$' {
			pad++
			pos++
		}
		rev = body[:dollarStart] + body[dollarStart+pad:]
		_ = pad
	}

	e := len(rev)
	bs := int(math.Ceil(float64(e) / 3.0))
	lb := e - 2*bs
	if lb < 0 {
		lb = 0
	}

	b2 := rev[:lb]
	b1End := lb + bs
	if b1End > e {
		b1End = e
	}
	b1 := rev[lb:b1End]
	b0 := rev[b1End:]

	reordered := b0 + b1 + b2

	var converted strings.Builder
	converted.Grow(len(reordered))
	for i := 0; i < len(reordered); i++ {
		b := alphaToStd[reordered[i]]
		if b != 255 {
			converted.WriteByte(b)
		}
	}

	stdStr := converted.String()
	missing := (4 - len(stdStr)%4) % 4
	stdStr += strings.Repeat("=", missing)

	decoded, err := base64.StdEncoding.DecodeString(stdStr)
	if err != nil {
		return nil
	}
	return decoded
}

func LingmaEncode(data []byte) string {
	return lingmaEncode(data)
}

func LingmaDecode(body string) []byte {
	return lingmaDecode(body)
}

func LingmaEncodeAES(plaintext, aesKey []byte) (string, error) {
	return lingmaEncodeAES(plaintext, aesKey)
}

func lingmaEncodeAES(plaintext, aesKey []byte) (string, error) {
	encrypted, err := EncryptCacheUser(string(aesKey), plaintext)
	if err != nil {
		return "", err
	}
	return lingmaEncode(encrypted), nil
}

func lingmaDecodeAES(encoded string, aesKey []byte) ([]byte, error) {
	decoded := lingmaDecode(encoded)
	if decoded == nil {
		return nil, nil
	}
	return DecryptCacheUser(string(aesKey), decoded)
}
