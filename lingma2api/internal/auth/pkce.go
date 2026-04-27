package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func GenerateState() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "bootstrap-fallback"
	}
	return "bootstrap-" + hex.EncodeToString(buf[:])
}

func GeneratePKCE() (string, string) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "fallback-verifier", "fallback-challenge"
	}

	verifier := base64.RawURLEncoding.EncodeToString(buf[:])
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	return verifier, challenge
}
