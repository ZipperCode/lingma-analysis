package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func NewMachineID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("fallback-%d", 0)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

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
