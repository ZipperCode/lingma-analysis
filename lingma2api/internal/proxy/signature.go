package proxy

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type SignatureOptions struct {
	CosyVersion  string
	Now          func() time.Time
	NewRequestID func() string
}

type SignatureEngine struct {
	cosyVersion  string
	now          func() time.Time
	newRequestID func() string
}

func NewSignatureEngine(options SignatureOptions) *SignatureEngine {
	if options.CosyVersion == "" {
		options.CosyVersion = "2.11.2"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewRequestID == nil {
		options.NewRequestID = NewUUID
	}

	return &SignatureEngine{
		cosyVersion:  options.CosyVersion,
		now:          options.Now,
		newRequestID: options.NewRequestID,
	}
}

func (engine *SignatureEngine) BuildBearer(credential CredentialSnapshot, path, body string) (string, string, error) {
	if err := validateSnapshot(credential); err != nil {
		return "", "", err
	}

	date := strconv.FormatInt(engine.now().Unix(), 10)
	payload := map[string]string{
		"cosyVersion": engine.cosyVersion,
		"ideVersion":  "",
		"info":        credential.EncryptUserInfo,
		"requestId":   engine.newRequestID(),
		"version":     "v1",
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	payloadBase64 := base64.StdEncoding.EncodeToString(payloadBytes)
	preimage := strings.Join([]string{
		payloadBase64,
		credential.CosyKey,
		date,
		body,
		normalizePath(path),
	}, "\n")
	signature := md5.Sum([]byte(preimage))

	return fmt.Sprintf("COSY.%s.%x", payloadBase64, signature), date, nil
}

func (engine *SignatureEngine) BuildHeaders(_ context.Context, credential CredentialSnapshot, path, body string) (map[string]string, error) {
	bearer, date, err := engine.BuildBearer(credential, path, body)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Authorization":     "Bearer " + bearer,
		"Content-Type":      "application/json",
		"Appcode":           "cosy",
		"Cosy-Date":         date,
		"Cosy-Key":          credential.CosyKey,
		"Cosy-Machineid":    credential.MachineID,
		"Cosy-User":         credential.UserID,
		"Cosy-Clientip":     "198.18.0.1",
		"Cosy-Clienttype":   "2",
		"Cosy-Machineos":    "x86_64_windows",
		"Cosy-Machinetoken": "",
		"Cosy-Machinetype":  "",
		"Cosy-Version":      engine.cosyVersion,
		"Login-Version":     "v2",
		"User-Agent":        "Go-http-client/1.1",
	}
	if body == "" {
		headers["Accept"] = "application/json"
	} else {
		headers["Accept"] = "text/event-stream"
		headers["Cache-Control"] = "no-cache"
	}
	return headers, nil
}

func normalizePath(path string) string {
	if strings.HasPrefix(path, "/algo") {
		return strings.TrimPrefix(path, "/algo")
	}
	return path
}
