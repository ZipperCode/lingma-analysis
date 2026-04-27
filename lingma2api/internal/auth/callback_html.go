package auth

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	userInfoPattern = regexp.MustCompile(`window\.user_info = '([^']+)';`)
	loginURLPattern = regexp.MustCompile(`window\.login_url = '([^']+)';`)
)

type CallbackHTMLHints struct {
	LoginURL            string
	MachineID           string
	SecurityOAuthToken  string
	RefreshToken        string
	ExpireTime          int64
}

func ParseCallbackHTMLHints(raw []byte) (CallbackHTMLHints, error) {
	text := string(raw)

	var hints CallbackHTMLHints

	userMatch := userInfoPattern.FindStringSubmatch(text)
	if len(userMatch) == 2 {
		var payload struct {
			SecurityOAuthToken string `json:"securityOauthToken"`
			RefreshToken       string `json:"refreshToken"`
			ExpireTime         int64  `json:"expireTime"`
		}
		if err := json.Unmarshal([]byte(userMatch[1]), &payload); err != nil {
			return CallbackHTMLHints{}, err
		}
		hints.SecurityOAuthToken = payload.SecurityOAuthToken
		hints.RefreshToken = payload.RefreshToken
		hints.ExpireTime = payload.ExpireTime
	}

	loginMatch := loginURLPattern.FindStringSubmatch(text)
	if len(loginMatch) == 2 {
		hints.LoginURL = loginMatch[1]
		hints.MachineID = extractMachineIDFromURL(hints.LoginURL)
	}

	if hints.LoginURL == "" && hints.SecurityOAuthToken == "" {
		return CallbackHTMLHints{}, errors.New("no callback html hints found")
	}
	return hints, nil
}

func extractMachineIDFromURL(raw string) string {
	current := raw
	for range 5 {
		decoded, err := url.QueryUnescape(current)
		if err != nil || decoded == current {
			break
		}
		current = decoded
	}

	parsed, err := url.Parse(current)
	if err == nil {
		if machineID := parsed.Query().Get("machine_id"); machineID != "" {
			return machineID
		}
	}

	if idx := strings.Index(current, "machine_id="); idx >= 0 {
		value := current[idx+len("machine_id="):]
		if end := strings.IndexAny(value, "&'\""); end >= 0 {
			value = value[:end]
		}
		return value
	}
	return ""
}
