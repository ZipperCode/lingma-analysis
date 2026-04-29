package auth

import (
	"encoding/json"
	"fmt"
	"strings"
)

// UserInfoPayload matches the JSON structure of window.user_info from Lingma's callback page.
type UserInfoPayload struct {
	AID                string `json:"aid"`
	UID                string `json:"uid"`
	Name               string `json:"name"`
	SecurityOauthToken string `json:"securityOauthToken"`
	RefreshToken       string `json:"refreshToken"`
	ExpireTime         int64  `json:"expireTime"`
}

// UserInfoExtracted holds the usable fields extracted from a callback page.
type UserInfoExtracted struct {
	AccessToken   string
	RefreshToken  string
	UserID        string
	Username      string
	MachineID     string
	TokenExpireMs string
}

// ParseUserInfoJSON parses the window.user_info JSON string from Lingma's callback page.
func ParseUserInfoJSON(userInfoJSON string) (UserInfoPayload, error) {
	var payload UserInfoPayload
	if err := json.Unmarshal([]byte(userInfoJSON), &payload); err != nil {
		return UserInfoPayload{}, fmt.Errorf("parse user_info json: %w", err)
	}
	if payload.SecurityOauthToken == "" {
		return UserInfoPayload{}, fmt.Errorf("user_info missing securityOauthToken")
	}
	return payload, nil
}

// ExtractFromCallbackPage parses both window.user_info and window.login_url to produce
// a RemoteLoginConfig ready for credential derivation.
func ExtractFromCallbackPage(userInfoJSON, loginURL string) (UserInfoExtracted, error) {
	payload, err := ParseUserInfoJSON(userInfoJSON)
	if err != nil {
		return UserInfoExtracted{}, err
	}

	machineID := extractMachineIDFromText(loginURL)
	if machineID == "" {
		return UserInfoExtracted{}, fmt.Errorf("could not extract machine_id from login_url")
	}

	expireMs := ""
	if payload.ExpireTime > 0 {
		expireMs = fmt.Sprintf("%d", payload.ExpireTime)
	}

	return UserInfoExtracted{
		AccessToken:   payload.SecurityOauthToken,
		RefreshToken:  payload.RefreshToken,
		UserID:        payload.UID,
		Username:      payload.Name,
		MachineID:     machineID,
		TokenExpireMs: expireMs,
	}, nil
}

// extractMachineIDFromText pulls machine_id out of a URL string, handling URL encoding chains.
func extractMachineIDFromText(raw string) string {
	// First try the URL-based extraction from credential_derive.go
	if mid := extractMachineIDFromLoginURL(raw); mid != "" {
		return mid
	}

	// Fallback: search for machine_id= in the raw text
	idx := strings.Index(raw, "machine_id=")
	if idx < 0 {
		idx = strings.Index(raw, "machine_id%3D") // URL-encoded '='
		if idx < 0 {
			return ""
		}
		// machine_id%3D<VALUE>
		value := raw[idx+len("machine_id%3D"):]
		if end := strings.IndexAny(value, "&'\"%"); end >= 0 {
			value = value[:end]
		}
		return value
	}

	value := raw[idx+len("machine_id="):]
	if end := strings.IndexAny(value, "&'\""); end >= 0 {
		value = value[:end]
	}
	return value
}
