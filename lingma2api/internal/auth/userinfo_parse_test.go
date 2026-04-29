package auth

import "testing"

func TestParseUserInfoJSON_Valid(t *testing.T) {
	raw := `{"aid":"5930676910898027","uid":"5930676910898027","name":"zhang640@blny.de","securityOauthToken":"pt-5zmkcs3cUpPGP8FGb88WGkSJ","refreshToken":"rt-gHWjpgS9NQ4TOhmtvmN55ELZ","expireTime":1782107060847}`
	payload, err := ParseUserInfoJSON(raw)
	if err != nil {
		t.Fatalf("ParseUserInfoJSON: %v", err)
	}
	if payload.SecurityOauthToken != "pt-5zmkcs3cUpPGP8FGb88WGkSJ" {
		t.Errorf("token: got %q", payload.SecurityOauthToken)
	}
	if payload.RefreshToken != "rt-gHWjpgS9NQ4TOhmtvmN55ELZ" {
		t.Errorf("refresh: got %q", payload.RefreshToken)
	}
	if payload.UID != "5930676910898027" {
		t.Errorf("uid: got %q", payload.UID)
	}
	if payload.ExpireTime != 1782107060847 {
		t.Errorf("expireTime: got %d", payload.ExpireTime)
	}
}

func TestParseUserInfoJSON_EmptyToken(t *testing.T) {
	_, err := ParseUserInfoJSON(`{"uid":"123","name":"test","securityOauthToken":""}`)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestParseUserInfoJSON_InvalidJSON(t *testing.T) {
	_, err := ParseUserInfoJSON(`not json`)
	if err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestExtractFromCallbackPage_Full(t *testing.T) {
	userInfo := `{"aid":"5930676910898027","uid":"5930676910898027","name":"test@example.com","securityOauthToken":"pt-test-token","refreshToken":"rt-test-refresh","expireTime":1782107060847}`
	loginURL := "https://lingma.alibabacloud.com/lingma/login?state=abc&challenge=xyz&challenge_method=S256&machine_id=43303747-3630-492d-8151-366d4e59432d&nonce=abc&port=37510"

	result, err := ExtractFromCallbackPage(userInfo, loginURL)
	if err != nil {
		t.Fatalf("ExtractFromCallbackPage: %v", err)
	}
	if result.AccessToken != "pt-test-token" {
		t.Errorf("AccessToken: got %q", result.AccessToken)
	}
	if result.MachineID != "43303747-3630-492d-8151-366d4e59432d" {
		t.Errorf("MachineID: got %q", result.MachineID)
	}
	if result.TokenExpireMs != "1782107060847" {
		t.Errorf("TokenExpireMs: got %q", result.TokenExpireMs)
	}
}

func TestExtractFromCallbackPage_NoMachineID(t *testing.T) {
	_, err := ExtractFromCallbackPage(
		`{"securityOauthToken":"pt-test"}`,
		"https://example.com/no-machine-id?foo=bar",
	)
	if err == nil {
		t.Fatal("expected error for missing machine_id")
	}
}
