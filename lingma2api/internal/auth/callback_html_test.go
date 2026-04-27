package auth

import "testing"

func TestParseCallbackHTMLHints(t *testing.T) {
	raw := []byte(`
<script>
window.user_info = '{"securityOauthToken":"pt-test","refreshToken":"rt-test","expireTime":1782107060847}';
window.login_url = 'https://account.alibabacloud.com/logout/logout.htm?oauth_callback=https%3A%2F%2Flingma.alibabacloud.com%2Flingma%2Flogin%3Fstate%3D2-abc%26challenge%3Dxyz%26challenge_method%3DS256%26machine_id%3D43303747-3630-492d-8151-366d4e59432d%26nonce%3Dabc%26port%3D37510';
</script>
`)

	hints, err := ParseCallbackHTMLHints(raw)
	if err != nil {
		t.Fatalf("ParseCallbackHTMLHints() error = %v", err)
	}
	if hints.SecurityOAuthToken != "pt-test" {
		t.Fatalf("expected security token, got %q", hints.SecurityOAuthToken)
	}
	if hints.RefreshToken != "rt-test" {
		t.Fatalf("expected refresh token, got %q", hints.RefreshToken)
	}
	if hints.MachineID != "43303747-3630-492d-8151-366d4e59432d" {
		t.Fatalf("expected machine id, got %q", hints.MachineID)
	}
}
