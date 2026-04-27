package auth

import (
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"
)

func TestBuildAuthorizeURLIncludesStateAndChallenge(t *testing.T) {
	url, state, verifier, err := BuildAuthorizeURL(AuthorizeConfig{
		ClientID:    "client-123",
		RedirectURL: "http://127.0.0.1:38080/callback",
	})
	if err != nil {
		t.Fatalf("BuildAuthorizeURL() error = %v", err)
	}
	if state == "" {
		t.Fatal("expected state")
	}
	if verifier == "" {
		t.Fatal("expected verifier")
	}
	if !strings.Contains(url, "code_challenge=") {
		t.Fatalf("expected code challenge in url: %s", url)
	}
	if !strings.Contains(url, "client_id=client-123") {
		t.Fatalf("expected client_id in url: %s", url)
	}
}

func TestBuildLingmaLoginEntryURL(t *testing.T) {
	loginURL, state, verifier, err := BuildLingmaLoginEntryURL(LingmaLoginEntryConfig{
		MachineID: "abc-123",
		Port:      "37510",
	})
	if err != nil {
		t.Fatalf("BuildLingmaLoginEntryURL() error = %v", err)
	}
	if state == "" {
		t.Fatal("expected state")
	}
	if verifier == "" {
		t.Fatal("expected verifier")
	}
	if !strings.HasPrefix(loginURL, "https://lingma.alibabacloud.com/lingma/login?") {
		t.Fatalf("unexpected base url: %s", loginURL)
	}
	parsed, err := neturl.Parse(loginURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	q := parsed.Query()
	if q.Get("machine_id") != "abc-123" {
		t.Errorf("machine_id: got %q, want abc-123", q.Get("machine_id"))
	}
	if q.Get("port") != "37510" {
		t.Errorf("port: got %q, want 37510", q.Get("port"))
	}
	if q.Get("challenge_method") != "S256" {
		t.Errorf("challenge_method: got %q, want S256", q.Get("challenge_method"))
	}
	if q.Get("challenge") == "" {
		t.Error("challenge missing")
	}
	if q.Get("nonce") == "" {
		t.Error("nonce missing")
	}
}

func TestBuildLingmaLoginEntryURL_MissingPort(t *testing.T) {
	_, _, _, err := BuildLingmaLoginEntryURL(LingmaLoginEntryConfig{
		MachineID: "abc-123",
	})
	if err == nil {
		t.Fatal("expected error when port missing")
	}
}

func TestBuildLingmaLoginEntryURL_AutoMachineID(t *testing.T) {
	loginURL, _, _, err := BuildLingmaLoginEntryURL(LingmaLoginEntryConfig{
		Port: "37510",
	})
	if err != nil {
		t.Fatalf("BuildLingmaLoginEntryURL() error = %v", err)
	}
	parsed, err := neturl.Parse(loginURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	machineID := parsed.Query().Get("machine_id")
	if machineID == "" {
		t.Fatal("expected auto-generated machine_id")
	}
	if !strings.Contains(machineID, "-") {
		t.Errorf("expected UUID format, got %q", machineID)
	}
}

func TestWrapLingmaLoginURLForBrowser(t *testing.T) {
	input := "https://lingma.alibabacloud.com/lingma/login?port=37510&state=2-abc&challenge=xyz"
	output, err := WrapLingmaLoginURLForBrowser(input)
	if err != nil {
		t.Fatalf("WrapLingmaLoginURLForBrowser() error = %v", err)
	}
	if !strings.Contains(output, "https://account.alibabacloud.com/logout/logout.htm?oauth_callback=") {
		t.Fatalf("unexpected wrapped url %s", output)
	}
	if !strings.Contains(output, "https%253A%252F%252Flingma.alibabacloud.com%252Flingma%252Flogin") {
		t.Fatalf("expected encoded lingma login in wrapped url %s", output)
	}
}

func TestRewriteLingmaLoginURLPort(t *testing.T) {
	input := "https://lingma.alibabacloud.com/lingma/login?port=37510&state=2-abc&challenge=xyz"
	output, err := RewriteLingmaLoginURLPort(input, "127.0.0.1:37988")
	if err != nil {
		t.Fatalf("RewriteLingmaLoginURLPort() error = %v", err)
	}
	if !strings.Contains(output, "port=37988") {
		t.Fatalf("expected rewritten port in %s", output)
	}
}

func TestCaptureFromRequestReadsQuery(t *testing.T) {
	request := httptest.NewRequest("GET", "http://127.0.0.1:38081/callback?code=abc&state=xyz", nil)
	result := CaptureFromRequest(request)

	if result.Query.Get("code") != "abc" {
		t.Fatalf("expected code abc, got %q", result.Query.Get("code"))
	}
	if result.Query.Get("state") != "xyz" {
		t.Fatalf("expected state xyz, got %q", result.Query.Get("state"))
	}
}
