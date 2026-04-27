package auth

import (
	"net/http/httptest"
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
