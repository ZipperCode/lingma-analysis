package proxy

import "testing"

func TestParseCurlResponseSeparatesHeadersAndBody(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"chat\":[]}")
	status, body, err := parseCurlResponse(raw)
	if err != nil {
		t.Fatalf("parseCurlResponse() error = %v", err)
	}
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if string(body) != "{\"chat\":[]}" {
		t.Fatalf("unexpected body %q", string(body))
	}
}
