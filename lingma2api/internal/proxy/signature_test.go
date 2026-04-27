package proxy

import (
	"testing"
	"time"
)

func TestSignatureEngineBuildsExpectedBearer(t *testing.T) {
	engine := NewSignatureEngine(SignatureOptions{
		CosyVersion: "2.11.2",
		Now: func() time.Time {
			return time.Unix(1777045062, 0)
		},
		NewRequestID: func() string {
			return "fixed-request-id"
		},
	})

	bearer, date, err := engine.BuildBearer(CredentialSnapshot{
		CosyKey:         "sentinel-key",
		EncryptUserInfo: "sentinel-info",
		UserID:          "user-1",
		MachineID:       "machine-1",
	}, "/algo/api/v2/model/list", "")
	if err != nil {
		t.Fatalf("BuildBearer() error = %v", err)
	}
	if date != "1777045062" {
		t.Fatalf("unexpected date %q", date)
	}
	if bearer == "" || bearer[:5] != "COSY." {
		t.Fatalf("unexpected bearer %q", bearer)
	}
}
