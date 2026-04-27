package auth

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestLingmaEncodeDecode_RoundTrip(t *testing.T) {
	tests := [][]byte{
		[]byte("hello"),
		[]byte(`{"test":"value"}`),
		make([]byte, 16),
		make([]byte, 64),
		make([]byte, 100),
	}

	for i, plain := range tests {
		for j := range plain {
			plain[j] = byte('a' + j%26)
		}

		encoded := lingmaEncode(plain)
		decoded := lingmaDecode(encoded)

		if string(decoded) != string(plain) {
			t.Errorf("round-trip test %d (len=%d): mismatch", i, len(plain))
			t.Logf("  encoded: %s", encoded[:min(40, len(encoded))])
		}
	}
}

func TestLingmaEncode_Charset(t *testing.T) {
	data := []byte(`{"key":"value","number":42}`)
	encoded := lingmaEncode(data)

	for _, c := range encoded {
		if c == '$' {
			continue
		}
		if !strings.ContainsRune(encode1Alpha, c) {
			t.Errorf("char %c not in custom alphabet", c)
		}
	}
}

func TestLingmaEncode_Length(t *testing.T) {
	data := []byte(`{"test":"data"}`)
	encoded := lingmaEncode(data)

	if len(encoded)%4 != 0 {
		t.Errorf("encoded length %d not divisible by 4", len(encoded))
	}
}

func TestLingmaEncode_KnownVector(t *testing.T) {
	data := []byte("test")
	encoded := lingmaEncode(data)

	decoded := lingmaDecode(encoded)
	if string(decoded) != "test" {
		t.Errorf("known vector fail: got %q", string(decoded))
	}
}

func TestLingmaDecode_Garbage(t *testing.T) {
	result := lingmaDecode("!!!invalid!!!")
	if result != nil {
		t.Errorf("expected nil for garbage input")
	}
}

func TestLingmaEncodeAES_RoundTrip(t *testing.T) {
	plaintext := []byte(`{"token":"pt-test","refreshToken":"rt-test"}`)
	aesKey := []byte("QbgzpWzN7tfe43gf")

	encoded, err := lingmaEncodeAES(plaintext, aesKey)
	if err != nil {
		t.Fatalf("lingmaEncodeAES: %v", err)
	}

	if len(encoded) < 10 {
		t.Errorf("encoded too short: %d", len(encoded))
	}

	decoded, err := lingmaDecodeAES(encoded, aesKey)
	if err != nil {
		t.Fatalf("lingmaDecodeAES: %v", err)
	}

	if string(decoded) != string(plaintext) {
		t.Errorf("AES round-trip mismatch: got %q, want %q", string(decoded), string(plaintext))
	}
}

func TestLingmaDecode_InvalidBase64(t *testing.T) {
	encoded := lingmaEncode([]byte("test"))

	mangled := strings.Replace(encoded, string(encode1Alpha[0]), "#", 1)
	result := lingmaDecode(mangled)
	if result == nil {
		t.Log("correctly returned nil for mangled input")
	}
}

func TestLingmaEncodeVsStdBase64(t *testing.T) {
	data := []byte("hello world")
	encoded := lingmaEncode(data)
	stdEncoded := base64.StdEncoding.EncodeToString(data)

	if encoded == stdEncoded {
		t.Error("encoded should differ from standard base64")
	}
}
