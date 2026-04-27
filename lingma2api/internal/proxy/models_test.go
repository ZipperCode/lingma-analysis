package proxy

import (
	"context"
	"testing"
)

type stubTransport struct {
	models []RemoteModel
}

func (transport stubTransport) ListModels(_ context.Context, _ CredentialSnapshot) ([]RemoteModel, error) {
	return transport.models, nil
}

type stubCredentialReader struct{}

func (stubCredentialReader) Current(_ context.Context) (CredentialSnapshot, error) {
	return CredentialSnapshot{
		CosyKey:         "k",
		EncryptUserInfo: "info",
		UserID:          "u",
		MachineID:       "m",
	}, nil
}

func TestResolveChatModelMapsAutoToEmptyKey(t *testing.T) {
	service := NewModelService(stubTransport{
		models: []RemoteModel{{Key: "dashscope_qwen3_coder"}},
	}, stubCredentialReader{}, DefaultAliases(), nil)

	got, err := service.ResolveChatModel(context.Background(), "auto")
	if err != nil {
		t.Fatalf("ResolveChatModel() error = %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty key, got %q", got)
	}
}
