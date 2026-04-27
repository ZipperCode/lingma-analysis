package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lingma2api/internal/proxy"
)

type fakeCredentials struct{}

func (fakeCredentials) Current(context.Context) (proxy.CredentialSnapshot, error) {
	return proxy.CredentialSnapshot{
		CosyKey:         "k",
		EncryptUserInfo: "info",
		UserID:          "u",
		MachineID:       "m",
	}, nil
}

func (fakeCredentials) Refresh(context.Context) (proxy.CredentialSnapshot, error) {
	return fakeCredentials{}.Current(context.Background())
}

func (fakeCredentials) Status() proxy.CredentialStatus {
	return proxy.CredentialStatus{Loaded: true, HasCredentials: true}
}

type fakeModels struct{}

func (fakeModels) ResolveChatModel(context.Context, string) (string, error) {
	return "", nil
}

func (fakeModels) ListModels(context.Context) ([]proxy.OpenAIModel, error) {
	return []proxy.OpenAIModel{{ID: "auto", Object: "model", OwnedBy: "lingma"}}, nil
}

func (fakeModels) Refresh(context.Context) error { return nil }

func (fakeModels) Status() proxy.ModelStatus {
	return proxy.ModelStatus{Cached: true, Count: 1}
}

type fakeSessions struct{}

func (fakeSessions) BuildMessages(_ context.Context, _ string, messages []proxy.Message) ([]proxy.Message, error) {
	return messages, nil
}

func (fakeSessions) SaveResponse(context.Context, string, []proxy.Message, proxy.Message) error {
	return nil
}

func (fakeSessions) Delete(context.Context, string) error { return nil }

func (fakeSessions) List(context.Context) ([]proxy.SessionState, error) {
	return []proxy.SessionState{{ID: "s1", MessageCount: 1}}, nil
}

func (fakeSessions) SweepExpired(context.Context) error { return nil }

type fakeTransport struct {
	lines []string
}

func (transport fakeTransport) StreamChat(context.Context, proxy.RemoteChatRequest, proxy.CredentialSnapshot) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(strings.Join(transport.lines, "\n"))), nil
}

type fakeBuilder struct{}

func (fakeBuilder) Build(request proxy.OpenAIChatRequest, _ []proxy.Message, modelKey string) (proxy.RemoteChatRequest, error) {
	return proxy.RemoteChatRequest{
		Path:      proxy.ChatPath,
		Query:     proxy.ChatQuery,
		RequestID: "req-1",
		ModelKey:  modelKey,
		Stream:    request.Stream,
	}, nil
}

func TestChatCompletionsNonStreamReturnsOpenAIResponse(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport: fakeTransport{
			lines: []string{
				`data:{"body":"{\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}","statusCodeValue":200}`,
				`data:{"body":"{\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}","statusCodeValue":200}`,
				`data:[DONE]`,
			},
		},
		Builder: fakeBuilder{},
		Now:     func() time.Time { return time.Unix(1, 0) },
	})

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"auto","messages":[{"role":"user","content":"hi"}],"stream":false}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"content":"Hello"`) {
		t.Fatalf("unexpected body %s", recorder.Body.String())
	}
}

func TestAdminRefreshRequiresTokenWhenConfigured(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport:   fakeTransport{},
		Builder:     fakeBuilder{},
		AdminToken:  "secret",
	})

	request := httptest.NewRequest(http.MethodPost, "/admin/refresh", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestAdminRefreshReturnsNotImplementedWithoutRefreshFlow(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport:   fakeTransport{},
		Builder:     fakeBuilder{},
	})

	request := httptest.NewRequest(http.MethodPost, "/admin/refresh", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", recorder.Code)
	}
}
