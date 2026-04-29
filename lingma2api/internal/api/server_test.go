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
	}, nil)

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
	}, nil)

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
	}, nil)

	request := httptest.NewRequest(http.MethodPost, "/admin/refresh", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", recorder.Code)
	}
}

func TestChatCompletionsRejectsToolMessageWithoutToolCallID(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport:   fakeTransport{},
		Builder:     fakeBuilder{},
	}, nil)

	body := `{"model":"auto","messages":[{"role":"tool","content":"result"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for tool message without tool_call_id, got %d", recorder.Code)
	}
}

func TestChatCompletionsAllowsAssistantWithToolCalls(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport: fakeTransport{
			lines: []string{`data:{"body":"{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}","statusCodeValue":200}`, `data:[DONE]`},
		},
		Builder: fakeBuilder{},
		Now:     func() time.Time { return time.Unix(1, 0) },
	}, nil)

	body := `{"model":"auto","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{}"}}]},{"role":"tool","content":"result","tool_call_id":"c1"}],"stream":false}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid tool message chain, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestChatCompletionsRejectsToolCallWithoutFunctionName(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport:   fakeTransport{},
		Builder:     fakeBuilder{},
	}, nil)

	body := `{"model":"auto","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"","arguments":"{}"}}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for tool_call without function name, got %d", recorder.Code)
	}
}

func TestChatCompletionsStripsEmptyNameToolCallsFromHistory(t *testing.T) {
	// Mixed history: one valid tool_call + two empty-name fragments from a streaming bug.
	// The proxy should silently strip the fragments and process the valid call.
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport:   fakeTransport{},
		Builder:     fakeBuilder{},
	}, nil)

	body := `{"model":"auto","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"search","arguments":"{\"q\":\"x\"}"}},{"id":"","type":"function","function":{"name":"","arguments":""}}]}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 after stripping empty-name tool_calls, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestChatCompletionsStreamWithToolCalls(t *testing.T) {
	handler := NewServer(Dependencies{
		Credentials: fakeCredentials{},
		Models:      fakeModels{},
		Sessions:    fakeSessions{},
		Transport: fakeTransport{
			lines: []string{
				`data:{"body":"{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c2\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"\"}}]}}]}","statusCodeValue":200}`,
				`data:{"body":"{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"main.go\\\"}\"}}]}}]}","statusCodeValue":200}`,
				`data:[DONE]`,
			},
		},
		Builder: fakeBuilder{},
		Now:     func() time.Time { return time.Unix(1, 0) },
	}, nil)

	body := `{"model":"auto","messages":[{"role":"user","content":"read main.go"}],"stream":true}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	responseBody := recorder.Body.String()
	if !strings.Contains(responseBody, `"tool_calls"`) {
		t.Fatalf("expected tool_calls in SSE response, got: %s", responseBody)
	}
	if !strings.Contains(responseBody, `"read_file"`) {
		t.Fatalf("expected read_file function name, got: %s", responseBody)
	}
	// Continuation fragments with empty name should not produce a separate tool_call.
	if strings.Contains(responseBody, `"name":""`) {
		t.Fatalf("unexpected empty name tool_call leaked to client: %s", responseBody)
	}
}

func TestChatCompletionsStreamWithContentOnlyNoToolCalls(t *testing.T) {
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
	}, nil)

	body := `{"model":"auto","messages":[{"role":"user","content":"hi"}],"stream":true}`
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"content":"Hel"`) {
		t.Fatalf("expected content in SSE, got: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"tool_calls"`) {
		t.Fatalf("unexpected tool_calls in content-only response: %s", recorder.Body.String())
	}
}
