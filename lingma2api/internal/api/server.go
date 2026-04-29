package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lingma2api/internal/db"
	"lingma2api/internal/middleware"
	"lingma2api/internal/proxy"
)

type CredentialProvider interface {
	Current(context.Context) (proxy.CredentialSnapshot, error)
	Refresh(context.Context) (proxy.CredentialSnapshot, error)
	Status() proxy.CredentialStatus
}

type ModelService interface {
	ResolveChatModel(context.Context, string) (string, error)
	ListModels(context.Context) ([]proxy.OpenAIModel, error)
	Refresh(context.Context) error
	Status() proxy.ModelStatus
}

type SessionStore interface {
	BuildMessages(context.Context, string, []proxy.Message) ([]proxy.Message, error)
	SaveResponse(context.Context, string, []proxy.Message, proxy.Message) error
	Delete(context.Context, string) error
	List(context.Context) ([]proxy.SessionState, error)
	SweepExpired(context.Context) error
}

type ChatTransport interface {
	StreamChat(context.Context, proxy.RemoteChatRequest, proxy.CredentialSnapshot) (io.ReadCloser, error)
}

type RequestBuilder interface {
	Build(proxy.OpenAIChatRequest, []proxy.Message, string) (proxy.RemoteChatRequest, error)
}

type Dependencies struct {
	Credentials CredentialProvider
	Models      ModelService
	Sessions    SessionStore
	Transport   ChatTransport
	Builder     RequestBuilder
	AdminToken  string
	Now         func() time.Time
	FrontendFS  embed.FS
	Bootstrap   *BootstrapManager
}

type Server struct {
	deps Dependencies
	db   *db.Store
}

type chatCompletionResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Created int64                  `json:"created"`
	Model   string                 `json:"model"`
	Choices []chatCompletionChoice `json:"choices"`
}

type chatCompletionChoice struct {
	Index        int              `json:"index"`
	Message      *proxy.Message   `json:"message,omitempty"`
	Delta        *deltaPayload    `json:"delta,omitempty"`
	FinishReason *string          `json:"finish_reason"`
	ToolCalls    []proxy.ToolCall `json:"tool_calls,omitempty"`
}

type deltaPayload struct {
	Role      string           `json:"role,omitempty"`
	Content   string           `json:"content,omitempty"`
	ToolCalls []proxy.ToolCall `json:"tool_calls,omitempty"`
}

type adminStatusResponse struct {
	Credential   proxy.CredentialStatus `json:"credential"`
	Models       proxy.ModelStatus      `json:"models"`
	SessionCount int                    `json:"session_count"`
}

func NewServer(deps Dependencies, store *db.Store) http.Handler {
	if deps.Now == nil {
		deps.Now = time.Now
	}

	server := &Server{deps: deps, db: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", server.handleChatCompletions)
	mux.HandleFunc("/v1/messages", server.handleAnthropicMessages)
	mux.HandleFunc("/v1/models", server.handleModels)
	mux.HandleFunc("/admin/status", server.handleAdminStatus)
	mux.HandleFunc("/admin/refresh", server.handleAdminRefresh)
	mux.HandleFunc("/admin/sessions", server.handleAdminSessions)
	mux.HandleFunc("/admin/sessions/", server.handleAdminSessionDelete)
	mux.HandleFunc("/admin/dashboard", server.handleAdminDashboard)
	mux.HandleFunc("/admin/account", server.handleAdminAccount)
	mux.HandleFunc("/admin/account/refresh", server.handleAdminAccountRefresh)
	mux.HandleFunc("/admin/account/bootstrap", server.handleAdminAccountBootstrap)
	mux.HandleFunc("/admin/account/bootstrap/status", server.handleAdminAccountBootstrapStatus)
	mux.HandleFunc("/admin/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			server.handleAdminSettingsGet(w, r)
		} else if r.Method == http.MethodPut {
			server.handleAdminSettingsUpdate(w, r)
		} else {
			writeMethodNotAllowed(w, "GET, PUT")
		}
	})
	mux.HandleFunc("/admin/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/logs" {
			server.handleAdminLogsList(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/replay") {
			server.handleAdminLogsReplay(w, r)
		} else {
			server.handleAdminLogsGet(w, r)
		}
	})
	mux.HandleFunc("/admin/logs/cleanup", server.handleAdminLogsCleanup)
	mux.HandleFunc("/admin/logs/export", server.handleAdminLogsExport)
	mux.HandleFunc("/admin/stats/export", server.handleAdminStatsExport)
	mux.HandleFunc("/admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			server.handleAdminMappingsList(w, r)
		} else if r.Method == http.MethodPost {
			server.handleAdminMappingsCreate(w, r)
		} else {
			writeMethodNotAllowed(w, "GET, POST")
		}
	})
	mux.HandleFunc("/admin/mappings/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/mappings/test" {
			server.handleAdminMappingsTest(w, r)
			return
		}
		if r.Method == http.MethodPut {
			server.handleAdminMappingsUpdate(w, r)
		} else if r.Method == http.MethodDelete {
			server.handleAdminMappingsDelete(w, r)
		} else {
			writeMethodNotAllowed(w, "PUT, DELETE")
		}
	})

	if deps.FrontendFS != (embed.FS{}) {
		subFS, err := fs.Sub(deps.FrontendFS, "frontend-dist")
		if err == nil {
			fileServer := http.FileServerFS(subFS)
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				f, err := subFS.Open(strings.TrimPrefix(r.URL.Path, "/"))
				if err == nil {
					f.Close()
					fileServer.ServeHTTP(w, r)
					return
				}
				r.URL.Path = "/"
				fileServer.ServeHTTP(w, r)
			})
		}
	}

	handler := http.Handler(mux)
	if store != nil {
		settings, _ := store.GetSettings(context.Background())
		cfg := middleware.LoggingConfig{
			StorageMode:    settings["storage_mode"],
			TruncateLength: parseIntOr(settings["truncate_length"], 102400),
		}
		handler = middleware.Logging(store, cfg)(handler)
	}
	return handler
}

func parseIntOr(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func (server *Server) handleModels(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer, http.MethodGet)
		return
	}

	models, err := server.deps.Models.ListModels(request.Context())
	if err != nil {
		writeMappedError(writer, err)
		return
	}

	writeJSON(writer, http.StatusOK, proxy.OpenAIModelsResponse{
		Object: "list",
		Data:   models,
	})
}

func (server *Server) handleChatCompletions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer, http.MethodPost)
		return
	}

	chatRequest, err := decodeChatRequest(writer, request)
	if err != nil {
		writeOpenAIError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateChatRequest(&chatRequest); err != nil {
		writeOpenAIError(writer, http.StatusBadRequest, err.Error())
		return
	}

	sessionID := strings.TrimSpace(chatRequest.ExtraBody.SessionID)
	if headerSession := strings.TrimSpace(request.Header.Get("X-Session-Id")); headerSession != "" {
		sessionID = headerSession
	}

	messages, err := server.deps.Sessions.BuildMessages(request.Context(), sessionID, chatRequest.Messages)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	modelKey, err := server.deps.Models.ResolveChatModel(request.Context(), chatRequest.Model)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	credential, err := server.deps.Credentials.Current(request.Context())
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	remoteRequest, err := server.deps.Builder.Build(chatRequest, messages, modelKey)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	stream, err := server.deps.Transport.StreamChat(request.Context(), remoteRequest, credential)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	defer stream.Close()

	if chatRequest.Stream {
		server.streamChatResponse(writer, request, chatRequest, remoteRequest, sessionID, messages, stream)
		return
	}
	server.writeNonStreamResponse(writer, chatRequest, remoteRequest, sessionID, messages, stream)
}

func (server *Server) writeNonStreamResponse(
	writer http.ResponseWriter,
	request proxy.OpenAIChatRequest,
	remoteRequest proxy.RemoteChatRequest,
	sessionID string,
	messages []proxy.Message,
	stream io.Reader,
) {
	content, err := proxy.CollectSSEContent(stream)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	if err := server.deps.Sessions.SaveResponse(context.Background(), sessionID, messages, proxy.Message{
		Role:    "assistant",
		Content: content,
	}); err != nil {
		writeMappedError(writer, err)
		return
	}

	finishReason := "stop"
	writeJSON(writer, http.StatusOK, chatCompletionResponse{
		ID:      "chatcmpl-" + remoteRequest.RequestID,
		Object:  "chat.completion",
		Created: server.deps.Now().Unix(),
		Model:   request.Model,
		Choices: []chatCompletionChoice{
			{
				Index: 0,
				Message: &proxy.Message{
					Role:    "assistant",
					Content: content,
				},
				FinishReason: &finishReason,
			},
		},
	})
}

func (server *Server) streamChatResponse(
	writer http.ResponseWriter,
	request *http.Request,
	chatRequest proxy.OpenAIChatRequest,
	remoteRequest proxy.RemoteChatRequest,
	sessionID string,
	messages []proxy.Message,
	stream io.Reader,
) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeOpenAIError(writer, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")

	responseID := "chatcmpl-" + remoteRequest.RequestID
	if err := writeSSEChunk(writer, chatCompletionResponse{
		ID:      responseID,
		Object:  "chat.completion.chunk",
		Created: server.deps.Now().Unix(),
		Model:   chatRequest.Model,
		Choices: []chatCompletionChoice{{
			Index: 0,
			Delta: &deltaPayload{Role: "assistant"},
		}},
	}); err != nil {
		return
	}
	flusher.Flush()

	// pendingTCs tracks in-progress tool calls by index, accumulating fragments
	// from the upstream SSE stream into complete calls before emitting to the client.
	type pendingToolCall struct {
		id   string
		typ  string
		name string
		args strings.Builder
	}
	pendingTCs := map[int]*pendingToolCall{}

	// emitPending flushes a completed tool call as a single delta to the client.
	emitPending := func(p *pendingToolCall) error {
		tc := proxy.ToolCall{
			Index: 0,
			ID:    p.id,
			Type:  p.typ,
			Function: proxy.FunctionCall{
				Name:      p.name,
				Arguments: p.args.String(),
			},
		}
		if tc.ID == "" {
			tc.ID = "call_" + remoteRequest.RequestID + "_0"
		}
		choice := chatCompletionChoice{Index: 0}
		choice.Delta = &deltaPayload{
			Role:      "assistant",
			ToolCalls: []proxy.ToolCall{tc},
		}
		return writeSSEChunk(writer, chatCompletionResponse{
			ID:      responseID,
			Object:  "chat.completion.chunk",
			Created: server.deps.Now().Unix(),
			Model:   chatRequest.Model,
			Choices: []chatCompletionChoice{choice},
		})
	}

	var contentBuilder strings.Builder
	err := proxy.ScanSSE(stream, func(event proxy.SSEEvent) error {
		if event.Done {
			return nil
		}
		if event.Content == "" && len(event.ToolCalls) == 0 {
			return nil
		}
		if event.Content != "" {
			// When content arrives, flush any pending tool calls first.
			for _, p := range pendingTCs {
				if err := emitPending(p); err != nil {
					return err
				}
				flusher.Flush()
			}
			pendingTCs = map[int]*pendingToolCall{}

			contentBuilder.WriteString(event.Content)
			choice := chatCompletionChoice{Index: 0}
			choice.Delta = &deltaPayload{Content: event.Content}
			if err := writeSSEChunk(writer, chatCompletionResponse{
				ID:      responseID,
				Object:  "chat.completion.chunk",
				Created: server.deps.Now().Unix(),
				Model:   chatRequest.Model,
				Choices: []chatCompletionChoice{choice},
			}); err != nil {
				return err
			}
			flusher.Flush()
			return nil
		}
		// Handle tool call fragments.
		for _, tc := range event.ToolCalls {
			idx := tc.Index
			p, exists := pendingTCs[idx]
			isNew := tc.ID != "" || tc.Function.Name != ""
			if !isNew && exists {
				// Continuation fragment – just accumulate arguments.
				p.args.WriteString(tc.Function.Arguments)
			} else {
				// New tool call start – flush any previous one at this index.
				if exists {
					if err := emitPending(p); err != nil {
						return err
					}
					flusher.Flush()
				}
				p = &pendingToolCall{
					id:   tc.ID,
					typ:  tc.Type,
					name: tc.Function.Name,
				}
				p.args.WriteString(tc.Function.Arguments)
				pendingTCs[idx] = p
			}
		}
		return nil
	})
	// Flush any remaining pending tool calls after the stream ends.
	if err == nil {
		for _, p := range pendingTCs {
			if err := emitPending(p); err != nil {
				break
			}
			flusher.Flush()
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(writer, "data: {\"error\":{\"message\":%q}}\n\n", err.Error())
		flusher.Flush()
		return
	}

	if err := server.deps.Sessions.SaveResponse(request.Context(), sessionID, messages, proxy.Message{
		Role:    "assistant",
		Content: contentBuilder.String(),
	}); err != nil {
		return
	}

	finishReason := "stop"
	_ = writeSSEChunk(writer, chatCompletionResponse{
		ID:      responseID,
		Object:  "chat.completion.chunk",
		Created: server.deps.Now().Unix(),
		Model:   chatRequest.Model,
		Choices: []chatCompletionChoice{{
			Index:        0,
			Delta:        &deltaPayload{},
			FinishReason: &finishReason,
		}},
	})
	_, _ = io.WriteString(writer, "data: [DONE]\n\n")
	flusher.Flush()
}

func (server *Server) handleAdminStatus(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(request) {
		writeOpenAIError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}

	sessions, err := server.deps.Sessions.List(request.Context())
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, adminStatusResponse{
		Credential:   server.deps.Credentials.Status(),
		Models:       server.deps.Models.Status(),
		SessionCount: len(sessions),
	})
}

func (server *Server) handleAdminRefresh(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer, http.MethodPost)
		return
	}
	if !server.isAdminAuthorized(request) {
		writeOpenAIError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeOpenAIError(writer, http.StatusNotImplemented, "project credential refresh is not implemented; rerun lingma-auth-bootstrap")
}

func (server *Server) handleAdminSessions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(request) {
		writeOpenAIError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}

	sessions, err := server.deps.Sessions.List(request.Context())
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, sessions)
}

func (server *Server) handleAdminSessionDelete(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodDelete {
		writeMethodNotAllowed(writer, http.MethodDelete)
		return
	}
	if !server.isAdminAuthorized(request) {
		writeOpenAIError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}

	sessionID := strings.TrimPrefix(request.URL.Path, "/admin/sessions/")
	if sessionID == "" || sessionID == request.URL.Path {
		writeOpenAIError(writer, http.StatusBadRequest, "missing session id")
		return
	}
	if err := server.deps.Sessions.Delete(request.Context(), sessionID); err != nil {
		writeMappedError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "deleted"})
}

func (server *Server) isAdminAuthorized(request *http.Request) bool {
	if server.deps.AdminToken == "" {
		return true
	}
	if token := strings.TrimSpace(request.Header.Get("X-Admin-Token")); token == server.deps.AdminToken {
		return true
	}
	authorization := strings.TrimSpace(request.Header.Get("Authorization"))
	return authorization == "Bearer "+server.deps.AdminToken
}

func decodeChatRequest(writer http.ResponseWriter, request *http.Request) (proxy.OpenAIChatRequest, error) {
	body := http.MaxBytesReader(writer, request.Body, 1<<20)
	defer body.Close()

	var chatRequest proxy.OpenAIChatRequest
	if err := json.NewDecoder(body).Decode(&chatRequest); err != nil {
		return proxy.OpenAIChatRequest{}, err
	}
	return chatRequest, nil
}

func validateChatRequest(request *proxy.OpenAIChatRequest) error {
	if len(request.Messages) == 0 {
		return errors.New("messages must not be empty")
	}
	for i := range request.Messages {
		message := &request.Messages[i]
		switch message.Role {
		case "system", "user":
			if message.Content == "" {
				return errors.New("message content must not be empty")
			}
		case "assistant":
			// Filter empty-name tool_calls that may result from streaming
			// fragment artifacts in upstream models. Stripping them preserves
			// the conversation while the streaming fix prevents new ones.
			if len(message.ToolCalls) > 0 {
				filtered := message.ToolCalls[:0]
				for _, tc := range message.ToolCalls {
					if tc.Function.Name != "" {
						filtered = append(filtered, tc)
					}
				}
				message.ToolCalls = filtered
			}
			if message.Content == "" && len(message.ToolCalls) == 0 {
				return errors.New("assistant message must have content or tool_calls")
			}
		case "tool":
			if message.ToolCallID == "" {
				return errors.New("tool message must have tool_call_id")
			}
		default:
			return fmt.Errorf("unsupported role %q", message.Role)
		}
	}
	return nil
}

func writeSSEChunk(writer http.ResponseWriter, payload chatCompletionResponse) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "data: %s\n\n", data)
	return err
}

func writeJSON(writer http.ResponseWriter, statusCode int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	_ = json.NewEncoder(writer).Encode(payload)
}

func writeMethodNotAllowed(writer http.ResponseWriter, method string) {
	writer.Header().Set("Allow", method)
	writeOpenAIError(writer, http.StatusMethodNotAllowed, "method not allowed")
}

func writeMappedError(writer http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	switch {
	case errors.Is(err, proxy.ErrUnknownModel):
		statusCode = http.StatusBadRequest
	case errors.Is(err, proxy.ErrCredentialsUnavailable):
		statusCode = http.StatusInternalServerError
	default:
		var upstream *proxy.UpstreamHTTPError
		if errors.As(err, &upstream) {
			if upstream.StatusCode == http.StatusUnauthorized || upstream.StatusCode == http.StatusForbidden {
				statusCode = http.StatusUnauthorized
			} else {
				statusCode = http.StatusBadGateway
			}
		}
	}
	writeOpenAIError(writer, statusCode, err.Error())
}

func writeOpenAIError(writer http.ResponseWriter, statusCode int, message string) {
	writeJSON(writer, statusCode, map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "invalid_request_error",
		},
	})
}
