package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"lingma2api/internal/proxy"
)

func (server *Server) handleAnthropicMessages(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer, http.MethodPost)
		return
	}

	body, err := io.ReadAll(io.LimitReader(request.Body, 2<<20))
	if err != nil {
		writeAnthropicError(writer, http.StatusBadRequest, "read body failed")
		return
	}

	var anthropicReq proxy.AnthropicMessagesRequest
	if err := json.Unmarshal(body, &anthropicReq); err != nil {
		writeAnthropicError(writer, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if anthropicReq.Model == "" {
		writeAnthropicError(writer, http.StatusBadRequest, "model is required")
		return
	}
	if len(anthropicReq.Messages) == 0 {
		writeAnthropicError(writer, http.StatusBadRequest, "messages must not be empty")
		return
	}
	if anthropicReq.MaxTokens == 0 {
		anthropicReq.MaxTokens = 4096
	}

	// Convert Anthropic → IR messages.
	irMessages, err := proxy.ConvertAnthropicToIR(anthropicReq)
	if err != nil {
		writeAnthropicError(writer, http.StatusBadRequest, err.Error())
		return
	}

	// Enable Lingma native reasoning when Anthropic thinking is not explicitly disabled.
	reasoning := anthropicReq.Thinking == nil || anthropicReq.Thinking.Type != "disabled"

	// Build an OpenAI-compatible request for the body builder.
	openaiReq := proxy.OpenAIChatRequest{
		Model:     anthropicReq.Model,
		Stream:    anthropicReq.Stream,
		Messages:  irMessages,
		Tools:     anthropicReq.Tools,
		Reasoning: reasoning,
	}

	resolvedModelKey, err := server.deps.Models.ResolveChatModel(request.Context(), anthropicReq.Model)
	if err != nil {
		writeAnthropicError(writer, http.StatusBadRequest, "resolve model: "+err.Error())
		return
	}

	snapshot, err := server.deps.Credentials.Current(request.Context())
	if err != nil {
		writeAnthropicError(writer, http.StatusInternalServerError, "credentials: "+err.Error())
		return
	}

	remoteRequest, err := server.deps.Builder.Build(openaiReq, irMessages, resolvedModelKey)
	if err != nil {
		writeAnthropicError(writer, http.StatusInternalServerError, "build request: "+err.Error())
		return
	}

	stream, err := server.deps.Transport.StreamChat(request.Context(), remoteRequest, snapshot)
	if err != nil {
		writeAnthropicError(writer, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	defer stream.Close()

	responseID := "msg_" + remoteRequest.RequestID

	if !anthropicReq.Stream {
		server.nonStreamAnthropicResponse(writer, stream, responseID, anthropicReq.Model)
	} else {
		server.streamAnthropicResponse(writer, request, stream, responseID, anthropicReq.Model)
	}
}

func (server *Server) nonStreamAnthropicResponse(
	writer http.ResponseWriter,
	stream io.Reader,
	responseID, model string,
) {
	var contentBuilder strings.Builder
	var reasoningBuilder strings.Builder
	err := proxy.ScanSSE(stream, func(event proxy.SSEEvent) error {
		contentBuilder.WriteString(event.Content)
		reasoningBuilder.WriteString(event.ReasoningContent)
		return nil
	})
	if err != nil {
		writeAnthropicError(writer, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}

	blocks := []proxy.ContentBlock{}

	reasoningText := reasoningBuilder.String()
	if reasoningText != "" {
		blocks = append(blocks, proxy.ContentBlock{
			Type:     "thinking",
			Thinking: reasoningText,
		})
	}

	contentText := contentBuilder.String()
	if contentText != "" {
		blocks = append(blocks, proxy.ContentBlock{
			Type: "text",
			Text: contentText,
		})
	}

	if len(blocks) == 0 {
		blocks = append(blocks, proxy.ContentBlock{
			Type: "text",
			Text: contentText,
		})
	}

	usage := proxy.Usage{
		InputTokens:  len(contentText)/4 + len(reasoningText)/4,
		OutputTokens: len(contentText)/4 + len(reasoningText)/4,
	}

	resp := proxy.AnthropicMessagesResponse{
		ID:         responseID,
		Type:       "message",
		Role:       "assistant",
		Content:    blocks,
		Model:      model,
		StopReason: "end_turn",
		Usage:      usage,
	}

	writeJSON(writer, http.StatusOK, resp)
}

func (server *Server) streamAnthropicResponse(
	writer http.ResponseWriter,
	request *http.Request,
	stream io.Reader,
	responseID, model string,
) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeAnthropicError(writer, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")

	// message_start
	startUsage := proxy.Usage{}
	writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
		Type: "message_start",
		Message: &proxy.StreamMessage{
			ID:    responseID,
			Type:  "message",
			Role:  "assistant",
			Model: model,
			Usage: startUsage,
		},
	})
	flusher.Flush()

	blockIndex := -1
	var blockStarted bool
	var blockType string // "thinking", "text", or "tool_use"
	var contentBuilder strings.Builder
	var reasoningBuilder strings.Builder

	closeBlock := func() {
		if !blockStarted {
			return
		}
		writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
			Type:  "content_block_stop",
			Index: intPtr(blockIndex),
		})
		flusher.Flush()
		blockStarted = false
		blockType = ""
	}

	err := proxy.ScanSSE(stream, func(event proxy.SSEEvent) error {
		if event.Done {
			return nil
		}

		// Emit thinking content first (reasoning_content from Lingma).
		if event.ReasoningContent != "" {
			if blockStarted && blockType != "thinking" {
				closeBlock()
			}
			if !blockStarted {
				blockIndex++
				writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
					Type:  "content_block_start",
					Index: intPtr(blockIndex),
					ContentBlock: &proxy.ContentBlock{
						Type:     "thinking",
						Thinking: "",
					},
				})
				blockStarted = true
				blockType = "thinking"
			}
			writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
				Type:  "content_block_delta",
				Index: intPtr(blockIndex),
				Delta: &proxy.StreamDelta{
					Type:     "thinking_delta",
					Thinking: event.ReasoningContent,
				},
			})
			flusher.Flush()
			reasoningBuilder.WriteString(event.ReasoningContent)
			return nil
		}

		if event.Content != "" {
			if blockStarted && blockType != "text" {
				closeBlock()
			}
			if !blockStarted {
				blockIndex++
				writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
					Type:  "content_block_start",
					Index: intPtr(blockIndex),
					ContentBlock: &proxy.ContentBlock{
						Type: "text",
						Text: "",
					},
				})
				blockStarted = true
				blockType = "text"
			}
			writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
				Type:  "content_block_delta",
				Index: intPtr(blockIndex),
				Delta: &proxy.StreamDelta{
					Type: "text_delta",
					Text: event.Content,
				},
			})
			flusher.Flush()
			contentBuilder.WriteString(event.Content)
			return nil
		}

		for _, tc := range event.ToolCalls {
			isNew := tc.ID != "" || tc.Function.Name != ""
			if isNew {
				closeBlock()
				blockIndex++
				writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
					Type:  "content_block_start",
					Index: intPtr(blockIndex),
					ContentBlock: &proxy.ContentBlock{
						Type: "tool_use",
						ID:   tc.ID,
						Name: tc.Function.Name,
					},
				})
				blockStarted = true
				blockType = "tool_use"
			}
			if tc.Function.Arguments != "" {
				writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
					Type:  "content_block_delta",
					Index: intPtr(blockIndex),
					Delta: &proxy.StreamDelta{
						Type:        "input_json_delta",
						PartialJSON: tc.Function.Arguments,
					},
				})
				flusher.Flush()
			}
		}
		return nil
	})

	if err != nil {
		closeBlock()
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(map[string]string{
			"type":    "error",
			"message": err.Error(),
		})
		_, _ = fmt.Fprintf(writer, "event: error\ndata: %s\n\n", buf.String())
		flusher.Flush()
		return
	}

	closeBlock()

	totalText := contentBuilder.String()
	totalReasoning := reasoningBuilder.String()
	outTokens := (len(totalText) + len(totalReasoning)) / 4
	if outTokens == 0 {
		outTokens = 1
	}
	inTokens := outTokens * 2

	// message_delta
	writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
		Type: "message_delta",
		Delta: &proxy.StreamDelta{
			StopReason: "end_turn",
		},
		Usage: &proxy.Usage{
			OutputTokens: outTokens,
			InputTokens:  inTokens,
		},
	})
	flusher.Flush()

	// message_stop
	writeAnthropicSSE(writer, proxy.AnthropicStreamEvent{
		Type: "message_stop",
	})
	flusher.Flush()
}

func writeAnthropicSSE(writer http.ResponseWriter, event proxy.AnthropicStreamEvent) {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(event)
	data := strings.TrimSpace(buf.String())
	eventType := event.Type
	fmt.Fprintf(writer, "event: %s\ndata: %s\n\n", eventType, data)
}

func writeAnthropicError(writer http.ResponseWriter, statusCode int, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"type":  "error",
		"error": map[string]string{"type": "invalid_request_error", "message": message},
	})
}

func intPtr(i int) *int { return &i }
