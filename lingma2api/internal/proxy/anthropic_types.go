package proxy

import "encoding/json"

// ---- Request types ----

type AnthropicMessagesRequest struct {
	Model     string             `json:"model"`
	Messages  []AnthropicMessage `json:"messages"`
	System    json.RawMessage    `json:"system,omitempty"` // string or []SystemBlock
	Tools     []Tool             `json:"tools,omitempty"`
	MaxTokens int                `json:"max_tokens"`
	Stream    bool               `json:"stream,omitempty"`
	Thinking  *ThinkingConfig    `json:"thinking,omitempty"`
	Metadata  json.RawMessage    `json:"metadata,omitempty"`
}

type ThinkingConfig struct {
	Type         string `json:"type"`                    // "enabled", "disabled", "auto"
	BudgetTokens *int   `json:"budget_tokens,omitempty"`
}

type AnthropicMessage struct {
	Role    string         `json:"role"` // "user" | "assistant"
	Content []ContentBlock `json:"content"`
}

type ContentBlock struct {
	Type      string          `json:"type"`                 // text, tool_use, tool_result, thinking, image, document
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`         // tool_use id
	Name      string          `json:"name,omitempty"`       // tool_use name
	Input     json.RawMessage `json:"input,omitempty"`      // tool_use input (JSON object)
	ToolUseID string          `json:"tool_use_id,omitempty"` // tool_result
	Content   json.RawMessage `json:"content,omitempty"`    // tool_result content
	IsError   *bool           `json:"is_error,omitempty"`
	Source    *ImageSource    `json:"source,omitempty"`     // image / document
	Thinking  string          `json:"thinking,omitempty"`
	Signature string          `json:"signature,omitempty"`
}

type ImageSource struct {
	Type      string `json:"type"`       // "base64"
	MediaType string `json:"media_type"` // "image/png", "image/jpeg", etc.
	Data      string `json:"data"`
}

// SystemBlock is used when system is a list of content blocks.
type SystemBlock struct {
	Type string `json:"type"` // "text"
	Text string `json:"text"`
}

// ---- Response types ----

type AnthropicMessagesResponse struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"` // "message"
	Role       string         `json:"role"`
	Content    []ContentBlock `json:"content"`
	Model      string         `json:"model"`
	StopReason string         `json:"stop_reason"`
	Usage      Usage          `json:"usage"`
}

type Usage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
}

// ---- Streaming event types ----

type AnthropicStreamEvent struct {
	Type         string          `json:"type"`
	Index        *int            `json:"index,omitempty"`
	Message      *StreamMessage  `json:"message,omitempty"`
	ContentBlock *ContentBlock   `json:"content_block,omitempty"`
	Delta        *StreamDelta    `json:"delta,omitempty"`
	Usage        *Usage          `json:"usage,omitempty"`
}

type StreamMessage struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Role  string `json:"role"`
	Model string `json:"model"`
	Usage Usage  `json:"usage"`
}

type StreamDelta struct {
	Type         string `json:"type,omitempty"` // text_delta, input_json_delta, thinking_delta, signature_delta
	Text         string `json:"text,omitempty"`
	PartialJSON  string `json:"partial_json,omitempty"`
	Thinking     string `json:"thinking,omitempty"`
	Signature    string `json:"signature,omitempty"`
	StopReason   string `json:"stop_reason,omitempty"`
	StopSequence string `json:"stop_sequence,omitempty"`
}
