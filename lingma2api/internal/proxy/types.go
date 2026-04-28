package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	ChatPath      = "/algo/api/v2/service/pro/sse/agent_chat_generation"
	ChatQuery     = "?FetchKeys=llm_model_result&AgentId=agent_common"
	ModelListPath = "/algo/api/v2/model/list"
)

var (
	ErrUnknownModel           = errors.New("unknown model")
	ErrCredentialsUnavailable = errors.New("credentials unavailable")
)

// ToolCall represents an OpenAI-compatible tool call from an assistant message.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall holds the function name and JSON-encoded arguments.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Tool is an OpenAI-compatible tool definition passed in a chat request.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction describes a tool's function schema.
type ToolFunction struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
}

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	Name       string     `json:"name,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

type ExtraBody struct {
	SessionID string `json:"session_id"`
}

type OpenAIChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	Temperature *float64  `json:"temperature,omitempty"`
	ExtraBody   ExtraBody `json:"extra_body,omitempty"`
	Tools       []Tool    `json:"tools,omitempty"`
	ToolChoice  any       `json:"tool_choice,omitempty"`
}

type OpenAIModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
}

type OpenAIModelsResponse struct {
	Object string        `json:"object"`
	Data   []OpenAIModel `json:"data"`
}

type CredentialSnapshot struct {
	CosyKey         string    `json:"cosy_key"`
	EncryptUserInfo string    `json:"encrypt_user_info"`
	UserID          string    `json:"user_id"`
	MachineID       string    `json:"machine_id"`
	Source          string    `json:"source"`
	LoadedAt        time.Time `json:"loaded_at"`
}

type StoredCredentialFile struct {
	SchemaVersion     int               `json:"schema_version"`
	Source            string            `json:"source"`
	LingmaVersionHint string            `json:"lingma_version_hint,omitempty"`
	ObtainedAt        string            `json:"obtained_at,omitempty"`
	UpdatedAt         string            `json:"updated_at,omitempty"`
	TokenExpireTime   string            `json:"token_expire_time,omitempty"`
	Auth              StoredAuthFields  `json:"auth"`
	OAuth             StoredOAuthFields `json:"oauth,omitempty"`
}

type StoredAuthFields struct {
	CosyKey         string `json:"cosy_key"`
	EncryptUserInfo string `json:"encrypt_user_info"`
	UserID          string `json:"user_id"`
	MachineID       string `json:"machine_id"`
}

type StoredOAuthFields struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type CredentialStatus struct {
	Loaded         bool      `json:"loaded"`
	HasCredentials bool      `json:"has_credentials"`
	Source         string    `json:"source"`
	LoadedAt       time.Time `json:"loaded_at"`
}

type SessionState struct {
	ID           string    `json:"id"`
	Messages     []Message `json:"messages,omitempty"`
	MessageCount int       `json:"message_count"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ModelStatus struct {
	FetchedAt time.Time `json:"fetched_at"`
	Cached    bool      `json:"cached"`
	Count     int       `json:"count"`
	LastError string    `json:"last_error,omitempty"`
}

type RemoteModel struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
	Model       string `json:"model"`
	Enable      bool   `json:"enable"`
}

type RemoteChatRequest struct {
	Path      string
	Query     string
	BodyJSON  string
	RequestID string
	ModelKey  string
	Stream    bool
}

type SSEEvent struct {
	Content   string
	ToolCalls []ToolCall
	Done      bool
}

type UpstreamHTTPError struct {
	StatusCode int
	Body       string
}

func (err *UpstreamHTTPError) Error() string {
	return fmt.Sprintf("upstream http status %d: %s", err.StatusCode, err.Body)
}

func DefaultAliases() map[string]string {
	return map[string]string{
		"qwen3-coder":         "dashscope_qwen3_coder",
		"qwen3-coder-default": "dashscope_qwen3_coder_default",
		"qwen-plus-thinking":  "dashscope_qwen_plus_20250428_thinking",
		"qwen-max":            "dashscope_qwen_max_latest",
		"auto":                "",
	}
}

func NewUUID() string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}

	data[6] = (data[6] & 0x0f) | 0x40
	data[8] = (data[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[0:4], data[4:6], data[6:8], data[8:10], data[10:16])
}

func NewHexID() string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return fmt.Sprintf("fallback%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(data[:])
}

func cloneMessages(messages []Message) []Message {
	if len(messages) == 0 {
		return nil
	}
	cloned := make([]Message, len(messages))
	copy(cloned, messages)
	return cloned
}
