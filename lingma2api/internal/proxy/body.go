package proxy

import (
	"encoding/json"
	"time"
)

type BodyBuilder struct {
	cosyVersion string
	now         func() time.Time
	newUUID     func() string
	newHexID    func() string
}

func NewBodyBuilder(cosyVersion string, now func() time.Time, newUUID func() string, newHexID func() string) *BodyBuilder {
	if cosyVersion == "" {
		cosyVersion = "2.11.2"
	}
	if now == nil {
		now = time.Now
	}
	if newUUID == nil {
		newUUID = NewUUID
	}
	if newHexID == nil {
		newHexID = NewHexID
	}

	return &BodyBuilder{
		cosyVersion: cosyVersion,
		now:         now,
		newUUID:     newUUID,
		newHexID:    newHexID,
	}
}

func (builder *BodyBuilder) Build(request OpenAIChatRequest, messages []Message, modelKey string) (RemoteChatRequest, error) {
	requestID := builder.newHexID()
	temperature := 0.1
	if request.Temperature != nil {
		temperature = *request.Temperature
	}

	serializedMessages := make([]map[string]any, 0, len(messages))
	for _, message := range messages {
		m := map[string]any{
			"role":    message.Role,
			"content": message.Content,
			"response_meta": map[string]any{
				"id": "",
				"usage": map[string]int{
					"prompt_tokens":     0,
					"completion_tokens": 0,
					"total_tokens":      0,
				},
			},
			"reasoning_content_signature": "",
		}
		if message.Name != "" {
			m["name"] = message.Name
		}
		if message.ToolCallID != "" {
			m["tool_call_id"] = message.ToolCallID
		}
		if len(message.ToolCalls) > 0 {
			m["tool_calls"] = message.ToolCalls
		}
		serializedMessages = append(serializedMessages, m)
	}

	payload := map[string]any{
		"request_id":       requestID,
		"request_set_id":   "",
		"chat_record_id":   requestID,
		"stream":           request.Stream,
		"image_urls":       nil,
		"is_reply":         false,
		"is_retry":         false,
		"session_id":       "",
		"code_language":    "",
		"source":           0,
		"version":          "3",
		"chat_prompt":      "",
		"parameters":       map[string]float64{"temperature": temperature},
		"aliyun_user_type": "personal_standard",
		"agent_id":         "agent_common",
		"task_id":          "question_refine",
		"model_config": map[string]any{
			"key":                   modelKey,
			"display_name":          "",
			"model":                 modelKey,
			"format":                "",
			"is_vl":                 false,
			"is_reasoning":          request.Reasoning,
			"api_key":               "",
			"url":                   "",
			"source":                "",
			"max_input_tokens":      0,
			"enable":                false,
			"price_factor":          0,
			"original_price_factor": 0,
			"is_default":            false,
			"is_new":                false,
			"exclude_tags":          nil,
			"tags":                  nil,
			"icon":                  nil,
			"strategies":            nil,
		},
		"messages": serializedMessages,
		"business": map[string]any{
			"product":  "jb_plugin",
			"version":  builder.cosyVersion,
			"type":     "memory",
			"id":       builder.newUUID(),
			"begin_at": builder.now().UnixMilli(),
			"stage":    "start",
			"name":     "memory_intent_recognition_" + requestID,
		},
	}

	if len(request.Tools) > 0 {
		payload["tools"] = request.Tools
	}
	if request.ToolChoice != nil {
		payload["tool_choice"] = request.ToolChoice
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return RemoteChatRequest{}, err
	}

	return RemoteChatRequest{
		Path:      ChatPath,
		Query:     ChatQuery,
		BodyJSON:  string(bodyBytes),
		RequestID: requestID,
		ModelKey:  modelKey,
		Stream:    request.Stream,
	}, nil
}
