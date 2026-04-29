package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ConvertAnthropicToIR converts an Anthropic Messages request to the internal
// Message IR understood by the body builder and transport layer.
func ConvertAnthropicToIR(req AnthropicMessagesRequest) ([]Message, error) {
	out := make([]Message, 0, len(req.Messages)+1)

	// Inject system prompt as the first message when present.
	if len(req.System) > 0 {
		sysMsg, err := parseSystemPrompt(req.System)
		if err != nil {
			return nil, fmt.Errorf("parse system: %w", err)
		}
		if sysMsg != nil {
			out = append(out, *sysMsg)
		}
	}

	for _, m := range req.Messages {
		ir, err := convertAnthropicMessage(m)
		if err != nil {
			return nil, err
		}
		out = append(out, ir...)
	}
	return out, nil
}

// ConvertIRToAnthropic converts IR messages back to Anthropic content blocks.
func ConvertIRToAnthropic(ir []Message) []ContentBlock {
	blocks := make([]ContentBlock, 0, len(ir))
	for _, m := range ir {
		switch m.Role {
		case "assistant":
			if len(m.ToolCalls) > 0 {
				for _, tc := range m.ToolCalls {
					input := json.RawMessage(tc.Function.Arguments)
					if !json.Valid(input) {
						input = json.RawMessage("{}")
					}
					blocks = append(blocks, ContentBlock{
						Type:  "tool_use",
						ID:    tc.ID,
						Name:  tc.Function.Name,
						Input: input,
					})
				}
			}
			if m.Content != "" {
				blocks = append(blocks, ContentBlock{
					Type: "text",
					Text: m.Content,
				})
			}
		case "tool":
			var content json.RawMessage
			if json.Valid([]byte(m.Content)) {
				content = json.RawMessage(m.Content)
			} else {
				escaped, _ := json.Marshal(m.Content)
				content = json.RawMessage(escaped)
			}
			blocks = append(blocks, ContentBlock{
				Type:      "tool_result",
				ToolUseID: m.ToolCallID,
				Content:   content,
			})
		case "user", "system":
			if m.Content != "" {
				blocks = append(blocks, ContentBlock{
					Type: "text",
					Text: m.Content,
				})
			}
		}
	}
	return blocks
}

func parseSystemPrompt(raw json.RawMessage) (*Message, error) {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil, nil
	}

	// Case 1: plain string
	if raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, err
		}
		if text == "" {
			return nil, nil
		}
		return &Message{Role: "system", Content: text}, nil
	}

	// Case 2: array of {type:"text", text:"..."}
	if raw[0] == '[' {
		var blocks []SystemBlock
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return nil, fmt.Errorf("unmarshal system blocks: %w", err)
		}
		var builder strings.Builder
		for _, b := range blocks {
			if b.Type == "text" {
				builder.WriteString(b.Text)
				builder.WriteByte('\n')
			}
		}
		text := strings.TrimRight(builder.String(), "\n")
		if text == "" {
			return nil, nil
		}
		return &Message{Role: "system", Content: text}, nil
	}

	return nil, fmt.Errorf("unsupported system format: %s", string(raw[:min(60, len(raw))]))
}

func convertAnthropicMessage(m AnthropicMessage) ([]Message, error) {
	if m.Role != "user" && m.Role != "assistant" {
		return nil, fmt.Errorf("unsupported role %q", m.Role)
	}

	out := make([]Message, 0, 1)
	switch m.Role {
	case "user":
		msg := Message{Role: "user"}
		for _, block := range m.Content {
			switch block.Type {
			case "text":
				msg.Content += block.Text
			case "tool_result":
				out = append(out, Message{
					Role:       "tool",
					ToolCallID: block.ToolUseID,
					Content:    toolResultString(block.Content),
				})
				continue
			case "image":
				if msg.Content != "" {
					msg.Content += "\n"
				}
				msg.Content += imageToText(block.Source)
			case "document":
				if msg.Content != "" {
					msg.Content += "\n"
				}
				msg.Content += documentToText(block.Source)
			default:
				continue
			}
		}
		if msg.Content != "" || len(out) == 0 {
			out = append([]Message{msg}, out...)
		}

	case "assistant":
		msg := Message{Role: "assistant"}
		for _, block := range m.Content {
			switch block.Type {
			case "text":
				msg.Content += block.Text
			case "thinking":
				msg.Content += "[thinking]" + block.Thinking + "[/thinking]"
			case "tool_use":
				args := string(block.Input)
				if !json.Valid(block.Input) {
					args = "{}"
				}
				msg.ToolCalls = append(msg.ToolCalls, ToolCall{
					Index: len(msg.ToolCalls),
					ID:    block.ID,
					Type:  "function",
					Function: FunctionCall{
						Name:      block.Name,
						Arguments: args,
					},
				})
			}
		}
		out = append(out, msg)
	}
	return out, nil
}

func toolResultString(content json.RawMessage) string {
	if len(content) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(content, &s); err == nil {
		return s
	}
	return string(content)
}

func imageToText(source *ImageSource) string {
	if source == nil || source.Data == "" {
		return "[image]"
	}
	keep := source.Data
	if len(keep) > 256<<10 {
		keep = keep[:256<<10]
	}
	return fmt.Sprintf("data:%s;base64,%s", source.MediaType, keep)
}

func documentToText(source *ImageSource) string {
	if source == nil || source.Data == "" {
		return "[document]"
	}
	keep := source.Data
	if len(keep) > 256<<10 {
		keep = keep[:256<<10]
	}
	return fmt.Sprintf("data:%s;base64,%s", source.MediaType, keep)
}
