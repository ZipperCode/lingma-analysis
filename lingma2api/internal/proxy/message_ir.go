package proxy

// ConvertMessagesToIR normalizes incoming messages for downstream processing.
// Phase 1: identity pass-through (OpenAI messages are already in IR format).
// Phase 3: adds Anthropic content-block ↔ OpenAI IR conversion.
func ConvertMessagesToIR(messages []Message) []Message {
	return messages
}

// ConvertIRToMessages converts IR messages back to the target format.
// Phase 1: identity pass-through.
// Phase 3: adds OpenAI IR ↔ Anthropic content-block conversion.
func ConvertIRToMessages(ir []Message) []Message {
	return ir
}

// HasToolCalls returns true if any message in the slice contains tool_calls.
func HasToolCalls(messages []Message) bool {
	for _, m := range messages {
		if len(m.ToolCalls) > 0 {
			return true
		}
	}
	return false
}

// LastAssistantToolCalls returns the tool_calls from the most recent assistant message, if any.
func LastAssistantToolCalls(messages []Message) []ToolCall {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "assistant" && len(messages[i].ToolCalls) > 0 {
			return messages[i].ToolCalls
		}
	}
	return nil
}
