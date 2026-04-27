package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type outerSSEPayload struct {
	Body            string `json:"body"`
	StatusCodeValue int    `json:"statusCodeValue"`
}

type innerSSEPayload struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

func ParseSSELine(line string) (SSEEvent, bool, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || !strings.HasPrefix(trimmed, "data:") {
		return SSEEvent{}, false, nil
	}

	payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
	if payload == "[DONE]" {
		return SSEEvent{Done: true}, true, nil
	}

	var outer outerSSEPayload
	if err := json.Unmarshal([]byte(payload), &outer); err != nil {
		return SSEEvent{}, false, err
	}
	if outer.StatusCodeValue >= 400 {
		return SSEEvent{}, false, fmt.Errorf("upstream sse status %d", outer.StatusCodeValue)
	}
	if outer.Body == "" {
		return SSEEvent{}, false, nil
	}
	if outer.Body == "[DONE]" {
		return SSEEvent{Done: true}, true, nil
	}

	var inner innerSSEPayload
	if err := json.Unmarshal([]byte(outer.Body), &inner); err != nil {
		return SSEEvent{}, false, err
	}

	var builder strings.Builder
	for _, choice := range inner.Choices {
		builder.WriteString(choice.Delta.Content)
	}
	return SSEEvent{Content: builder.String()}, true, nil
}

func ScanSSE(reader io.Reader, onEvent func(SSEEvent) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		event, ok, err := ParseSSELine(scanner.Text())
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := onEvent(event); err != nil {
			return err
		}
		if event.Done {
			return nil
		}
	}
	return scanner.Err()
}

func CollectSSEContent(reader io.Reader) (string, error) {
	var builder strings.Builder
	err := ScanSSE(reader, func(event SSEEvent) error {
		builder.WriteString(event.Content)
		return nil
	})
	if err != nil {
		return "", err
	}
	return builder.String(), nil
}
