package middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"lingma2api/internal/db"
)

type LoggingConfig struct {
	StorageMode    string
	TruncateLength int
}

func Logging(dbInst *db.Store, cfg LoggingConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}

			bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
			if err != nil {
				http.Error(w, "read body failed", http.StatusBadRequest)
				return
			}
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			start := time.Now()
			rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rec, r)
			elapsed := time.Since(start)

			logEntry := &db.RequestLog{
				ID:               generateID(),
				CreatedAt:        start,
				DownstreamMethod: r.Method,
				DownstreamPath:   r.URL.Path,
				DownstreamReq:    string(bodyBytes),
				DownstreamResp:   rec.buf.String(),
				UpstreamStatus:   rec.statusCode,
				Status:           "success",
				DownstreamMs:     int(elapsed.Milliseconds()),
			}
			if rec.statusCode >= 400 {
				logEntry.Status = "error"
			}

			var reqBody struct {
				Model string `json:"model"`
			}
			json.Unmarshal(bodyBytes, &reqBody)
			logEntry.Model = reqBody.Model
			logEntry.MappedModel = reqBody.Model

			extractTokensFromResponse(logEntry)

			if cfg.StorageMode == "truncated" && cfg.TruncateLength > 0 {
				logEntry.DownstreamReq = truncate(logEntry.DownstreamReq, cfg.TruncateLength)
				logEntry.DownstreamResp = truncate(logEntry.DownstreamResp, cfg.TruncateLength)
			}

			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = dbInst.InsertLog(ctx, logEntry)
			}()
		})
	}
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	buf        bytes.Buffer
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.buf.Write(b)
	return r.ResponseWriter.Write(b)
}

func (r *responseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func extractTokensFromResponse(log *db.RequestLog) {
	var resp struct {
		Usage *struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal([]byte(log.DownstreamResp), &resp) == nil && resp.Usage != nil {
		log.PromptTokens = resp.Usage.PromptTokens
		log.CompletionTokens = resp.Usage.CompletionTokens
		log.TotalTokens = resp.Usage.TotalTokens
		return
	}
	total := len(log.DownstreamResp) / 4
	if total > 0 {
		log.TotalTokens = total
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b)
}
