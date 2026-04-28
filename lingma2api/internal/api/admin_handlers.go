package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"lingma2api/internal/db"
	"lingma2api/internal/proxy"
)

func (server *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "24h"
	}
	data, err := server.db.GetDashboardData(r.Context(), rangeParam)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (server *Server) handleAdminAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	cred, _ := server.deps.Credentials.Current(r.Context())
	today, week, total, _ := server.db.GetTokenStats(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"credential": cred,
		"status":     server.deps.Credentials.Status(),
		"token_stats": map[string]int{
			"today": today,
			"week":  week,
			"total": total,
		},
	})
}

func (server *Server) handleAdminAccountRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	cred, err := server.deps.Credentials.Refresh(r.Context())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential": cred})
}

func (server *Server) handleAdminSettingsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	settings, err := server.db.GetSettings(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (server *Server) handleAdminSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeMethodNotAllowed(w, http.MethodPut)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var settings map[string]string
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := server.db.UpdateSettings(r.Context(), settings); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (server *Server) handleAdminLogsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 || limit > 200 {
		limit = 50
	}

	filter := db.LogFilter{
		Status: q.Get("status"),
		Model:  q.Get("model"),
	}
	if from := q.Get("from"); from != "" {
		filter.From, _ = parseTime(from)
	}
	if to := q.Get("to"); to != "" {
		filter.To, _ = parseTime(to)
	}

	result, err := server.db.ListLogs(r.Context(), filter, page, limit)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (server *Server) handleAdminLogsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/logs/")
	id = strings.TrimSuffix(id, "/replay")
	if id == "" {
		writeOpenAIError(w, http.StatusBadRequest, "missing log id")
		return
	}
	log, err := server.db.GetLog(r.Context(), id)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "log not found")
		return
	}
	writeJSON(w, http.StatusOK, log)
}

func (server *Server) handleAdminLogsReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/logs/")
	id = strings.TrimSuffix(id, "/replay")
	replayReq, err := server.db.GetLog(r.Context(), id)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "log not found")
		return
	}
	bodyBytes, _ := io.ReadAll(r.Body)
	var replayBody io.ReadCloser
	if len(bodyBytes) > 0 {
		replayBody = io.NopCloser(bytes.NewReader(bodyBytes))
	} else {
		replayBody = io.NopCloser(strings.NewReader(replayReq.DownstreamReq))
	}
	newReq := r.Clone(r.Context())
	newReq.Method = http.MethodPost
	newReq.URL.Path = "/v1/chat/completions"
	newReq.Body = replayBody
	server.handleChatCompletions(w, newReq)
}

func (server *Server) handleAdminLogsCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	settings, _ := server.db.GetSettings(r.Context())
	days := 30
	if d, err := strconv.Atoi(settings["retention_days"]); err == nil {
		days = d
	}
	affected, err := server.db.CleanupExpiredLogs(r.Context(), days)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": affected})
}

func (server *Server) handleAdminLogsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	q := r.URL.Query()
	filter := db.LogFilter{Status: q.Get("status"), Model: q.Get("model")}
	if from := q.Get("from"); from != "" {
		filter.From, _ = parseTime(from)
	}
	if to := q.Get("to"); to != "" {
		filter.To, _ = parseTime(to)
	}

	logs, err := server.db.ExportLogs(r.Context(), filter)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	format := q.Get("format")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=logs.csv")
		w.Write([]byte("id,created_at,model,status,prompt_tokens,completion_tokens,total_tokens,ttft_ms\n"))
		for _, l := range logs {
			w.Write([]byte(l.ID + "," + l.CreatedAt.Format("2006-01-02T15:04:05Z") + "," + l.Model + "," + l.Status + "," +
				strconv.Itoa(l.PromptTokens) + "," + strconv.Itoa(l.CompletionTokens) + "," + strconv.Itoa(l.TotalTokens) + "," + strconv.Itoa(l.TTFTMs) + "\n"))
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=logs.json")
	json.NewEncoder(w).Encode(logs)
}

func (server *Server) handleAdminStatsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "24h"
	}
	data, err := server.db.GetDashboardData(r.Context(), rangeParam)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=stats.json")
	json.NewEncoder(w).Encode(data)
}

func (server *Server) handleAdminMappingsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	mappings, err := server.db.ListMappings(r.Context())
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, mappings)
}

func (server *Server) handleAdminMappingsCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var m db.ModelMapping
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := server.db.CreateMapping(r.Context(), &m); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (server *Server) handleAdminMappingsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeMethodNotAllowed(w, http.MethodPut)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/mappings/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var m db.ModelMapping
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid json")
		return
	}
	m.ID = id
	if err := server.db.UpdateMapping(r.Context(), &m); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (server *Server) handleAdminMappingsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeMethodNotAllowed(w, http.MethodDelete)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/mappings/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := server.db.DeleteMapping(r.Context(), id); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (server *Server) handleAdminMappingsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !server.isAdminAuthorized(r) {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Model string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid json")
		return
	}
	mappings, _ := server.db.GetEnabledMappings(r.Context())
	for _, m := range mappings {
		if matched, _ := matchRegex(m.Pattern, req.Model); matched {
			writeJSON(w, http.StatusOK, map[string]any{
				"matched":     true,
				"rule_name":   m.Name,
				"rule_id":     m.ID,
				"target":      m.Target,
				"input_model": req.Model,
			})
			return
		}
	}
	target := req.Model
	if alias, ok := proxy.DefaultAliases()[req.Model]; ok {
		target = alias
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matched":     false,
		"input_model": req.Model,
		"target":      target,
	})
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

func matchRegex(pattern, input string) (bool, error) {
	if len(pattern) > 1024 {
		return false, fmt.Errorf("pattern too long")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(input), nil
}
