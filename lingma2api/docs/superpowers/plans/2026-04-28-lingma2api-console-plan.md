# Lingma2API Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an embedded React management console to lingma2api with dashboard, request logs, account management, model mapping, and settings pages.

**Architecture:** Go backend gains SQLite storage + admin API endpoints; React SPA (Vite + React Router + Recharts) is built into `frontend-dist/` and embedded via `embed.FS`; a logging middleware intercepts all Chat API calls to record full upstream/downstream request/response data.

**Tech Stack:** Go 1.24 + `modernc.org/sqlite` (pure-Go) / React 18 + TypeScript + Vite + React Router (HashRouter) + Recharts

---

## File Structure Summary

### New Go Files
- `internal/db/store.go` — SQLite init + Store struct
- `internal/db/migrations.go` — DDL for 3 tables
- `internal/db/logs.go` — request_logs CRUD + export
- `internal/db/mappings.go` — model_mappings CRUD
- `internal/db/settings.go` — settings key-value CRUD
- `internal/db/stats.go` — aggregation queries for dashboard
- `internal/middleware/logging.go` — HTTP middleware intercepting Chat API

### Modified Go Files
- `internal/api/server.go` — add admin routes, DB dependency, embed FS serve
- `internal/api/admin_handlers.go` — all new admin HTTP handlers (new file)
- `main.go` — init DB, pass to server, start cleanup goroutine
- `go.mod` — add SQLite dependency

### New Frontend Files (`frontend/`)
- `package.json`, `vite.config.ts`, `tsconfig.json`, `tsconfig.app.json`, `tsconfig.node.json`, `index.html`
- `src/main.tsx`, `src/App.tsx`
- `src/types/index.ts` — all TypeScript types
- `src/api/client.ts` — fetch wrapper with admin token
- `src/hooks/useAdminToken.ts`, `src/hooks/useSettings.ts`, `src/hooks/usePolling.ts`
- `src/pages/Dashboard.tsx`, `src/pages/Logs.tsx`, `src/pages/LogDetail.tsx`, `src/pages/Account.tsx`, `src/pages/Models.tsx`, `src/pages/Settings.tsx`
- `src/components/Layout.tsx`, `src/components/StatCard.tsx`, `src/components/CodeViewer.tsx`, `src/components/ReplayModal.tsx`, `src/components/MappingRuleEditor.tsx`, `src/components/Pagination.tsx`
- `src/styles/global.css`

---

### Task 1: Add SQLite dependency and DB init

**Files:**
- Create: `internal/db/store.go`
- Create: `internal/db/migrations.go`
- Modify: `go.mod`

- [ ] **Step 1: Add SQLite Go dependency**

Run:
```bash
cd D:/Project/lingma/lingma2api && go get modernc.org/sqlite
```

- [ ] **Step 2: Create `internal/db/store.go`**

```go
package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON", path)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1)
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return &Store{db: conn}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Migrate() error {
	return runMigrations(s.db)
}
```

- [ ] **Step 3: Create `internal/db/migrations.go`**

```go
package db

import "database/sql"

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS request_logs (
		id           TEXT PRIMARY KEY,
		created_at   DATETIME NOT NULL,
		session_id   TEXT DEFAULT '',
		model        TEXT NOT NULL,
		mapped_model TEXT NOT NULL,
		stream       INTEGER NOT NULL DEFAULT 0,
		status       TEXT NOT NULL,
		error_msg    TEXT DEFAULT '',
		downstream_method TEXT NOT NULL,
		downstream_path   TEXT NOT NULL,
		downstream_req    TEXT NOT NULL,
		downstream_resp   TEXT NOT NULL,
		upstream_req      TEXT NOT NULL,
		upstream_resp     TEXT NOT NULL,
		upstream_status   INTEGER NOT NULL,
		prompt_tokens     INTEGER NOT NULL DEFAULT 0,
		completion_tokens INTEGER NOT NULL DEFAULT 0,
		total_tokens      INTEGER NOT NULL DEFAULT 0,
		ttft_ms           INTEGER NOT NULL DEFAULT 0,
		upstream_ms       INTEGER NOT NULL DEFAULT 0,
		downstream_ms     INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_logs_created ON request_logs(created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_logs_model ON request_logs(model)`,
	`CREATE INDEX IF NOT EXISTS idx_logs_status ON request_logs(status)`,

	`CREATE TABLE IF NOT EXISTS model_mappings (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		priority    INTEGER NOT NULL DEFAULT 0,
		name        TEXT NOT NULL,
		pattern     TEXT NOT NULL,
		target      TEXT NOT NULL,
		enabled     INTEGER NOT NULL DEFAULT 1,
		created_at  DATETIME NOT NULL,
		updated_at  DATETIME NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
}

func runMigrations(conn *sql.DB) error {
	for _, ddl := range migrations {
		if _, err := conn.Exec(ddl); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 4: Verify compilation**

Run:
```bash
cd D:/Project/lingma/lingma2api && go build ./internal/db/
```
Expected: no output (success)

---

### Task 2: DB request_logs CRUD

**Files:**
- Create: `internal/db/logs.go`
- Create: `internal/db/logs_test.go`

- [ ] **Step 1: Create `internal/db/logs.go`**

```go
package db

import (
	"context"
	"database/sql"
	"time"
)

type RequestLog struct {
	ID               string    `json:"id"`
	CreatedAt        time.Time `json:"created_at"`
	SessionID        string    `json:"session_id"`
	Model            string    `json:"model"`
	MappedModel      string    `json:"mapped_model"`
	Stream           bool      `json:"stream"`
	Status           string    `json:"status"`
	ErrorMsg         string    `json:"error_msg"`
	DownstreamMethod string    `json:"downstream_method"`
	DownstreamPath   string    `json:"downstream_path"`
	DownstreamReq    string    `json:"downstream_req"`
	DownstreamResp   string    `json:"downstream_resp"`
	UpstreamReq      string    `json:"upstream_req"`
	UpstreamResp     string    `json:"upstream_resp"`
	UpstreamStatus   int       `json:"upstream_status"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
	TotalTokens      int       `json:"total_tokens"`
	TTFTMs           int       `json:"ttft_ms"`
	UpstreamMs       int       `json:"upstream_ms"`
	DownstreamMs     int       `json:"downstream_ms"`
}

type LogFilter struct {
	Status string
	Model  string
	From   time.Time
	To     time.Time
}

type LogListResult struct {
	Items []RequestLog `json:"items"`
	Total int          `json:"total"`
	Page  int          `json:"page"`
	Limit int          `json:"limit"`
}

func (s *Store) InsertLog(ctx context.Context, log *RequestLog) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO request_logs (id,created_at,session_id,model,mapped_model,stream,status,error_msg,
			downstream_method,downstream_path,downstream_req,downstream_resp,
			upstream_req,upstream_resp,upstream_status,
			prompt_tokens,completion_tokens,total_tokens,ttft_ms,upstream_ms,downstream_ms)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		log.ID, log.CreatedAt, log.SessionID, log.Model, log.MappedModel, boolToInt(log.Stream),
		log.Status, log.ErrorMsg,
		log.DownstreamMethod, log.DownstreamPath, log.DownstreamReq, log.DownstreamResp,
		log.UpstreamReq, log.UpstreamResp, log.UpstreamStatus,
		log.PromptTokens, log.CompletionTokens, log.TotalTokens, log.TTFTMs, log.UpstreamMs, log.DownstreamMs,
	)
	return err
}

func (s *Store) GetLog(ctx context.Context, id string) (RequestLog, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,created_at,session_id,model,mapped_model,stream,status,error_msg,
		 downstream_method,downstream_path,downstream_req,downstream_resp,
		 upstream_req,upstream_resp,upstream_status,
		 prompt_tokens,completion_tokens,total_tokens,ttft_ms,upstream_ms,downstream_ms
		 FROM request_logs WHERE id=?`, id)
	return scanLog(row)
}

func (s *Store) ListLogs(ctx context.Context, filter LogFilter, page, limit int) (LogListResult, error) {
	where, args := buildLogWhere(filter)

	var total int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM request_logs WHERE 1=1"+where, args...).Scan(&total)
	if err != nil {
		return LogListResult{}, err
	}

	offset := (page - 1) * limit
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,created_at,session_id,model,mapped_model,stream,status,error_msg,
		 downstream_method,downstream_path,downstream_req,downstream_resp,
		 upstream_req,upstream_resp,upstream_status,
		 prompt_tokens,completion_tokens,total_tokens,ttft_ms,upstream_ms,downstream_ms
		 FROM request_logs WHERE 1=1`+where+
			` ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return LogListResult{}, err
	}
	defer rows.Close()

	var items []RequestLog
	for rows.Next() {
		l, err := scanLogRows(rows)
		if err != nil {
			return LogListResult{}, err
		}
		items = append(items, l)
	}
	return LogListResult{Items: items, Total: total, Page: page, Limit: limit}, rows.Err()
}

func (s *Store) CleanupExpiredLogs(ctx context.Context, days int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -days)
	result, err := s.db.ExecContext(ctx, `DELETE FROM request_logs WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) ExportLogs(ctx context.Context, filter LogFilter) ([]RequestLog, error) {
	where, args := buildLogWhere(filter)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,created_at,session_id,model,mapped_model,stream,status,error_msg,
		 downstream_method,downstream_path,downstream_req,downstream_resp,
		 upstream_req,upstream_resp,upstream_status,
		 prompt_tokens,completion_tokens,total_tokens,ttft_ms,upstream_ms,downstream_ms
		 FROM request_logs WHERE 1=1`+where+` ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []RequestLog
	for rows.Next() {
		l, err := scanLogRows(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, l)
	}
	return items, rows.Err()
}

func buildLogWhere(filter LogFilter) (string, []any) {
	var where string
	var args []any
	if filter.Status != "" {
		where += " AND status=?"
		args = append(args, filter.Status)
	}
	if filter.Model != "" {
		where += " AND model=?"
		args = append(args, filter.Model)
	}
	if !filter.From.IsZero() {
		where += " AND created_at>=?"
		args = append(args, filter.From)
	}
	if !filter.To.IsZero() {
		where += " AND created_at<=?"
		args = append(args, filter.To)
	}
	return where, args
}

func scanLog(row *sql.Row) (RequestLog, error) {
	var l RequestLog
	var streamInt int
	err := row.Scan(
		&l.ID, &l.CreatedAt, &l.SessionID, &l.Model, &l.MappedModel, &streamInt, &l.Status, &l.ErrorMsg,
		&l.DownstreamMethod, &l.DownstreamPath, &l.DownstreamReq, &l.DownstreamResp,
		&l.UpstreamReq, &l.UpstreamResp, &l.UpstreamStatus,
		&l.PromptTokens, &l.CompletionTokens, &l.TotalTokens, &l.TTFTMs, &l.UpstreamMs, &l.DownstreamMs,
	)
	l.Stream = streamInt != 0
	return l, err
}

func scanLogRows(rows *sql.Rows) (RequestLog, error) {
	var l RequestLog
	var streamInt int
	err := rows.Scan(
		&l.ID, &l.CreatedAt, &l.SessionID, &l.Model, &l.MappedModel, &streamInt, &l.Status, &l.ErrorMsg,
		&l.DownstreamMethod, &l.DownstreamPath, &l.DownstreamReq, &l.DownstreamResp,
		&l.UpstreamReq, &l.UpstreamResp, &l.UpstreamStatus,
		&l.PromptTokens, &l.CompletionTokens, &l.TotalTokens, &l.TTFTMs, &l.UpstreamMs, &l.DownstreamMs,
	)
	l.Stream = streamInt != 0
	return l, err
}

func boolToInt(b bool) int {
	if b { return 1 }
	return 0
}
```

- [ ] **Step 2: Create `internal/db/logs_test.go`**

```go
package db

import (
	"context"
	"testing"
	"time"
)

func TestInsertAndGetLog(t *testing.T) {
	store, cleanup := tempStore(t)
	defer cleanup()

	ctx := context.Background()
	log := &RequestLog{
		ID: "test-1", CreatedAt: time.Now(), Model: "gpt-4o", MappedModel: "lingma-gpt4",
		Status: "success", DownstreamMethod: "POST", DownstreamPath: "/v1/chat/completions",
		DownstreamReq: `{}`, DownstreamResp: `{}`, UpstreamReq: `{}`, UpstreamResp: `{}`,
		UpstreamStatus: 200, PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150,
		TTFTMs: 200, UpstreamMs: 1500, DownstreamMs: 1600,
	}
	if err := store.InsertLog(ctx, log); err != nil {
		t.Fatalf("InsertLog: %v", err)
	}

	got, err := store.GetLog(ctx, "test-1")
	if err != nil {
		t.Fatalf("GetLog: %v", err)
	}
	if got.Model != "gpt-4o" || got.PromptTokens != 100 {
		t.Fatalf("unexpected: model=%s prompt=%d", got.Model, got.PromptTokens)
	}
}

func TestListLogsWithFilter(t *testing.T) {
	store, cleanup := tempStore(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()
	store.InsertLog(ctx, &RequestLog{ID: "a", CreatedAt: now.Add(-time.Hour), Model: "m1", Status: "success",
		DownstreamMethod: "POST", DownstreamPath: "/", DownstreamReq: `{}`, DownstreamResp: `{}`,
		UpstreamReq: `{}`, UpstreamResp: `{}`})
	store.InsertLog(ctx, &RequestLog{ID: "b", CreatedAt: now, Model: "m2", Status: "error",
		DownstreamMethod: "POST", DownstreamPath: "/", DownstreamReq: `{}`, DownstreamResp: `{}`,
		UpstreamReq: `{}`, UpstreamResp: `{}`})

	result, err := store.ListLogs(ctx, LogFilter{Status: "error"}, 1, 10)
	if err != nil {
		t.Fatalf("ListLogs: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected 1 error log, got %d", result.Total)
	}
	if result.Items[0].ID != "b" {
		t.Fatalf("expected log b, got %s", result.Items[0].ID)
	}
}

func TestCleanupExpiredLogs(t *testing.T) {
	store, cleanup := tempStore(t)
	defer cleanup()

	ctx := context.Background()
	old := time.Now().AddDate(0, 0, -60)
	store.InsertLog(ctx, &RequestLog{ID: "old", CreatedAt: old, Model: "m", Status: "ok",
		DownstreamMethod: "POST", DownstreamPath: "/", DownstreamReq: `{}`, DownstreamResp: `{}`,
		UpstreamReq: `{}`, UpstreamResp: `{}`})
	store.InsertLog(ctx, &RequestLog{ID: "new", CreatedAt: time.Now(), Model: "m", Status: "ok",
		DownstreamMethod: "POST", DownstreamPath: "/", DownstreamReq: `{}`, DownstreamResp: `{}`,
		UpstreamReq: `{}`, UpstreamResp: `{}`})

	affected, err := store.CleanupExpiredLogs(ctx, 30)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if affected != 1 {
		t.Fatalf("expected 1 deleted, got %d", affected)
	}
	result, _ := store.ListLogs(ctx, LogFilter{}, 1, 10)
	if result.Total != 1 || result.Items[0].ID != "new" {
		t.Fatalf("expected only new log remaining")
	}
}
```

- [ ] **Step 3: Verify tests pass**

Run:
```bash
cd D:/Project/lingma/lingma2api && go test ./internal/db/ -run TestInsert -v
```

> Note: `tempStore` helper is defined in Task 3 (settings_test.go). Implement Task 2 and Task 3 together, or add the helper temporarily here.

---

### Task 3: DB model_mappings + settings CRUD

**Files:**
- Create: `internal/db/mappings.go`
- Create: `internal/db/settings.go`
- Create: `internal/db/db_test_helper.go`

- [ ] **Step 1: Create `internal/db/db_test_helper.go`**

```go
package db

import (
	"os"
	"testing"
)

func tempStore(t *testing.T) (*Store, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "lingma2api-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	store, err := Open(f.Name())
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}
	if err := store.Migrate(); err != nil {
		store.Close()
		os.Remove(f.Name())
		t.Fatal(err)
	}
	return store, func() {
		store.Close()
		os.Remove(f.Name())
	}
}
```

- [ ] **Step 2: Create `internal/db/mappings.go`**

```go
package db

import (
	"context"
	"database/sql"
	"time"
)

type ModelMapping struct {
	ID        int       `json:"id"`
	Priority  int       `json:"priority"`
	Name      string    `json:"name"`
	Pattern   string    `json:"pattern"`
	Target    string    `json:"target"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Store) ListMappings(ctx context.Context) ([]ModelMapping, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,priority,name,pattern,target,enabled,created_at,updated_at FROM model_mappings ORDER BY priority ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []ModelMapping
	for rows.Next() {
		var m ModelMapping
		var enabled int
		if err := rows.Scan(&m.ID, &m.Priority, &m.Name, &m.Pattern, &m.Target, &enabled, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		m.Enabled = enabled != 0
		items = append(items, m)
	}
	return items, rows.Err()
}

func (s *Store) CreateMapping(ctx context.Context, m *ModelMapping) error {
	now := time.Now()
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO model_mappings (priority,name,pattern,target,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`,
		m.Priority, m.Name, m.Pattern, m.Target, boolToInt(m.Enabled), now, now)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	m.ID = int(id)
	m.CreatedAt = now
	m.UpdatedAt = now
	return nil
}

func (s *Store) UpdateMapping(ctx context.Context, m *ModelMapping) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE model_mappings SET priority=?,name=?,pattern=?,target=?,enabled=?,updated_at=? WHERE id=?`,
		m.Priority, m.Name, m.Pattern, m.Target, boolToInt(m.Enabled), time.Now(), m.ID)
	return err
}

func (s *Store) DeleteMapping(ctx context.Context, id int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM model_mappings WHERE id=?`, id)
	return err
}

func (s *Store) GetEnabledMappings(ctx context.Context) ([]ModelMapping, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,priority,name,pattern,target,enabled,created_at,updated_at FROM model_mappings WHERE enabled=1 ORDER BY priority ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ModelMapping
	for rows.Next() {
		var m ModelMapping
		var enabled int
		if err := rows.Scan(&m.ID, &m.Priority, &m.Name, &m.Pattern, &m.Target, &enabled, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		m.Enabled = enabled != 0
		items = append(items, m)
	}
	return items, rows.Err()
}
```

- [ ] **Step 3: Create `internal/db/settings.go`**

```go
package db

import "context"

var defaultSettings = map[string]string{
	"storage_mode":      "full",
	"truncate_length":   "102400",
	"retention_days":    "30",
	"polling_interval":  "0",
	"theme":             "light",
	"request_timeout":   "90",
}

func (s *Store) GetSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]string)
	for k, v := range defaultSettings {
		result[k] = v
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		result[k] = v
	}
	return result, rows.Err()
}

func (s *Store) UpdateSettings(ctx context.Context, settings map[string]string) error {
	for k, v := range settings {
		if _, ok := defaultSettings[k]; !ok {
			continue
		}
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			k, v)
		if err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 4: Run all db tests**

Run:
```bash
cd D:/Project/lingma/lingma2api && go test ./internal/db/ -v
```
Expected: all tests PASS

---

### Task 4: DB stats aggregation

**Files:**
- Create: `internal/db/stats.go`
- Add test in: `internal/db/stats_test.go`

- [ ] **Step 1: Create `internal/db/stats.go`**

```go
package db

import (
	"context"
	"time"
)

type DashboardStats struct {
	TotalRequests int     `json:"total_requests"`
	SuccessRate   float64 `json:"success_rate"`
	AvgTTFTMs     int     `json:"avg_ttft_ms"`
	TotalTokens   int     `json:"total_tokens"`
}

type TimeSeriesPoint struct {
	Time        time.Time `json:"time"`
	Rate        float64   `json:"rate,omitempty"`
	Prompt      int       `json:"prompt"`
	Completion  int       `json:"completion"`
}

type ModelDistPoint struct {
	Model string `json:"model"`
	Count int    `json:"count"`
}

type DashboardData struct {
	Stats              DashboardStats     `json:"stats"`
	SuccessRateSeries  []TimeSeriesPoint  `json:"success_rate_series"`
	TokenSeries        []TimeSeriesPoint  `json:"token_series"`
	ModelDistribution  []ModelDistPoint   `json:"model_distribution"`
}

func (s *Store) GetDashboardData(ctx context.Context, rangeStr string) (DashboardData, error) {
	hours := rangeToHours(rangeStr)
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	granularity := granularityForRange(hours)

	data := DashboardData{}

	row := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END)*100.0/COUNT(*),0),
		 COALESCE(AVG(ttft_ms),0), COALESCE(SUM(total_tokens),0)
		 FROM request_logs WHERE created_at>=?`, cutoff)
	if err := row.Scan(&data.Stats.TotalRequests, &data.Stats.SuccessRate, &data.Stats.AvgTTFTMs, &data.Stats.TotalTokens); err != nil {
		return data, err
	}

	data.SuccessRateSeries, _ = s.querySuccessRateSeries(ctx, cutoff, granularity)
	data.TokenSeries, _ = s.queryTokenSeries(ctx, cutoff, granularity)
	data.ModelDistribution, _ = s.queryModelDistribution(ctx, cutoff)
	return data, nil
}

func (s *Store) querySuccessRateSeries(ctx context.Context, cutoff time.Time, gran string) ([]TimeSeriesPoint, error) {
	// SQLite strftime groups by granularity
	rows, err := s.db.QueryContext(ctx,
		`SELECT strftime(?, created_at) as t, COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END)*100.0/COUNT(*),0) as r
		 FROM request_logs WHERE created_at>=? GROUP BY t ORDER BY t`, gran, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var series []TimeSeriesPoint
	for rows.Next() {
		var p TimeSeriesPoint
		var t string
		if err := rows.Scan(&t, &p.Rate); err != nil {
			return nil, err
		}
		p.Time, _ = time.Parse("2006-01-02T15:04:05Z", t+":00:00Z")
		series = append(series, p)
	}
	return series, rows.Err()
}

func (s *Store) queryTokenSeries(ctx context.Context, cutoff time.Time, gran string) ([]TimeSeriesPoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT strftime(?, created_at) as t, COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0)
		 FROM request_logs WHERE created_at>=? GROUP BY t ORDER BY t`, gran, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var series []TimeSeriesPoint
	for rows.Next() {
		var p TimeSeriesPoint
		var t string
		if err := rows.Scan(&t, &p.Prompt, &p.Completion); err != nil {
			return nil, err
		}
		p.Time, _ = time.Parse("2006-01-02T15:04:05Z", t+":00:00Z")
		series = append(series, p)
	}
	return series, rows.Err()
}

func (s *Store) queryModelDistribution(ctx context.Context, cutoff time.Time) ([]ModelDistPoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT mapped_model, COUNT(*) as c FROM request_logs WHERE created_at>=? GROUP BY mapped_model ORDER BY c DESC LIMIT 10`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dist []ModelDistPoint
	for rows.Next() {
		var p ModelDistPoint
		if err := rows.Scan(&p.Model, &p.Count); err != nil {
			return nil, err
		}
		dist = append(dist, p)
	}
	return dist, rows.Err()
}

func (s *Store) GetTokenStats(ctx context.Context) (today, week, total int, err error) {
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	weekStart := todayStart.AddDate(0, 0, -7)

	s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_tokens),0) FROM request_logs WHERE created_at>=?`, todayStart).Scan(&today)
	s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_tokens),0) FROM request_logs WHERE created_at>=?`, weekStart).Scan(&week)
	s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_tokens),0) FROM request_logs`).Scan(&total)
	return
}

func rangeToHours(r string) int {
	switch r {
	case "1h":
		return 1
	case "7d":
		return 168
	case "30d":
		return 720
	default:
		return 24
	}
}

func granularityForRange(hours int) string {
	switch {
	case hours <= 1:
		return "%Y-%m-%dT%H:%M"
	case hours <= 24:
		return "%Y-%m-%dT%H:00"
	case hours <= 168:
		return "%Y-%m-%dT00:00"
	default:
		return "%Y-%m-%d"
	}
}
```

- [ ] **Step 2: Verify compilation**

Run:
```bash
cd D:/Project/lingma/lingma2api && go build ./internal/db/
```

---

### Task 5: Logging middleware

**Files:**
- Create: `internal/middleware/logging.go`
- Create: `internal/middleware/logging_test.go`

- [ ] **Step 1: Create `internal/middleware/logging.go`**

```go
package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"lingma2api/internal/db"
)

type DB interface {
	InsertLog(ctx interface{}, log *db.RequestLog) error
}

type LoggingConfig struct {
	StorageMode    string // "full" or "truncated"
	TruncateLength int    // bytes
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

			// Parse model from request
			var reqBody struct {
				Model string `json:"model"`
			}
			json.Unmarshal(bodyBytes, &reqBody)
			logEntry.Model = reqBody.Model
			logEntry.MappedModel = reqBody.Model

			// Extract token count from response
			extractTokensFromResponse(logEntry)

			// Apply storage mode
			if cfg.StorageMode == "truncated" && cfg.TruncateLength > 0 {
				logEntry.DownstreamReq = truncate(logEntry.DownstreamReq, cfg.TruncateLength)
				logEntry.DownstreamResp = truncate(logEntry.DownstreamResp, cfg.TruncateLength)
			}

			// Async write
			go dbInst.InsertLog(nil, logEntry)
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

func extractTokensFromResponse(log *db.RequestLog) {
	// Try parsing as non-stream JSON
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
	// Fallback: estimate from content length
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
	b := make([]byte, 16)
	for i := range b {
		b[i] = "0123456789abcdef"[time.Now().UnixNano()%16]
		time.Sleep(1)
	}
	return string(b)
}
```

- [ ] **Step 2: Add `InsertLog` convenience wrapper to `db.Store`**

Add to `internal/db/logs.go`:
```go
// InsertLog is already defined above — no change needed.
// This step is for reference; the middleware uses store.InsertLog directly.
```

- [ ] **Step 3: Verify compilation**

Run:
```bash
cd D:/Project/lingma/lingma2api && go build ./internal/middleware/
```

---

### Task 6: Admin API handlers — dashboard, account, settings

**Files:**
- Create: `internal/api/admin_handlers.go`
- Create: `internal/api/admin_handlers_test.go`
- Modify: `internal/api/server.go`

- [ ] **Step 1: Create `internal/api/admin_handlers.go`**

```go
package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"lingma2api/internal/db"
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
			"today":  today,
			"week":   week,
			"total":  total,
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
	if page < 1 { page = 1 }
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 || limit > 200 { limit = 50 }

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
	// Forward to /v1/chat/completions internally
	// Use the provided body or the original log's downstream_req
	// This reuses the existing chat handler logic
	replayReq, err := server.db.GetLog(r.Context(), id)
	if err != nil {
		writeOpenAIError(w, http.StatusNotFound, "log not found")
		return
	}
	// Build new request to forward to chat handler
	body := r.Body
	if r.ContentLength == 0 {
		body = strings.NewReader(replayReq.DownstreamReq)
	}
	newReq := r.Clone(r.Context())
	newReq.Method = http.MethodPost
	newReq.URL.Path = "/v1/chat/completions"
	newReq.Body = body
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
	if from := q.Get("from"); from != "" { filter.From, _ = parseTime(from) }
	if to := q.Get("to"); to != "" { filter.To, _ = parseTime(to) }

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
	if rangeParam == "" { rangeParam = "24h" }
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
	// Check built-in aliases
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
```

> Note: `matchRegex` and the `import "time"` need to be added. `matchRegex` uses `regexp.MatchString`.

- [ ] **Step 2: Add `matchRegex` helper and `import "time"` at the top of admin_handlers.go**

Add at the end of admin_handlers.go:
```go
func matchRegex(pattern, input string) (bool, error) {
	return regexp.MatchString(pattern, input)
}
```

And ensure `import "regexp"` and `import "time"` are in the import block.

- [ ] **Step 3: Update `server.go` to hold db field and register new routes**

Add to `Server` struct:
```go
type Server struct {
	deps Dependencies
	db   *db.Store
}
```

Update `NewServer` signature to accept `*db.Store`:
```go
func NewServer(deps Dependencies, store *db.Store) http.Handler {
	// ...existing init...
	server := &Server{deps: deps, db: store}
	// ...existing mux setup...

	// New admin routes
	mux.HandleFunc("/admin/dashboard", server.handleAdminDashboard)
	mux.HandleFunc("/admin/account", server.handleAdminAccount)
	mux.HandleFunc("/admin/account/refresh", server.handleAdminAccountRefresh)
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

	return mux
}
```

- [ ] **Step 4: Run all existing tests to verify nothing breaks**

Run:
```bash
cd D:/Project/lingma/lingma2api && go test ./internal/api/ -v
```
Expected: all existing tests pass (will need to update test calls to NewServer to pass nil for db, or use a tempStore)

---

### Task 7: Wire DB into main.go + cleanup goroutine + embed frontend

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Update `main.go` to init DB, pass to server, start cleanup**

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lingma2api/internal/api"
	"lingma2api/internal/config"
	"lingma2api/internal/db"
	"lingma2api/internal/proxy"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "./config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Open database
	store, err := db.Open("./lingma2api.db")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		log.Fatalf("migrate db: %v", err)
	}

	signer := proxy.NewSignatureEngine(proxy.SignatureOptions{
		CosyVersion: cfg.Lingma.CosyVersion,
	})
	credentials := proxy.NewCredentialManager(cfg.Credential, time.Now)
	transport := proxy.NewCurlTransport(cfg.Lingma.BaseURL, signer, 90*time.Second)
	models := proxy.NewModelService(transport, credentials, proxy.DefaultAliases(), time.Now)
	sessions := proxy.NewSessionStore(time.Duration(cfg.Session.TTLMinutes)*time.Minute, cfg.Session.MaxSessions, time.Now)
	builder := proxy.NewBodyBuilder(cfg.Lingma.CosyVersion, time.Now, proxy.NewUUID, proxy.NewHexID)

	handler := api.NewServer(api.Dependencies{
		Credentials: credentials,
		Models:      models,
		Sessions:    sessions,
		Transport:   transport,
		Builder:     builder,
		AdminToken:  cfg.Server.AdminToken,
		Now:         time.Now,
	}, store)

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go sweepSessions(ctx, sessions)
	go cleanupLogs(ctx, store)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("lingma2api listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func sweepSessions(ctx context.Context, store *proxy.SessionStore) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = store.SweepExpired(context.Background())
		}
	}
}

func cleanupLogs(ctx context.Context, store *db.Store) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			settings, _ := store.GetSettings(context.Background())
			days := 30
			if d, err := parseDays(settings["retention_days"]); err == nil {
				days = d
			}
			affected, _ := store.CleanupExpiredLogs(context.Background(), days)
			if affected > 0 {
				log.Printf("cleaned up %d expired logs", affected)
			}
		}
	}
}

func parseDays(s string) (int, error) {
	var d int
	_, err := fmt.Sscanf(s, "%d", &d)
	return d, err
}
```

- [ ] **Step 2: Add `config.yaml` db_path option (optional, or hardcode `./lingma2api.db`)**

The default `./lingma2api.db` is fine. No config change needed for MVP.

- [ ] **Step 3: Verify full project compiles**

Run:
```bash
cd D:/Project/lingma/lingma2api && go build .
```
Expected: no errors (will need to update test helper for NewServer signature change)

---

### Task 8: Frontend scaffold — Vite + React + TypeScript setup

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/tsconfig.json`
- Create: `frontend/tsconfig.app.json`
- Create: `frontend/tsconfig.node.json`
- Create: `frontend/index.html`
- Create: `frontend/src/vite-env.d.ts`

- [ ] **Step 1: Create `frontend/package.json`**

```json
{
  "name": "lingma2api-console",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.28.0",
    "recharts": "^2.15.0"
  },
  "devDependencies": {
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.4",
    "typescript": "~5.6.2",
    "vite": "^6.0.0"
  }
}
```

- [ ] **Step 2: Create `frontend/vite.config.ts`**

```ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../frontend-dist',
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    proxy: {
      '/v1': 'http://127.0.0.1:8080',
      '/admin': 'http://127.0.0.1:8080',
    },
  },
});
```

- [ ] **Step 3: Create `frontend/tsconfig.json`**

```json
{
  "files": [],
  "references": [
    { "path": "./tsconfig.app.json" },
    { "path": "./tsconfig.node.json" }
  ]
}
```

- [ ] **Step 4: Create `frontend/tsconfig.app.json`**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": false,
    "noUnusedParameters": false,
    "noFallthroughCasesInSwitch": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src"]
}
```

- [ ] **Step 5: Create `frontend/tsconfig.node.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2023"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "strict": true,
    "noUnusedLocals": false,
    "noUnusedParameters": false,
    "noFallthroughCasesInSwitch": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["vite.config.ts"]
}
```

- [ ] **Step 6: Create `frontend/index.html`**

```html
<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>lingma2api Console</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 7: Create `frontend/src/vite-env.d.ts`**

```ts
/// <reference types="vite/client" />
```

- [ ] **Step 8: Install dependencies**

Run:
```bash
cd D:/Project/lingma/lingma2api/frontend && npm install
```

---

### Task 9: Frontend core — types, API client, auth, hooks, styles, layout, router

**Files:**
- Create: `frontend/src/types/index.ts`
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/hooks/useAdminToken.ts`
- Create: `frontend/src/hooks/useSettings.ts`
- Create: `frontend/src/hooks/usePolling.ts`
- Create: `frontend/src/styles/global.css`
- Create: `frontend/src/components/Layout.tsx`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/App.tsx`

- [ ] **Step 1: Create `frontend/src/types/index.ts`**

```ts
export interface RequestLog {
  id: string;
  created_at: string;
  session_id: string;
  model: string;
  mapped_model: string;
  stream: boolean;
  status: string;
  error_msg: string;
  downstream_method: string;
  downstream_path: string;
  downstream_req: string;
  downstream_resp: string;
  upstream_req: string;
  upstream_resp: string;
  upstream_status: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  ttft_ms: number;
  upstream_ms: number;
  downstream_ms: number;
}

export interface LogListResult {
  items: RequestLog[];
  total: number;
  page: number;
  limit: number;
}

export interface ModelMapping {
  id: number;
  priority: number;
  name: string;
  pattern: string;
  target: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DashboardStats {
  total_requests: number;
  success_rate: number;
  avg_ttft_ms: number;
  total_tokens: number;
}

export interface TimeSeriesPoint {
  time: string;
  rate?: number;
  prompt?: number;
  completion?: number;
}

export interface ModelDistPoint {
  model: string;
  count: number;
}

export interface DashboardData {
  stats: DashboardStats;
  success_rate_series: TimeSeriesPoint[];
  token_series: TimeSeriesPoint[];
  model_distribution: ModelDistPoint[];
}

export interface AccountData {
  credential: {
    cos_y_key: string;
    encrypt_user_info: string;
    user_id: string;
    machine_id: string;
    loaded_at: string;
  };
  status: {
    loaded: boolean;
    has_credentials: boolean;
    source: string;
    loaded_at: string;
  };
  token_stats: {
    today: number;
    week: number;
    total: number;
  };
}

export type Theme = 'light' | 'dark';
```

- [ ] **Step 2: Create `frontend/src/api/client.ts`**

```ts
import type { LogListResult, RequestLog, DashboardData, AccountData, ModelMapping } from '../types';

function getToken(): string {
  return localStorage.getItem('admin_token') || '';
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers['X-Admin-Token'] = token;

  const res = await fetch(path, { ...init, headers: { ...headers, ...init?.headers } });
  if (res.status === 401) throw new Error('unauthorized');
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: { message: res.statusText } }));
    throw new Error(err.error?.message || `HTTP ${res.status}`);
  }
  return res.json();
}

// Dashboard
export const getDashboard = (range: string) =>
  request<DashboardData>(`/admin/dashboard?range=${range}`);

// Logs
export const getLogs = (params: Record<string, string>) => {
  const qs = new URLSearchParams(params).toString();
  return request<LogListResult>(`/admin/logs?${qs}`);
};
export const getLog = (id: string) => request<RequestLog>(`/admin/logs/${id}`);
export const replayLog = (id: string, body?: unknown) =>
  request<RequestLog>(`/admin/logs/${id}/replay`, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  });
export const cleanupLogs = () => request<{ deleted: number }>('/admin/logs/cleanup', { method: 'POST' });

// Account
export const getAccount = () => request<AccountData>('/admin/account');
export const refreshAccount = () => request<{ credential: unknown }>('/admin/account/refresh', { method: 'POST' });

// Mappings
export const getMappings = () => request<ModelMapping[]>('/admin/mappings');
export const createMapping = (m: Partial<ModelMapping>) =>
  request<ModelMapping>('/admin/mappings', { method: 'POST', body: JSON.stringify(m) });
export const updateMapping = (id: number, m: Partial<ModelMapping>) =>
  request<ModelMapping>(`/admin/mappings/${id}`, { method: 'PUT', body: JSON.stringify(m) });
export const deleteMapping = (id: number) =>
  request<{ status: string }>(`/admin/mappings/${id}`, { method: 'DELETE' });
export const testMapping = (model: string) =>
  request<{ matched: boolean; rule_name?: string; rule_id?: number; target: string; input_model: string }>(
    '/admin/mappings/test', { method: 'POST', body: JSON.stringify({ model }) }
  );

// Settings
export const getSettings = () => request<Record<string, string>>('/admin/settings');
export const updateSettings = (s: Record<string, string>) =>
  request<{ status: string }>('/admin/settings', { method: 'PUT', body: JSON.stringify(s) });

// Validation
export const validateToken = async (): Promise<boolean> => {
  try {
    await request('/admin/status');
    return true;
  } catch {
    return false;
  }
};
```

- [ ] **Step 3: Create `frontend/src/hooks/useAdminToken.ts`**

```ts
import { useState, useCallback } from 'react';

export function useAdminToken() {
  const [token, setTokenState] = useState(() => localStorage.getItem('admin_token') || '');

  const setToken = useCallback((newToken: string) => {
    if (newToken) {
      localStorage.setItem('admin_token', newToken);
    } else {
      localStorage.removeItem('admin_token');
    }
    setTokenState(newToken);
  }, []);

  return { token, setToken };
}
```

- [ ] **Step 4: Create `frontend/src/hooks/useSettings.ts`**

```ts
import { useState, useEffect } from 'react';
import { getSettings } from '../api/client';
import type { Theme } from '../types';

export function useSettings() {
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem('theme') as Theme) || 'light');

  useEffect(() => {
    getSettings().then(setSettings).catch(() => {});
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

  const refresh = () => getSettings().then(setSettings).catch(() => {});

  return { settings, theme, setTheme, refresh };
}
```

- [ ] **Step 5: Create `frontend/src/hooks/usePolling.ts`**

```ts
import { useEffect, useRef, useCallback } from 'react';

export function usePolling(callback: () => void, intervalSec: number) {
  const saved = useRef(callback);
  useEffect(() => { saved.current = callback; }, [callback]);

  const start = useCallback(() => {
    if (intervalSec <= 0) return;
    return setInterval(() => saved.current(), intervalSec * 1000);
  }, [intervalSec]);

  useEffect(() => {
    const id = start();
    return () => { if (id) clearInterval(id); };
  }, [start]);
}
```

- [ ] **Step 6: Create `frontend/src/styles/global.css`**

```css
:root {
  --bg: #ffffff;
  --bg-card: #f8f9fa;
  --bg-sidebar: #f0f2f5;
  --text: #1a1a2e;
  --text-secondary: #6c757d;
  --border: #dee2e6;
  --primary: #4361ee;
  --success: #2d6a4f;
  --error: #d00000;
  --warning: #e85d04;
  --radius: 8px;
  --shadow: 0 1px 3px rgba(0,0,0,0.08);
}

[data-theme="dark"] {
  --bg: #1a1a2e;
  --bg-card: #16213e;
  --bg-sidebar: #0f3460;
  --text: #e0e0e0;
  --text-secondary: #9e9e9e;
  --border: #2d3748;
  --primary: #6c9fff;
  --success: #81c784;
  --error: #ef5350;
  --warning: #ffb74d;
  --shadow: 0 1px 3px rgba(0,0,0,0.3);
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); }

.app-layout { display: flex; min-height: 100vh; }
.sidebar {
  width: 200px; background: var(--bg-sidebar); border-right: 1px solid var(--border);
  display: flex; flex-direction: column; padding: 16px 0;
}
.sidebar-logo { font-size: 18px; font-weight: 700; padding: 0 16px 16px; border-bottom: 1px solid var(--border); }
.sidebar-nav { flex: 1; padding: 12px 0; }
.sidebar-nav a {
  display: flex; align-items: center; gap: 8px; padding: 10px 16px;
  color: var(--text-secondary); text-decoration: none; border-radius: var(--radius);
  margin: 2px 8px; transition: all 0.2s;
}
.sidebar-nav a:hover, .sidebar-nav a.active { color: var(--primary); background: var(--bg-card); }
.sidebar-status { padding: 12px 16px; font-size: 12px; color: var(--text-secondary); border-top: 1px solid var(--border); }

.main-area { flex: 1; display: flex; flex-direction: column; min-width: 0; }
.top-bar {
  display: flex; align-items: center; justify-content: flex-end; gap: 12px;
  padding: 12px 24px; border-bottom: 1px solid var(--border);
}
.content { flex: 1; padding: 24px; overflow: auto; }
.bottom-bar {
  padding: 8px 24px; font-size: 12px; color: var(--text-secondary);
  border-top: 1px solid var(--border); background: var(--bg-card);
}

.page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
.page-header h2 { font-size: 20px; font-weight: 600; }

.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; box-shadow: var(--shadow); }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; }
.stat-card .label { font-size: 13px; color: var(--text-secondary); margin-bottom: 4px; }
.stat-card .value { font-size: 24px; font-weight: 700; }

table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }
th { font-weight: 600; color: var(--text-secondary); font-size: 12px; text-transform: uppercase; }

.btn {
  padding: 6px 14px; border-radius: var(--radius); font-size: 13px; cursor: pointer;
  border: 1px solid var(--border); background: var(--bg-card); color: var(--text); transition: all 0.2s;
}
.btn:hover { background: var(--border); }
.btn-primary { background: var(--primary); color: white; border-color: var(--primary); }
.btn-primary:hover { opacity: 0.9; }
.btn-danger { color: var(--error); border-color: var(--error); }

.input, select {
  padding: 6px 10px; border: 1px solid var(--border); border-radius: var(--radius);
  font-size: 13px; background: var(--bg); color: var(--text);
}

.tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 16px; }
.tab-btn {
  padding: 8px 16px; border: none; background: none; cursor: pointer;
  color: var(--text-secondary); font-size: 13px; border-bottom: 2px solid transparent;
}
.tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }

.code-viewer {
  background: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: var(--radius);
  font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; overflow-x: auto;
  white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto;
}

.badge { padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
.badge-success { background: var(--success); color: white; }
.badge-error { background: var(--error); color: white; }

.pagination { display: flex; align-items: center; gap: 8px; margin-top: 16px; justify-content: center; }
.pagination button { padding: 4px 10px; }
.pagination .current { font-weight: 600; }

.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.modal { background: var(--bg-card); border-radius: var(--radius); padding: 24px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; }
.modal h3 { margin-bottom: 16px; }

.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 13px; color: var(--text-secondary); margin-bottom: 4px; }
.form-group input, .form-group select, .form-group textarea { width: 100%; }

.tag { display: inline-block; padding: 4px 10px; border-radius: var(--radius); font-size: 12px; margin: 2px; background: var(--bg-card); border: 1px solid var(--border); }
```

- [ ] **Step 7: Create `frontend/src/components/Layout.tsx`**

```tsx
import { NavLink, Outlet } from 'react-router-dom';
import type { Theme } from '../types';

interface Props {
  theme: Theme;
  onToggleTheme: () => void;
}

export function Layout({ theme, onToggleTheme }: Props) {
  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-logo">lingma2api</div>
        <nav className="sidebar-nav">
          <NavLink to="/dashboard" className={({ isActive }) => isActive ? 'active' : ''}>📊 仪表盘</NavLink>
          <NavLink to="/logs" className={({ isActive }) => isActive ? 'active' : ''}>📋 请求日志</NavLink>
          <NavLink to="/account" className={({ isActive }) => isActive ? 'active' : ''}>👤 账号管理</NavLink>
          <NavLink to="/models" className={({ isActive }) => isActive ? 'active' : ''}>🤖 模型管理</NavLink>
          <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>⚙️ 设置</NavLink>
        </nav>
        <div className="sidebar-status">🟢 已连接</div>
      </aside>
      <div className="main-area">
        <div className="top-bar">
          <button className="btn" onClick={onToggleTheme}>
            {theme === 'light' ? '🌙 深色' : '☀️ 浅色'}
          </button>
          <NavLink to="/settings" className="btn">⚙️</NavLink>
        </div>
        <div className="content">
          <Outlet />
        </div>
        <div className="bottom-bar">lingma2api v1.0.0</div>
      </div>
    </div>
  );
}
```

- [ ] **Step 8: Create `frontend/src/main.tsx`**

```tsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles/global.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
```

- [ ] **Step 9: Create `frontend/src/App.tsx`**

```tsx
import { useState, useEffect, useCallback } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { validateToken } from './api/client';
import { useAdminToken } from './hooks/useAdminToken';
import { useSettings } from './hooks/useSettings';
import { Dashboard } from './pages/Dashboard';
import { Logs } from './pages/Logs';
import { LogDetail } from './pages/LogDetail';
import { Account } from './pages/Account';
import { Models } from './pages/Models';
import { Settings } from './pages/Settings';

export default function App() {
  const { token, setToken } = useAdminToken();
  const { theme, setTheme } = useSettings();
  const [authed, setAuthed] = useState(false);
  const [loading, setLoading] = useState(true);

  const checkAuth = useCallback(async () => {
    setLoading(true);
    const ok = await validateToken();
    setAuthed(ok);
    setLoading(false);
  }, []);

  useEffect(() => { checkAuth(); }, [checkAuth]);

  const handleLogin = async (inputToken: string) => {
    setToken(inputToken);
    const ok = await validateToken();
    setAuthed(ok);
    if (!ok) setToken('');
  };

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}>加载中...</div>;

  if (!authed) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', flexDirection: 'column', gap: 16 }}>
        <h2>lingma2api Console</h2>
        <p style={{ color: 'var(--text-secondary)' }}>请输入 Admin Token</p>
        <form onSubmit={(e) => { e.preventDefault(); handleLogin((e.target as HTMLFormElement).token.value); }}>
          <input name="token" className="input" placeholder="Admin Token" style={{ width: 280, marginRight: 8 }} />
          <button type="submit" className="btn btn-primary">登录</button>
        </form>
      </div>
    );
  }

  const toggleTheme = () => setTheme(theme === 'light' ? 'dark' : 'light');

  return (
    <HashRouter>
      <Routes>
        <Route element={<Layout theme={theme} onToggleTheme={toggleTheme} />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/logs/:id" element={<LogDetail />} />
          <Route path="/account" element={<Account />} />
          <Route path="/models" element={<Models />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
```

- [ ] **Step 10: Verify frontend dev server starts**

Run:
```bash
cd D:/Project/lingma/lingma2api/frontend && npm run dev
```
Expected: Vite dev server starts on http://localhost:3000

---

### Task 10: Dashboard page + chart components

**Files:**
- Create: `frontend/src/pages/Dashboard.tsx`
- Create: `frontend/src/components/StatCard.tsx`

- [ ] **Step 1: Create `frontend/src/components/StatCard.tsx`**

```tsx
interface Props {
  label: string;
  value: string | number;
  suffix?: string;
}

export function StatCard({ label, value, suffix }: Props) {
  return (
    <div className="stat-card">
      <div className="label">{label}</div>
      <div className="value">{value}{suffix && <span style={{ fontSize: 14, fontWeight: 400, marginLeft: 4 }}>{suffix}</span>}</div>
    </div>
  );
}
```

- [ ] **Step 2: Create `frontend/src/pages/Dashboard.tsx`**

```tsx
import { useState, useCallback } from 'react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { getDashboard } from '../api/client';
import { usePolling } from '../hooks/usePolling';
import { useSettings } from '../hooks/useSettings';
import { StatCard } from '../components/StatCard';
import type { DashboardData } from '../types';

const RANGES = ['1h', '24h', '7d', '30d'];
const COLORS = ['#4361ee', '#2d6a4f', '#e85d04', '#9b5de5', '#00b4d8', '#ef5350', '#66bb6a', '#ffa726'];

export function Dashboard() {
  const { settings } = useSettings();
  const [range, setRange] = useState('24h');
  const [data, setData] = useState<DashboardData | null>(null);

  const load = useCallback(async () => {
    try { setData(await getDashboard(range)); } catch {}
  }, [range]);

  const pollInterval = parseInt(settings.polling_interval || '0', 10);
  usePolling(load, pollInterval);
  useState(() => { load(); });

  if (!data) return <div>加载中...</div>;

  const fmtToken = (n: number) => n >= 1000000 ? `${(n / 1000000).toFixed(1)}M` : n >= 1000 ? `${(n / 1000).toFixed(1)}K` : String(n);

  return (
    <div>
      <div className="page-header">
        <h2>仪表盘</h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select className="input" value={range} onChange={e => setRange(e.target.value)}>
            {RANGES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <button className="btn" onClick={load}>🔄 刷新</button>
          {pollInterval > 0 && <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>自动 {pollInterval}s</span>}
        </div>
      </div>

      <div className="stat-grid">
        <StatCard label="总请求数" value={data.stats.total_requests.toLocaleString()} />
        <StatCard label="成功率" value={data.stats.success_rate.toFixed(1)} suffix="%" />
        <StatCard label="平均 TTFT" value={data.stats.avg_ttft_ms} suffix="ms" />
        <StatCard label="Token 消耗" value={fmtToken(data.stats.total_tokens)} />
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>成功率趋势</h4>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={data.success_rate_series}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="time" tick={{ fontSize: 11 }} tickFormatter={t => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} />
            <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
            <Tooltip />
            <Line type="monotone" dataKey="rate" stroke="var(--primary)" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>Token 趋势</h4>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={data.token_series}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="time" tick={{ fontSize: 11 }} tickFormatter={t => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip />
            <Legend />
            <Bar dataKey="prompt" fill="#4361ee" name="Prompt" stackId="a" />
            <Bar dataKey="completion" fill="#2d6a4f" name="Completion" stackId="a" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="card">
          <h4 style={{ marginBottom: 12 }}>模型分布</h4>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={data.model_distribution} dataKey="count" nameKey="model" cx="50%" cy="50%" outerRadius={80} label>
                {data.model_distribution.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h4 style={{ marginBottom: 12 }}>Top 模型</h4>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={data.model_distribution.slice(0, 6)} layout="vertical">
              <XAxis type="number" tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="model" tick={{ fontSize: 11 }} width={120} />
              <Tooltip />
              <Bar dataKey="count" fill="var(--primary)" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Verify Dashboard renders with mock data**

Run:
```bash
cd D:/Project/lingma/lingma2api/frontend && npm run dev
```
Navigate to `http://localhost:3000/#/dashboard`. Should show loading or stats (API may not be running yet).

---

### Task 11: Logs page — list, detail, pagination, code viewer, replay modal

**Files:**
- Create: `frontend/src/components/Pagination.tsx`
- Create: `frontend/src/components/CodeViewer.tsx`
- Create: `frontend/src/components/ReplayModal.tsx`
- Create: `frontend/src/pages/Logs.tsx`
- Create: `frontend/src/pages/LogDetail.tsx`

- [ ] **Step 1: Create `frontend/src/components/Pagination.tsx`**

```tsx
interface Props {
  page: number;
  total: number;
  limit: number;
  onChange: (page: number) => void;
}

export function Pagination({ page, total, limit, onChange }: Props) {
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="pagination">
      <button className="btn" disabled={page <= 1} onClick={() => onChange(page - 1)}>← 上一页</button>
      <span>{page} / {pages}</span>
      <button className="btn" disabled={page >= pages} onClick={() => onChange(page + 1)}>下一页 →</button>
    </div>
  );
}
```

- [ ] **Step 2: Create `frontend/src/components/CodeViewer.tsx`**

```tsx
interface Props {
  code: string;
  language?: string;
}

export function CodeViewer({ code }: Props) {
  let formatted = code;
  try { formatted = JSON.stringify(JSON.parse(code), null, 2); } catch {}

  return (
    <pre className="code-viewer">{formatted}</pre>
  );
}
```

- [ ] **Step 3: Create `frontend/src/components/ReplayModal.tsx`**

```tsx
import { useState } from 'react';
import { replayLog } from '../api/client';
import { CodeViewer } from './CodeViewer';

interface Props {
  logId: string;
  originalBody: string;
  onClose: () => void;
}

export function ReplayModal({ logId, originalBody, onClose }: Props) {
  const [body, setBody] = useState(originalBody);
  const [response, setResponse] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSend = async () => {
    setLoading(true);
    try {
      const parsed = JSON.parse(body);
      const result = await replayLog(logId, parsed);
      setResponse(JSON.stringify(result, null, 2));
    } catch (err) {
      setResponse(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }
    setLoading(false);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h3>请求重发</h3>
        <div className="form-group">
          <label>请求体 (可编辑)</label>
          <textarea
            className="input"
            rows={12}
            value={body}
            onChange={e => setBody(e.target.value)}
            style={{ fontFamily: 'monospace', fontSize: 12 }}
          />
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <button className="btn btn-primary" onClick={handleSend} disabled={loading}>
            {loading ? '发送中...' : '发送'}
          </button>
          <button className="btn" onClick={onClose}>关闭</button>
        </div>
        {response && (
          <div>
            <h4 style={{ marginBottom: 8 }}>响应</h4>
            <CodeViewer code={response} />
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Create `frontend/src/pages/Logs.tsx`**

```tsx
import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getLogs } from '../api/client';
import { Pagination } from '../components/Pagination';
import { ReplayModal } from '../components/ReplayModal';
import type { RequestLog, LogListResult } from '../types';

export function Logs() {
  const [data, setData] = useState<LogListResult | null>(null);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('');
  const [model, setModel] = useState('');
  const [replayId, setReplayId] = useState<string | null>(null);
  const [replayBody, setReplayBody] = useState('');

  const load = async () => {
    const params: Record<string, string> = { page: String(page), limit: '50' };
    if (status) params.status = status;
    if (model) params.model = model;
    try { setData(await getLogs(params)); } catch {}
  };

  useEffect(() => { load(); }, [page, status, model]);

  const fmtTime = (s: string) => new Date(s).toLocaleString();
  const handleReplay = (log: RequestLog) => {
    setReplayId(log.id);
    setReplayBody(log.downstream_req);
  };

  return (
    <div>
      <div className="page-header">
        <h2>请求日志</h2>
        <div style={{ display: 'flex', gap: 8 }}>
          <select className="input" value={status} onChange={e => { setStatus(e.target.value); setPage(1); }}>
            <option value="">全部状态</option>
            <option value="success">成功</option>
            <option value="error">失败</option>
          </select>
          <input className="input" placeholder="模型筛选" value={model} onChange={e => { setModel(e.target.value); setPage(1); }} />
          <a className="btn" href="/admin/logs/export?format=json" target="_blank" rel="noopener">📥 导出</a>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>时间</th><th>模型</th><th>状态</th><th>TTFT</th><th>Token</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          {data?.items.map(log => (
            <tr key={log.id}>
              <td>{fmtTime(log.created_at)}</td>
              <td>{log.model}{log.model !== log.mapped_model && ` → ${log.mapped_model}`}</td>
              <td><span className={`badge ${log.status === 'success' ? 'badge-success' : 'badge-error'}`}>{log.status}</span></td>
              <td>{log.ttft_ms > 0 ? `${log.ttft_ms}ms` : '-'}</td>
              <td>{log.total_tokens > 0 ? log.total_tokens.toLocaleString() : '-'}</td>
              <td>
                <Link to={`/logs/${log.id}`} className="btn" style={{ marginRight: 4 }}>👁</Link>
                <button className="btn" onClick={() => handleReplay(log)}>↩️</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {data && <Pagination page={data.page} total={data.total} limit={data.limit} onChange={setPage} />}
      {replayId && <ReplayModal logId={replayId} originalBody={replayBody} onClose={() => setReplayId(null)} />}
    </div>
  );
}
```

- [ ] **Step 5: Create `frontend/src/pages/LogDetail.tsx`**

```tsx
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getLog } from '../api/client';
import { CodeViewer } from '../components/CodeViewer';
import { ReplayModal } from '../components/ReplayModal';
import type { RequestLog } from '../types';

const TABS = [
  { key: 'downstream_req', label: '下游请求' },
  { key: 'upstream_req', label: '上游请求' },
  { key: 'upstream_resp', label: '上游响应' },
  { key: 'downstream_resp', label: '下游响应' },
];

export function LogDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [log, setLog] = useState<RequestLog | null>(null);
  const [tab, setTab] = useState('downstream_req');
  const [showReplay, setShowReplay] = useState(false);

  useEffect(() => {
    if (id) getLog(id).then(setLog).catch(() => navigate('/logs'));
  }, [id, navigate]);

  if (!log) return <div>加载中...</div>;

  const copyToClipboard = (text: string) => navigator.clipboard.writeText(text);

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button className="btn" onClick={() => navigate('/logs')}>← 返回</button>
          <h2>请求详情</h2>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={() => copyToClipboard(log[tab as keyof RequestLog] as string)}>📋 复制</button>
          <button className="btn btn-primary" onClick={() => setShowReplay(true)}>↩️ 重发</button>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>时间</span><br />{new Date(log.created_at).toLocaleString()}</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>状态</span><br /><span className={`badge ${log.status === 'success' ? 'badge-success' : 'badge-error'}`}>{log.upstream_status}</span></div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>模型</span><br />{log.model} → {log.mapped_model}</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Session</span><br />{log.session_id || '-'}</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>TTFT</span><br />{log.ttft_ms}ms</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>上游耗时</span><br />{log.upstream_ms}ms</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>下游耗时</span><br />{log.downstream_ms}ms</div>
        <div><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Token</span><br />P:{log.prompt_tokens} C:{log.completion_tokens} T:{log.total_tokens}</div>
      </div>

      <div className="tabs">
        {TABS.map(t => (
          <button key={t.key} className={`tab-btn ${tab === t.key ? 'active' : ''}`} onClick={() => setTab(t.key)}>
            {t.label}
          </button>
        ))}
      </div>

      <CodeViewer code={log[tab as keyof RequestLog] as string} />

      {showReplay && <ReplayModal logId={log.id} originalBody={log.downstream_req} onClose={() => setShowReplay(false)} />}
    </div>
  );
}
```

---

### Task 12: Account page

**Files:**
- Create: `frontend/src/pages/Account.tsx`

- [ ] **Step 1: Create `frontend/src/pages/Account.tsx`**

```tsx
import { useState, useEffect } from 'react';
import { getAccount, refreshAccount } from '../api/client';
import { StatCard } from '../components/StatCard';
import type { AccountData } from '../types';

export function Account() {
  const [data, setData] = useState<AccountData | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = async () => {
    try { setData(await getAccount()); } catch {}
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    try { await refreshAccount(); await load(); } catch {}
    setRefreshing(false);
  };

  const mask = (s: string) => s.length > 6 ? s.slice(0, 3) + '***' + s.slice(-3) : s;

  if (!data) return <div>加载中...</div>;

  const fmtToken = (n: number) => n >= 1000000 ? `${(n / 1000000).toFixed(1)}M` : n >= 1000 ? `${(n / 1000).toFixed(1)}K` : String(n);

  return (
    <div>
      <div className="page-header">
        <h2>账号管理</h2>
        <button className="btn btn-primary" onClick={handleRefresh} disabled={refreshing}>
          {refreshing ? '刷新中...' : '🔄 刷新凭据'}
        </button>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>用户信息</h4>
        <table>
          <tbody>
            <tr><td style={{ fontWeight: 600 }}>UserID</td><td>{data.credential?.user_id || '-'}</td></tr>
            <tr><td style={{ fontWeight: 600 }}>MachineID</td><td>{data.credential?.machine_id || '-'}</td></tr>
            <tr><td style={{ fontWeight: 600 }}>CosyKey</td><td>{data.credential?.cos_y_key ? mask(data.credential.cos_y_key) : '-'}</td></tr>
            <tr><td style={{ fontWeight: 600 }}>EncryptUserInfo</td><td>{data.credential?.encrypt_user_info ? mask(data.credential.encrypt_user_info) : '-'}</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>凭据状态</h4>
        <table>
          <tbody>
            <tr>
              <td style={{ fontWeight: 600 }}>状态</td>
              <td><span className={`badge ${data.status?.loaded ? 'badge-success' : 'badge-error'}`}>
                {data.status?.loaded ? '✅ 有效' : '❌ 无效'}
              </span></td>
            </tr>
            <tr><td style={{ fontWeight: 600 }}>加载时间</td><td>{data.status?.loaded_at ? new Date(data.status.loaded_at).toLocaleString() : '-'}</td></tr>
            <tr><td style={{ fontWeight: 600 }}>来源</td><td>{data.status?.source || '-'}</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <h4 style={{ marginBottom: 12 }}>Token 用量统计</h4>
        <div className="stat-grid">
          <StatCard label="今日" value={fmtToken(data.token_stats?.today || 0)} />
          <StatCard label="本周" value={fmtToken(data.token_stats?.week || 0)} />
          <StatCard label="总计" value={fmtToken(data.token_stats?.total || 0)} />
        </div>
      </div>
    </div>
  );
}
```

---

### Task 13: Models page + mapping editor

**Files:**
- Create: `frontend/src/components/MappingRuleEditor.tsx`
- Create: `frontend/src/pages/Models.tsx`

- [ ] **Step 1: Create `frontend/src/components/MappingRuleEditor.tsx`**

```tsx
import { useState } from 'react';
import type { ModelMapping } from '../types';

interface Props {
  mapping?: ModelMapping;
  onSave: (m: Partial<ModelMapping>) => void;
  onClose: () => void;
}

export function MappingRuleEditor({ mapping, onSave, onClose }: Props) {
  const [name, setName] = useState(mapping?.name || '');
  const [pattern, setPattern] = useState(mapping?.pattern || '');
  const [target, setTarget] = useState(mapping?.target || '');
  const [priority, setPriority] = useState(mapping?.priority ?? 0);
  const [enabled, setEnabled] = useState(mapping?.enabled ?? true);
  const [error, setError] = useState('');

  const handleSave = () => {
    if (!name || !pattern || !target) {
      setError('所有字段必填');
      return;
    }
    try { new RegExp(pattern); } catch {
      setError('正则表达式无效');
      return;
    }
    onSave({ name, pattern, target, priority, enabled });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h3>{mapping ? '编辑规则' : '新增规则'}</h3>
        {error && <div style={{ color: 'var(--error)', marginBottom: 12 }}>{error}</div>}
        <div className="form-group">
          <label>规则名称</label>
          <input className="input" value={name} onChange={e => setName(e.target.value)} />
        </div>
        <div className="form-group">
          <label>源模型匹配正则</label>
          <input className="input" value={pattern} onChange={e => setPattern(e.target.value)} placeholder="^gpt-4" />
        </div>
        <div className="form-group">
          <label>目标模型</label>
          <input className="input" value={target} onChange={e => setTarget(e.target.value)} placeholder="lingma-gpt4" />
        </div>
        <div className="form-group">
          <label>优先级 (越小越高)</label>
          <input className="input" type="number" value={priority} onChange={e => setPriority(Number(e.target.value))} />
        </div>
        <div className="form-group">
          <label>
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} style={{ marginRight: 8 }} />
            启用
          </label>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-primary" onClick={handleSave}>保存</button>
          <button className="btn" onClick={onClose}>取消</button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create `frontend/src/pages/Models.tsx`**

```tsx
import { useState, useEffect, useCallback } from 'react';
import { getMappings, createMapping, updateMapping, deleteMapping, testMapping } from '../api/client';
import { MappingRuleEditor } from '../components/MappingRuleEditor';
import type { ModelMapping } from '../types';

export function Models() {
  const [mappings, setMappings] = useState<ModelMapping[]>([]);
  const [editing, setEditing] = useState<ModelMapping | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [testModel, setTestModel] = useState('');
  const [testResult, setTestResult] = useState<string | null>(null);

  const load = useCallback(async () => {
    try { setMappings(await getMappings()); } catch {}
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSave = async (data: Partial<ModelMapping>) => {
    if (editing) {
      await updateMapping(editing.id, data);
    } else {
      await createMapping(data);
    }
    setEditing(null);
    setShowNew(false);
    load();
  };

  const handleDelete = async (id: number) => {
    if (confirm('确认删除？')) {
      await deleteMapping(id);
      load();
    }
  };

  const handleTest = async () => {
    if (!testModel) return;
    const r = await testMapping(testModel);
    setTestResult(r.matched ? `✅ 匹配规则 "${r.rule_name}" → ${r.target}` : `❌ 无匹配，使用默认 → ${r.target}`);
  };

  return (
    <div>
      <div className="page-header">
        <h2>模型管理</h2>
        <button className="btn btn-primary" onClick={() => setShowNew(true)}>➕ 新增规则</button>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>映射规则</h4>
        <table>
          <thead>
            <tr><th>优先级</th><th>名称</th><th>源匹配</th><th>目标</th><th>启用</th><th>操作</th></tr>
          </thead>
          <tbody>
            {mappings.map(m => (
              <tr key={m.id}>
                <td>{m.priority}</td>
                <td>{m.name}</td>
                <td><code>{m.pattern}</code></td>
                <td>{m.target}</td>
                <td>{m.enabled ? '✅' : '❌'}</td>
                <td>
                  <button className="btn" onClick={() => setEditing(m)} style={{ marginRight: 4 }}>✏️</button>
                  <button className="btn btn-danger" onClick={() => handleDelete(m.id)}>🗑</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h4 style={{ marginBottom: 12 }}>映射测试</h4>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input className="input" placeholder="输入模型名" value={testModel} onChange={e => setTestModel(e.target.value)} style={{ width: 300 }} />
          <button className="btn" onClick={handleTest}>测试</button>
          {testResult && <span style={{ fontSize: 13 }}>{testResult}</span>}
        </div>
      </div>

      {(showNew || editing) && (
        <MappingRuleEditor
          mapping={editing || undefined}
          onSave={handleSave}
          onClose={() => { setEditing(null); setShowNew(false); }}
        />
      )}
    </div>
  );
}
```

---

### Task 14: Settings page

**Files:**
- Create: `frontend/src/pages/Settings.tsx`

- [ ] **Step 1: Create `frontend/src/pages/Settings.tsx`**

```tsx
import { useState, useEffect } from 'react';
import { getSettings, updateSettings, cleanupLogs } from '../api/client';
import { useSettings } from '../hooks/useSettings';
import { useAdminToken } from '../hooks/useAdminToken';

export function Settings() {
  const { settings: hookSettings, theme, setTheme } = useSettings();
  const { token, setToken } = useAdminToken();
  const [form, setForm] = useState<Record<string, string>>({});
  const [newToken, setNewToken] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    getSettings().then(s => {
      setForm(s);
    }).catch(() => {});
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateSettings(form);
      setMsg('设置已保存');
      setTimeout(() => setMsg(''), 2000);
    } catch (e) {
      setMsg(`保存失败: ${e instanceof Error ? e.message : String(e)}`);
    }
    setSaving(false);
  };

  const handleTokenChange = () => {
    setToken(newToken);
    setNewToken('');
    setMsg('Token 已更新');
    setTimeout(() => setMsg(''), 2000);
  };

  const handleCleanup = async () => {
    try {
      const r = await cleanupLogs();
      setMsg(`已清理 ${r.deleted} 条过期日志`);
      setTimeout(() => setMsg(''), 3000);
    } catch {}
  };

  const handleExportLogs = () => {
    window.open('/admin/logs/export?format=json', '_blank');
  };

  const handleExportStats = () => {
    window.open('/admin/stats/export?format=json', '_blank');
  };

  return (
    <div>
      <div className="page-header">
        <h2>设置</h2>
        {msg && <span style={{ color: 'var(--success)', fontSize: 13 }}>{msg}</span>}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>存储</h4>
        <div className="form-group">
          <label>响应体存储模式</label>
          <select className="input" value={form.storage_mode || 'full'} onChange={e => setForm({ ...form, storage_mode: e.target.value })}>
            <option value="full">完整存储</option>
            <option value="truncated">摘要存储</option>
          </select>
        </div>
        {form.storage_mode === 'truncated' && (
          <div className="form-group">
            <label>截断长度（字节）</label>
            <input className="input" type="number" value={form.truncate_length || '102400'} onChange={e => setForm({ ...form, truncate_length: e.target.value })} />
          </div>
        )}
        <div className="form-group">
          <label>日志保留天数</label>
          <select className="input" value={form.retention_days || '30'} onChange={e => setForm({ ...form, retention_days: e.target.value })}>
            <option value="7">7 天</option>
            <option value="14">14 天</option>
            <option value="30">30 天</option>
            <option value="90">90 天</option>
          </select>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>仪表盘</h4>
        <div className="form-group">
          <label>自动刷新间隔</label>
          <select className="input" value={form.polling_interval || '0'} onChange={e => setForm({ ...form, polling_interval: e.target.value })}>
            <option value="0">关闭</option>
            <option value="10">10 秒</option>
            <option value="30">30 秒</option>
            <option value="60">60 秒</option>
          </select>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>外观</h4>
        <div className="form-group">
          <label>主题</label>
          <select className="input" value={theme} onChange={e => setTheme(e.target.value as 'light' | 'dark')}>
            <option value="light">浅色</option>
            <option value="dark">深色</option>
          </select>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>超时</h4>
        <div className="form-group">
          <label>请求超时（秒）</label>
          <input className="input" type="number" value={form.request_timeout || '90'} onChange={e => setForm({ ...form, request_timeout: e.target.value })} />
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>安全</h4>
        <div className="form-group">
          <label>Admin Token（留空表示无 token）</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input className="input" type="password" value={newToken} onChange={e => setNewToken(e.target.value)} placeholder={token ? '••••••••' : '未设置'} style={{ flex: 1 }} />
            <button className="btn" onClick={handleTokenChange}>变更</button>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h4 style={{ marginBottom: 12 }}>数据</h4>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="btn" onClick={handleExportLogs}>📥 导出请求日志</button>
          <button className="btn" onClick={handleExportStats}>📥 导出统计数据</button>
          <button className="btn btn-danger" onClick={handleCleanup}>🗑 清理过期日志</button>
        </div>
      </div>

      <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
        {saving ? '保存中...' : '保存设置'}
      </button>
    </div>
  );
}
```

---

### Task 15: Build integration — embed frontend into Go binary

**Files:**
- Modify: `internal/api/server.go` (add embed.FS handling)
- Modify: `main.go` (add embed.FS)

- [ ] **Step 1: Add `embed` import and `frontendDist` embed to `main.go`**

```go
import "embed"

//go:embed frontend-dist
var frontendDist embed.FS
```

Pass `frontendDist` to `NewServer`:
```go
handler := api.NewServer(api.Dependencies{
    // ...existing fields...
    FrontendFS: frontendDist,
}, store)
```

Add `FrontendFS` to `Dependencies`:
```go
type Dependencies struct {
    Credentials CredentialProvider
    Models      ModelService
    Sessions    SessionStore
    Transport   ChatTransport
    Builder     RequestBuilder
    AdminToken  string
    Now         func() time.Time
    FrontendFS  embed.FS
}
```

- [ ] **Step 2: Add SPA fallback handler to `server.go`**

At the end of `NewServer`, add frontend serving:

```go
import "io/fs"

// Inside NewServer, after all routes are registered:
if deps.FrontendFS != nil {
    subFS, err := fs.Sub(deps.FrontendFS, "frontend-dist")
    if err == nil {
        fileServer := http.FileServerFS(subFS)
        mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            // Try serving the file directly
            f, err := subFS.Open(strings.TrimPrefix(r.URL.Path, "/"))
            if err == nil {
                f.Close()
                fileServer.ServeHTTP(w, r)
                return
            }
            // SPA fallback: serve index.html for non-file paths
            r.URL.Path = "/"
            fileServer.ServeHTTP(w, r)
        })
    }
}
```

- [ ] **Step 3: Build frontend and Go binary**

Run:
```bash
cd D:/Project/lingma/lingma2api/frontend && npm run build
cd D:/Project/lingma/lingma2api && go build -o lingma2api.exe .
```

- [ ] **Step 4: Test frontend served from Go binary**

Run:
```bash
cd D:/Project/lingma/lingma2api && ./lingma2api.exe -config ./config.yaml
```
Open `http://127.0.0.1:8080/` in browser. Should show the Console login page.

---

### Task 16: Wire logging middleware + final integration

**Files:**
- Modify: `main.go`
- Modify: `internal/api/server.go`

- [ ] **Step 1: Load settings from DB in main.go and configure middleware**

```go
// In main.go, after DB init and before handler creation:
settings, _ := store.GetSettings(context.Background())

loggingMiddleware := middleware.Logging(store, middleware.LoggingConfig{
    StorageMode:    settings["storage_mode"],
    TruncateLength: mustAtoi(settings["truncate_length"]),
})

// Wrap handler with middleware:
server := &http.Server{
    Addr:              fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
    Handler:           loggingMiddleware(handler),
    ReadHeaderTimeout: 5 * time.Second,
}

func mustAtoi(s string) int {
    var n int
    fmt.Sscanf(s, "%d", &n)
    return n
}
```

- [ ] **Step 2: Full build and smoke test**

Run:
```bash
cd D:/Project/lingma/lingma2api/frontend && npm run build
cd D:/Project/lingma/lingma2api && go build -o lingma2api.exe .
```

Start server, open browser to `http://127.0.0.1:8080/`, verify:
- Login page appears
- After entering admin token (empty if none configured), dashboard loads
- All 5 pages navigate correctly
- Settings can be saved

---

### Task 17: Tests + cleanup

**Files:**
- Update: `internal/api/server_test.go` (fix NewServer signature)
- Update: `internal/api/admin_handlers_test.go` (add admin handler tests)

- [ ] **Step 1: Update `server_test.go` — pass nil store to NewServer**

In every test that calls `api.NewServer(Dependencies{...})`, add the second argument `nil` for the store:
```go
handler := api.NewServer(Dependencies{...}, nil)
```

- [ ] **Step 2: Add admin handler tests**

```go
func TestAdminDashboardReturnsData(t *testing.T) {
    store, cleanup := tempDBStore(t)
    defer cleanup()
    handler := NewServer(Dependencies{
        Credentials: fakeCredentials{},
        Models:      fakeModels{},
        Sessions:    fakeSessions{},
        Transport:   fakeTransport{},
        Builder:     fakeBuilder{},
    }, store)

    req := httptest.NewRequest(http.MethodGet, "/admin/dashboard?range=24h", nil)
    rec := httptest.NewRecorder()
    handler.ServeHTTP(rec, req)

    if rec.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d", rec.Code)
    }
    var data db.DashboardData
    json.NewDecoder(rec.Body).Decode(&data)
    if data.Stats.TotalRequests != 0 {
        t.Fatalf("expected 0 requests in empty db")
    }
}

func TestAdminSettingsRoundTrip(t *testing.T) {
    store, cleanup := tempDBStore(t)
    defer cleanup()
    handler := NewServer(Dependencies{
        Credentials: fakeCredentials{},
        Models:      fakeModels{},
        Sessions:    fakeSessions{},
        Transport:   fakeTransport{},
        Builder:     fakeBuilder{},
    }, store)

    // Update
    body := `{"storage_mode":"truncated","retention_days":"14"}`
    req := httptest.NewRequest(http.MethodPut, "/admin/settings", strings.NewReader(body))
    rec := httptest.NewRecorder()
    handler.ServeHTTP(rec, req)
    if rec.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d", rec.Code)
    }

    // Get
    req = httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
    rec = httptest.NewRecorder()
    handler.ServeHTTP(rec, req)
    var settings map[string]string
    json.NewDecoder(rec.Body).Decode(&settings)
    if settings["storage_mode"] != "truncated" {
        t.Fatalf("expected truncated, got %s", settings["storage_mode"])
    }
}
```

- [ ] **Step 3: Run all tests**

Run:
```bash
cd D:/Project/lingma/lingma2api && go test ./... -v
```
Expected: all tests pass (except pre-existing auth and encode-crack failures)
