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
	if items == nil {
		items = []RequestLog{}
	}
	return LogListResult{Items: items, Total: total, Page: page, Limit: limit}, rows.Err()
}

func (s *Store) CleanupExpiredLogs(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
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
	if items == nil {
		items = []RequestLog{}
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
	if b {
		return 1
	}
	return 0
}
