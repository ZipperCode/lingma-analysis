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
