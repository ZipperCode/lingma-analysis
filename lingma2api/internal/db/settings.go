package db

import (
	"context"
	"fmt"
)

var defaultSettings = map[string]string{
	"storage_mode":     "full",
	"truncate_length":  "102400",
	"retention_days":   "30",
	"polling_interval": "0",
	"theme":            "light",
	"request_timeout":  "90",
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
			return fmt.Errorf("unknown setting key: %s", k)
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
