package db

import (
	"context"
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
	if items == nil {
		items = []ModelMapping{}
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
	if items == nil {
		items = []ModelMapping{}
	}
	return items, rows.Err()
}
