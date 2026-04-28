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
	Time       time.Time `json:"time"`
	Rate       float64   `json:"rate,omitempty"`
	Prompt     int       `json:"prompt"`
	Completion int       `json:"completion"`
}

type ModelDistPoint struct {
	Model string `json:"model"`
	Count int    `json:"count"`
}

type DashboardData struct {
	Stats             DashboardStats    `json:"stats"`
	SuccessRateSeries []TimeSeriesPoint `json:"success_rate_series"`
	TokenSeries       []TimeSeriesPoint `json:"token_series"`
	ModelDistribution []ModelDistPoint  `json:"model_distribution"`
}

func (s *Store) GetDashboardData(ctx context.Context, rangeStr string) (DashboardData, error) {
	hours := rangeToHours(rangeStr)
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	granularity := granularityForRange(hours)

	data := DashboardData{}

	row := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END)*100.0/COUNT(*),0),
		 COALESCE(AVG(ttft_ms),0), COALESCE(SUM(total_tokens),0)
		 FROM request_logs WHERE created_at>?`, cutoff)
	if err := row.Scan(&data.Stats.TotalRequests, &data.Stats.SuccessRate, &data.Stats.AvgTTFTMs, &data.Stats.TotalTokens); err != nil {
		return data, err
	}

	data.SuccessRateSeries, _ = s.querySuccessRateSeries(ctx, cutoff, granularity)
	data.TokenSeries, _ = s.queryTokenSeries(ctx, cutoff, granularity)
	data.ModelDistribution, _ = s.queryModelDistribution(ctx, cutoff)
	if data.SuccessRateSeries == nil {
		data.SuccessRateSeries = []TimeSeriesPoint{}
	}
	if data.TokenSeries == nil {
		data.TokenSeries = []TimeSeriesPoint{}
	}
	if data.ModelDistribution == nil {
		data.ModelDistribution = []ModelDistPoint{}
	}
	return data, nil
}

func (s *Store) querySuccessRateSeries(ctx context.Context, cutoff time.Time, gran string) ([]TimeSeriesPoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT strftime(?, created_at) as t, COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END)*100.0/COUNT(*),0) as r
		 FROM request_logs WHERE created_at>? GROUP BY t ORDER BY t`, gran, cutoff)
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
		 FROM request_logs WHERE created_at>? GROUP BY t ORDER BY t`, gran, cutoff)
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
		`SELECT mapped_model, COUNT(*) as c FROM request_logs WHERE created_at>? GROUP BY mapped_model ORDER BY c DESC LIMIT 10`, cutoff)
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

	if err = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_tokens),0) FROM request_logs WHERE created_at>=?`, todayStart).Scan(&today); err != nil {
		return 0, 0, 0, err
	}
	if err = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_tokens),0) FROM request_logs WHERE created_at>=?`, weekStart).Scan(&week); err != nil {
		return 0, 0, 0, err
	}
	if err = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_tokens),0) FROM request_logs`).Scan(&total); err != nil {
		return 0, 0, 0, err
	}
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
