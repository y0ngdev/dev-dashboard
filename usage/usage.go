package usage

import (
	"context"
	"fmt"
	"time"

	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/storage/sqldb"
)

// usage service owns the "usage" database.
var db = sqldb.NewDatabase("usage", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// UsageEvent is a single recorded API request.
type UsageEvent struct {
	ID          string    `json:"id"`
	APIKeyID    *string   `json:"api_key_id,omitempty"`
	UserID      string    `json:"user_id"`
	Endpoint    string    `json:"endpoint"`
	Method      string    `json:"method"`
	StatusCode  int       `json:"status_code"`
	DurationMs  *int      `json:"duration_ms,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
}

// ---------------------------------------------------------------------------
// Record — called internally to log a request
// ---------------------------------------------------------------------------

type RecordRequest struct {
	APIKeyID   *string `json:"api_key_id,omitempty"`
	UserID     string  `json:"user_id"`
	Endpoint   string  `json:"endpoint"`
	Method     string  `json:"method"`
	StatusCode int     `json:"status_code"`
	DurationMs *int    `json:"duration_ms,omitempty"`
}

// Record logs a single API usage event.
// Called by other services or middleware — not exposed publicly.
//
//encore:api private method=POST path=/usage/record
func Record(ctx context.Context, req *RecordRequest) error {
	if req.UserID == "" || req.Endpoint == "" || req.Method == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("user_id, endpoint, and method are required").Err()
	}

	_, err := db.Exec(ctx, `
		INSERT INTO usage (api_key_id, user_id, endpoint, method, status_code, duration_ms)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, req.APIKeyID, req.UserID, req.Endpoint, req.Method, req.StatusCode, req.DurationMs)
	if err != nil {
		return fmt.Errorf("failed to record usage: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// List — paginated request log for the dashboard
// ---------------------------------------------------------------------------

type ListParams struct {
	// Filter by API key ID (optional, leave empty for all keys)
	APIKeyID string `query:"api_key_id"`
	Limit    int    `query:"limit"`
	Offset   int    `query:"offset"`
}

type ListResponse struct {
	Events []*UsageEvent `json:"events"`
	Total  int           `json:"total"`
}

// List returns paginated usage events for the authenticated user.
//
//encore:api auth method=GET path=/usage
func List(ctx context.Context, p *ListParams) (*ListResponse, error) {
	uid, _ := auth.UserID()

	if p.Limit <= 0 || p.Limit > 100 {
		p.Limit = 50
	}

	// Count total
	var total int
	countQuery := `SELECT COUNT(*) FROM usage WHERE user_id = $1`
	countArgs := []any{uid}

	if p.APIKeyID != "" {
		countQuery += ` AND api_key_id = $2`
		countArgs = append(countArgs, p.APIKeyID)
	}

	if err := db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count failed: %w", err)
	}

	// Fetch page
	query := `
		SELECT id, api_key_id, user_id, endpoint, method, status_code, duration_ms, requested_at
		FROM usage
		WHERE user_id = $1`
	args := []any{uid}

	if p.APIKeyID != "" {
		query += ` AND api_key_id = $2`
		args = append(args, p.APIKeyID)
		query += ` ORDER BY requested_at DESC LIMIT $3 OFFSET $4`
		args = append(args, p.Limit, p.Offset)
	} else {
		query += ` ORDER BY requested_at DESC LIMIT $2 OFFSET $3`
		args = append(args, p.Limit, p.Offset)
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var events []*UsageEvent
	for rows.Next() {
		var e UsageEvent
		if err := rows.Scan(&e.ID, &e.APIKeyID, &e.UserID, &e.Endpoint, &e.Method, &e.StatusCode, &e.DurationMs, &e.RequestedAt); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		events = append(events, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row error: %w", err)
	}

	if events == nil {
		events = []*UsageEvent{}
	}

	return &ListResponse{Events: events, Total: total}, nil
}

// ---------------------------------------------------------------------------
// Summary — aggregated stats for the dashboard overview
// ---------------------------------------------------------------------------

type SummaryParams struct {
	// e.g. "7d", "30d", "90d" — defaults to "30d"
	Period string `query:"period"`
}

type EndpointStat struct {
	Endpoint   string  `json:"endpoint"`
	Method     string  `json:"method"`
	Count      int     `json:"count"`
	SuccessRate float64 `json:"success_rate"`
	AvgMs      *int    `json:"avg_ms,omitempty"`
}

type DailyStat struct {
	Date    string `json:"date"`
	Total   int    `json:"total"`
	Success int    `json:"success"`
	Errors  int    `json:"errors"`
}

type SummaryResponse struct {
	Period           string          `json:"period"`
	TotalRequests    int             `json:"total_requests"`
	SuccessRequests  int             `json:"success_requests"`
	ErrorRequests    int             `json:"error_requests"`
	AvgDurationMs    *int            `json:"avg_duration_ms,omitempty"`
	TopEndpoints     []*EndpointStat `json:"top_endpoints"`
	Daily            []*DailyStat    `json:"daily"`
}

// Summary returns aggregated usage metrics for the dashboard.
//
//encore:api auth method=GET path=/usage/summary
func Summary(ctx context.Context, p *SummaryParams) (*SummaryResponse, error) {
	uid, _ := auth.UserID()

	days, err := parsePeriodDays(p.Period)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}

	since := time.Now().AddDate(0, 0, -days)

	// Overall totals
	var total, success, errCount int
	var avgMs *int
	err = db.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status_code < 400),
			COUNT(*) FILTER (WHERE status_code >= 400),
			CASE WHEN COUNT(duration_ms) > 0 THEN CAST(AVG(duration_ms) AS INT) END
		FROM usage
		WHERE user_id = $1 AND requested_at >= $2
	`, uid, since).Scan(&total, &success, &errCount, &avgMs)
	if err != nil {
		return nil, fmt.Errorf("summary query failed: %w", err)
	}

	// Top 10 endpoints
	endpointRows, err := db.Query(ctx, `
		SELECT
			endpoint,
			method,
			COUNT(*) AS count,
			ROUND(COUNT(*) FILTER (WHERE status_code < 400) * 100.0 / COUNT(*), 2) AS success_rate,
			CASE WHEN COUNT(duration_ms) > 0 THEN CAST(AVG(duration_ms) AS INT) END AS avg_ms
		FROM usage
		WHERE user_id = $1 AND requested_at >= $2
		GROUP BY endpoint, method
		ORDER BY count DESC
		LIMIT 10
	`, uid, since)
	if err != nil {
		return nil, fmt.Errorf("endpoint stats query failed: %w", err)
	}
	defer endpointRows.Close()

	var topEndpoints []*EndpointStat
	for endpointRows.Next() {
		var s EndpointStat
		if err := endpointRows.Scan(&s.Endpoint, &s.Method, &s.Count, &s.SuccessRate, &s.AvgMs); err != nil {
			return nil, fmt.Errorf("endpoint stat scan failed: %w", err)
		}
		topEndpoints = append(topEndpoints, &s)
	}
	if err := endpointRows.Err(); err != nil {
		return nil, fmt.Errorf("endpoint rows error: %w", err)
	}

	// Daily breakdown
	dailyRows, err := db.Query(ctx, `
		SELECT
			TO_CHAR(DATE_TRUNC('day', requested_at), 'YYYY-MM-DD') AS date,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status_code < 400) AS success,
			COUNT(*) FILTER (WHERE status_code >= 400) AS errors
		FROM usage
		WHERE user_id = $1 AND requested_at >= $2
		GROUP BY DATE_TRUNC('day', requested_at)
		ORDER BY date ASC
	`, uid, since)
	if err != nil {
		return nil, fmt.Errorf("daily stats query failed: %w", err)
	}
	defer dailyRows.Close()

	var daily []*DailyStat
	for dailyRows.Next() {
		var d DailyStat
		if err := dailyRows.Scan(&d.Date, &d.Total, &d.Success, &d.Errors); err != nil {
			return nil, fmt.Errorf("daily stat scan failed: %w", err)
		}
		daily = append(daily, &d)
	}
	if err := dailyRows.Err(); err != nil {
		return nil, fmt.Errorf("daily rows error: %w", err)
	}

	if topEndpoints == nil {
		topEndpoints = []*EndpointStat{}
	}
	if daily == nil {
		daily = []*DailyStat{}
	}

	return &SummaryResponse{
		Period:          p.Period,
		TotalRequests:   total,
		SuccessRequests: success,
		ErrorRequests:   errCount,
		AvgDurationMs:   avgMs,
		TopEndpoints:    topEndpoints,
		Daily:           daily,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parsePeriodDays(period string) (int, error) {
	switch period {
	case "", "30d":
		return 30, nil
	case "7d":
		return 7, nil
	case "90d":
		return 90, nil
	default:
		return 0, fmt.Errorf("invalid period %q — use 7d, 30d, or 90d", period)
	}
}
