package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"encore.app/keys"
	"encore.dev/cron"
	"github.com/agentstation/publicid"
	"github.com/agentstation/utc"
	"github.com/google/uuid"

	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/rlog"
	"encore.dev/storage/sqldb"
)

// retryFailedCron runs every 5 minutes to retry pending webhook deliveries.
var _ = cron.NewJob("webhook-retry", cron.JobConfig{
	Title:    "Retry failed webhook deliveries",
	Every:    5 * cron.Minute,
	Endpoint: RetryFailed,
})

// webhooks service owns the "webhooks" database.
var db = sqldb.NewDatabase("webhooks", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// WebhookEndpoint is a registered URL that receives event notifications.
type WebhookEndpoint struct {
	ID           string   `json:"id"`
	WebhookKeyID string   `json:"webhook_key_id"`
	URL          string   `json:"url"`
	Description  string   `json:"description"`
	Events       []string `json:"events"` // nil/empty = all events
	IsActive     bool     `json:"is_active"`
	CreatedAt    utc.Time `json:"created_at"`
	UpdatedAt    utc.Time `json:"updated_at"`
}

// DeliveryStatus represents the outcome of a webhook delivery attempt.
type DeliveryStatus string

const (
	DeliveryStatusPending   DeliveryStatus = "pending"
	DeliveryStatusSucceeded DeliveryStatus = "succeeded"
	DeliveryStatusFailed    DeliveryStatus = "failed"
)

// WebhookDelivery is a single outbound delivery attempt record.
type WebhookDelivery struct {
	ID          string         `json:"id"`
	EndpointID  string         `json:"endpoint_id"`
	EventType   string         `json:"event_type"`
	EventID     string         `json:"event_id"`
	Status      DeliveryStatus `json:"status"`
	HTTPStatus  *int           `json:"http_status,omitempty"`
	Attempts    int            `json:"attempts"`
	NextRetryAt *utc.Time      `json:"next_retry_at,omitempty"`
	DeliveredAt *utc.Time      `json:"delivered_at,omitempty"`
	CreatedAt   utc.Time       `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Register Endpoint
// ---------------------------------------------------------------------------

type RegisterEndpointRequest struct {
	// WebhookKeyID is the api_keys.id of an active webhook-capability key
	// (WHLIVE or WHTEST). The associated signing secret is used to sign
	// every delivery to this endpoint.
	WebhookKeyID string `json:"webhook_key_id"`
	URL          string `json:"url"`
	Description  string `json:"description"`
	// Events is the list of event types to subscribe to.
	// Leave empty or omit to receive all event types.
	Events []string `json:"events,omitempty"`
}

type RegisterEndpointResponse struct {
	Endpoint *WebhookEndpoint `json:"endpoint"`
}

// RegisterEndpoint adds a new webhook endpoint for the authenticated user.
//
//encore:api auth method=POST path=/webhooks/endpoints
func RegisterEndpoint(ctx context.Context, req *RegisterEndpointRequest) (*RegisterEndpointResponse, error) {
	eb := errs.B()
	uid, _ := auth.UserID()

	if req.WebhookKeyID == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("webhook_key_id is required").Err()
	}
	if req.URL == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("url is required").Err()
	}
	if len(req.URL) > 2048 {
		return nil, eb.Code(errs.InvalidArgument).Msg("url must be 2048 characters or fewer").Err()
	}

	// Verify the webhook key exists, is active, and belongs to this user.
	_, err := keys.GetWebhookSecret(ctx, &keys.GetWebhookSecretRequest{
		WebhookKeyID: req.WebhookKeyID,
	})
	if err != nil {
		code := errs.Code(err)
		if code == errs.NotFound {
			return nil, eb.Code(errs.InvalidArgument).Msg("webhook signing key not found or inactive").Err()
		}
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to verify webhook key").Err()
	}

	endpointID, err := publicid.New()
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to generate endpoint ID").Err()
	}

	eventsJSON, err := json.Marshal(req.Events)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to serialize events").Err()
	}
	// Store NULL for empty/nil events (meaning: all events).
	var eventsArg *[]byte
	if len(req.Events) > 0 {
		b := eventsJSON
		eventsArg = &b
	}

	var ep WebhookEndpoint
	err = db.QueryRow(ctx, `
		INSERT INTO webhook_endpoints (id, user_id, webhook_key_id, url, description, events, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, true)
		RETURNING id, webhook_key_id, url, description, COALESCE(events::text, '[]'), is_active, created_at, updated_at
	`, endpointID, uid, req.WebhookKeyID, req.URL, req.Description, eventsArg).Scan(
		&ep.ID, &ep.WebhookKeyID, &ep.URL, &ep.Description,
		new(eventsScanner{&ep.Events}), &ep.IsActive, &ep.CreatedAt, &ep.UpdatedAt,
	)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to register endpoint").Err()
	}

	return &RegisterEndpointResponse{Endpoint: &ep}, nil
}

// ---------------------------------------------------------------------------
// List Endpoints
// ---------------------------------------------------------------------------

type ListEndpointsResponse struct {
	Endpoints []*WebhookEndpoint `json:"endpoints"`
}

// ListEndpoints returns all webhook endpoints for the authenticated user.
//
//encore:api auth method=GET path=/webhooks/endpoints
func ListEndpoints(ctx context.Context) (*ListEndpointsResponse, error) {
	uid, _ := auth.UserID()

	rows, err := db.Query(ctx, `
		SELECT id, webhook_key_id, url, description, COALESCE(events::text, '[]'), is_active, created_at, updated_at
		FROM webhook_endpoints
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, uid)
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to list endpoints").Err()
	}
	defer rows.Close()

	var endpoints []*WebhookEndpoint
	for rows.Next() {
		var ep WebhookEndpoint
		if err := rows.Scan(
			&ep.ID, &ep.WebhookKeyID, &ep.URL, &ep.Description,
			new(eventsScanner{&ep.Events}), &ep.IsActive, &ep.CreatedAt, &ep.UpdatedAt,
		); err != nil {
			return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to scan endpoint").Err()
		}
		endpoints = append(endpoints, &ep)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("row iteration error").Err()
	}

	if endpoints == nil {
		endpoints = []*WebhookEndpoint{}
	}

	return &ListEndpointsResponse{Endpoints: endpoints}, nil
}

// ---------------------------------------------------------------------------
// Delete Endpoint
// ---------------------------------------------------------------------------

type DeleteEndpointResponse struct {
	Message string `json:"message"`
}

// DeleteEndpoint removes a webhook endpoint (hard delete — deliveries are cascade-deleted).
//
//encore:api auth method=DELETE path=/webhooks/endpoints/:id
func DeleteEndpoint(ctx context.Context, id string) (*DeleteEndpointResponse, error) {
	eb := errs.B()
	uid, _ := auth.UserID()

	res, err := db.Exec(ctx, `DELETE FROM webhook_endpoints WHERE id = $1 AND user_id = $2`, id, uid)
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to delete endpoint").Err()
	}
	if res.RowsAffected() == 0 {
		return nil, eb.Code(errs.NotFound).Msg("webhook endpoint not found").Err()
	}

	return &DeleteEndpointResponse{Message: "webhook endpoint deleted"}, nil
}

// ---------------------------------------------------------------------------
// List Deliveries
// ---------------------------------------------------------------------------

type ListDeliveriesParams struct {
	EndpointID string `query:"endpoint_id"`
	Limit      int    `query:"limit"`
	Offset     int    `query:"offset"`
}

type ListDeliveriesResponse struct {
	Deliveries []*WebhookDelivery `json:"deliveries"`
	Total      int                `json:"total"`
}

// ListDeliveries returns the delivery log for the authenticated user's endpoints.
//
//encore:api auth method=GET path=/webhooks/deliveries
func ListDeliveries(ctx context.Context, p *ListDeliveriesParams) (*ListDeliveriesResponse, error) {
	uid, _ := auth.UserID()

	if p.Limit <= 0 || p.Limit > 100 {
		p.Limit = 50
	}

	var total int
	countQuery := `SELECT COUNT(*) FROM webhook_deliveries WHERE user_id = $1`
	countArgs := []any{uid}
	if p.EndpointID != "" {
		countQuery += ` AND endpoint_id = $2`
		countArgs = append(countArgs, p.EndpointID)
	}
	if err := db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("count failed").Err()
	}

	query := `
		SELECT id, endpoint_id, event_type, event_id, status, http_status, attempts, next_retry_at, delivered_at, created_at
		FROM webhook_deliveries
		WHERE user_id = $1`
	args := []any{uid}
	if p.EndpointID != "" {
		query += ` AND endpoint_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`
		args = append(args, p.EndpointID, p.Limit, p.Offset)
	} else {
		query += ` ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = append(args, p.Limit, p.Offset)
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("query failed").Err()
	}
	defer rows.Close()

	var deliveries []*WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		var status string
		if err := rows.Scan(
			&d.ID, &d.EndpointID, &d.EventType, &d.EventID,
			&status, &d.HTTPStatus, &d.Attempts,
			&d.NextRetryAt, &d.DeliveredAt, &d.CreatedAt,
		); err != nil {
			return nil, errs.B().Cause(err).Code(errs.Internal).Msg("scan failed").Err()
		}
		d.Status = DeliveryStatus(status)
		deliveries = append(deliveries, &d)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("row error").Err()
	}

	if deliveries == nil {
		deliveries = []*WebhookDelivery{}
	}

	return &ListDeliveriesResponse{Deliveries: deliveries, Total: total}, nil
}

// ---------------------------------------------------------------------------
// Dispatch — private, called by other services to send a webhook event
// ---------------------------------------------------------------------------

// DispatchRequest is sent by internal services when an event occurs.
type DispatchRequest struct {
	// UserID is the merchant's user ID — used to look up their active endpoints.
	UserID    string `json:"user_id"`
	EventType string `json:"event_type"`
	// EventID is a stable idempotency key for this event (e.g. a charge ID).
	// The same EventID+EventType pair will not be re-delivered to an endpoint.
	EventID string          `json:"event_id"`
	Payload json.RawMessage `json:"payload"`
}

type DispatchResponse struct {
	// DeliveryIDs lists the webhook_deliveries.id created — one per matching endpoint.
	DeliveryIDs []string `json:"delivery_ids"`
}

// Dispatch fans out a webhook event to all matching active endpoints for a user,
// signs each payload with the endpoint's webhook signing secret, and delivers
// synchronously. Failed deliveries are stored for retry.
// This is a private endpoint — callable only by services within this app.
//
//encore:api private method=POST path=/internal/webhooks/dispatch
func Dispatch(ctx context.Context, req *DispatchRequest) (*DispatchResponse, error) {
	eb := errs.B()

	if req.UserID == "" || req.EventType == "" || req.EventID == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("user_id, event_type, and event_id are required").Err()
	}

	// Look up all active endpoints for this user that subscribe to this event type.
	rows, err := db.Query(ctx, `
		SELECT id, webhook_key_id, url, COALESCE(events::text, '[]')
		FROM webhook_endpoints
		WHERE user_id = $1 AND is_active = true
	`, req.UserID)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to query endpoints").Err()
	}
	defer rows.Close()

	type endpointRow struct {
		id           string
		webhookKeyID string
		url          string
		events       []string
	}

	var matching []endpointRow
	for rows.Next() {
		var r endpointRow
		if err := rows.Scan(&r.id, &r.webhookKeyID, &r.url, new(eventsScanner{&r.events})); err != nil {
			return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to scan endpoint").Err()
		}
		// Filter: empty events list = all events; otherwise check membership.
		if len(r.events) == 0 || containsString(r.events, req.EventType) {
			matching = append(matching, r)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("endpoint iteration error").Err()
	}

	// Build the delivery envelope: wrap the caller's raw payload in a standard event object.
	type envelope struct {
		ID      string          `json:"id"`
		Type    string          `json:"type"`
		Created int64           `json:"created"`
		Data    json.RawMessage `json:"data"`
	}
	payloadBytes, err := json.Marshal(envelope{
		ID:      req.EventID,
		Type:    req.EventType,
		Created: time.Now().UTC().Unix(),
		Data:    req.Payload,
	})
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to marshal payload").Err()
	}

	var deliveryIDs []string
	for _, ep := range matching {
		deliveryID, err := deliverToEndpoint(ctx, ep.id, ep.webhookKeyID, ep.url, req, payloadBytes)
		if err != nil {
			// Log and continue — other endpoints should still receive the event.
			rlog.Warn("webhook delivery failed",
				"endpoint_id", ep.id,
				"event_type", req.EventType,
				"event_id", req.EventID,
				"err", err,
			)
			continue
		}
		deliveryIDs = append(deliveryIDs, deliveryID)
	}

	if deliveryIDs == nil {
		deliveryIDs = []string{}
	}

	return &DispatchResponse{DeliveryIDs: deliveryIDs}, nil
}

// ---------------------------------------------------------------------------
// Retry — private, called by a cron job to retry failed deliveries
// ---------------------------------------------------------------------------

type RetryFailedResponse struct {
	Retried int `json:"retried"`
}

// RetryFailed retries pending webhook deliveries whose next_retry_at is due.
// Intended to be called by a cron job.
//
//encore:api private method=POST path=/internal/webhooks/retry
func RetryFailed(ctx context.Context) (*RetryFailedResponse, error) {
	// Fetch up to 100 due deliveries in a single query.
	rows, err := db.Query(ctx, `
		SELECT d.id, d.endpoint_id, d.event_type, d.event_id, d.payload::text,
		       e.webhook_key_id, e.url, d.user_id
		FROM webhook_deliveries d
		JOIN webhook_endpoints e ON e.id = d.endpoint_id
		WHERE d.status = 'pending'
		  AND d.next_retry_at <= NOW()
		  AND e.is_active = true
		ORDER BY d.next_retry_at ASC
		LIMIT 100
	`)
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to fetch pending deliveries").Err()
	}
	defer rows.Close()

	type retryRow struct {
		deliveryID   string
		endpointID   string
		eventType    string
		eventID      string
		payloadText  string
		webhookKeyID string
		url          string
		userID       string
	}

	var due []retryRow
	for rows.Next() {
		var r retryRow
		if err := rows.Scan(
			&r.deliveryID, &r.endpointID, &r.eventType, &r.eventID, &r.payloadText,
			&r.webhookKeyID, &r.url, &r.userID,
		); err != nil {
			return nil, errs.B().Cause(err).Code(errs.Internal).Msg("retry scan failed").Err()
		}
		due = append(due, r)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("retry row error").Err()
	}

	retried := 0
	for _, r := range due {
		payloadBytes := []byte(r.payloadText)
		req := &DispatchRequest{
			UserID:    r.userID,
			EventType: r.eventType,
			EventID:   r.eventID,
		}
		if err := attemptDelivery(ctx, r.deliveryID, r.webhookKeyID, r.url, req, payloadBytes); err != nil {
			rlog.Warn("webhook retry failed",
				"delivery_id", r.deliveryID,
				"endpoint_id", r.endpointID,
				"err", err,
			)
			continue
		}
		retried++
	}

	return &RetryFailedResponse{Retried: retried}, nil
}

// ---------------------------------------------------------------------------
// Internal delivery helpers
// ---------------------------------------------------------------------------

// maxAttempts is the maximum number of delivery attempts before giving up.
const maxAttempts = 5

// deliverToEndpoint creates a new delivery record and attempts the first send.
func deliverToEndpoint(
	ctx context.Context,
	endpointID, webhookKeyID, url string,
	req *DispatchRequest,
	payloadBytes []byte,
) (deliveryID string, err error) {
	deliveryID, err = publicid.New()
	if err != nil {
		return "", fmt.Errorf("generate delivery ID: %w", err)
	}

	eventUUID, err := uuid.Parse(req.EventID)
	if err != nil {
		// Accept non-UUID event IDs — generate a deterministic UUID.
		eventUUID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(req.EventID))
	}

	_, err = db.Exec(ctx, `
		INSERT INTO webhook_deliveries
			(id, endpoint_id, user_id, event_type, event_id, payload, status, attempts, next_retry_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, NOW())
		ON CONFLICT DO NOTHING
	`, deliveryID, endpointID, req.UserID, req.EventType, eventUUID, json.RawMessage(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("insert delivery: %w", err)
	}

	return deliveryID, attemptDelivery(ctx, deliveryID, webhookKeyID, url, req, payloadBytes)
}

// attemptDelivery performs the HTTP POST, updates the delivery record, and
// schedules a retry with exponential back-off if it fails.
func attemptDelivery(
	ctx context.Context,
	deliveryID, webhookKeyID, url string,
	req *DispatchRequest,
	payloadBytes []byte,
) error {
	// Retrieve and decrypt the webhook signing secret.
	secretInfo, err := keys.GetWebhookSecret(ctx, &keys.GetWebhookSecretRequest{
		WebhookKeyID: webhookKeyID,
	})
	if err != nil {
		return fmt.Errorf("get webhook secret: %w", err)
	}

	// Sign the payload: HMAC-SHA256(secret, payload), hex-encoded.
	mac := hmac.New(sha256.New, []byte(secretInfo.Secret))
	mac.Write(payloadBytes)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// Deliver with a 10-second timeout.
	httpCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(httpCtx, http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		return scheduleRetry(ctx, deliveryID, nil, errors.New("invalid endpoint URL"))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Webhook-Signature", sig)
	httpReq.Header.Set("X-Webhook-Event", req.EventType)
	httpReq.Header.Set("X-Webhook-Delivery", deliveryID)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return scheduleRetry(ctx, deliveryID, nil, err)
	}
	defer resp.Body.Close()

	httpStatus := resp.StatusCode

	if httpStatus >= 200 && httpStatus < 300 {
		_, dbErr := db.Exec(ctx, `
			UPDATE webhook_deliveries
			SET status = 'succeeded', http_status = $1, attempts = attempts + 1,
			    delivered_at = NOW(), next_retry_at = NULL, updated_at = NOW()
			WHERE id = $2
		`, httpStatus, deliveryID)
		if dbErr != nil {
			rlog.Warn("failed to mark delivery succeeded", "delivery_id", deliveryID, "err", dbErr)
		}
		return nil
	}

	return scheduleRetry(ctx, deliveryID, &httpStatus, fmt.Errorf("endpoint returned HTTP %d", httpStatus))
}

// scheduleRetry increments the attempt counter and either schedules a retry
// with exponential back-off or marks the delivery as failed.
func scheduleRetry(ctx context.Context, deliveryID string, httpStatus *int, reason error) error {
	// Fetch current attempt count.
	var attempts int
	_ = db.QueryRow(ctx, `SELECT attempts FROM webhook_deliveries WHERE id = $1`, deliveryID).Scan(&attempts)

	nextAttempts := attempts + 1
	if nextAttempts >= maxAttempts {
		_, _ = db.Exec(ctx, `
			UPDATE webhook_deliveries
			SET status = 'failed', http_status = $1, attempts = $2,
			    next_retry_at = NULL, updated_at = NOW()
			WHERE id = $3
		`, httpStatus, nextAttempts, deliveryID)
		return reason
	}

	// Exponential back-off: 1m, 5m, 30m, 2h
	backoff := []time.Duration{1, 5, 30, 120}[min(nextAttempts-1, 3)] * time.Minute
	nextRetry := time.Now().Add(backoff)

	_, _ = db.Exec(ctx, `
		UPDATE webhook_deliveries
		SET http_status = $1, attempts = $2, next_retry_at = $3, updated_at = NOW()
		WHERE id = $4
	`, httpStatus, nextAttempts, nextRetry, deliveryID)

	return reason
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// eventsScanner is a sql.Scanner that deserialises a JSON text column into []string.
type eventsScanner struct {
	dst *[]string
}

func (s *eventsScanner) Scan(src any) error {
	if src == nil {
		*s.dst = nil
		return nil
	}
	var raw string
	switch v := src.(type) {
	case string:
		raw = v
	case []byte:
		raw = string(v)
	default:
		return fmt.Errorf("eventsScanner: unexpected type %T", src)
	}
	return json.Unmarshal([]byte(raw), s.dst)
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
