// Package types provides shared primitives used across all services.
// It is a plain Go package — no Encore service, no database.
package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

// Time is returned on every domain object. It carries both a Unix epoch
// (convenient for most languages) and an ISO 8601 UTC string (convenient
// for humans and JavaScript).
type Time struct {
	Unix int64  `json:"unix"` // seconds since epoch
	UTC  string `json:"utc"`  // e.g. "2026-03-15T10:30:00Z"
}

// NewTime creates a Time from a stdlib time.Time, normalised to UTC.
func NewTime(t time.Time) Time {
	u := t.UTC()
	return Time{
		Unix: u.Unix(),
		UTC:  u.Format(time.RFC3339),
	}
}

// ToTime converts back to a stdlib time.Time.
func (t Time) ToTime() time.Time {
	return time.Unix(t.Unix, 0).UTC()
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

// Metadata is a free-form JSON object attached to any resource.
// Values can be any JSON-serialisable type (nested objects, arrays, strings,
// numbers, booleans). Set a key to null to remove it.
type Metadata map[string]any

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

// PageParams are the query parameters accepted by every list endpoint.
type PageParams struct {
	// PageToken is an opaque cursor returned by a previous list call.
	// Omit for the first page.
	PageToken string `query:"page_token"`
	// Limit is the maximum number of items to return (1-100, default 20).
	Limit int `query:"limit"`
}

// Page is the standard envelope returned by every list endpoint.
type Page[T any] struct {
	Data          []T     `json:"data"`
	NextPageToken *string `json:"next_page_token"` // nil when no further pages
	PrevPageToken *string `json:"prev_page_token"` // nil on the first page
	TotalCount    int     `json:"total_count"`
	HasMore       bool    `json:"has_more"`
}

// cursorPayload is the internal structure encoded inside a page token.
type cursorPayload struct {
	ID        string `json:"id"`
	CreatedAt int64  `json:"created_at"` // unix seconds
	Direction string `json:"dir"`        // "next" | "prev"
}

// EncodeCursor encodes a cursor from an item's ID and creation time.
func EncodeCursor(id string, createdAt time.Time, direction string) string {
	p := cursorPayload{ID: id, CreatedAt: createdAt.Unix(), Direction: direction}
	b, _ := json.Marshal(p)
	return base64.URLEncoding.EncodeToString(b)
}

// DecodeCursor decodes an opaque page token back into its components.
// Returns an error if the token is malformed.
func DecodeCursor(token string) (id string, createdAt time.Time, direction string, err error) {
	b, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("invalid page_token")
	}
	var p cursorPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return "", time.Time{}, "", fmt.Errorf("invalid page_token")
	}
	return p.ID, time.Unix(p.CreatedAt, 0).UTC(), p.Direction, nil
}

// NormalisedLimit returns a valid limit in [1, 100], defaulting to 20.
func NormalisedLimit(limit int) int {
	switch {
	case limit <= 0:
		return 20
	case limit > 100:
		return 100
	default:
		return limit
	}
}

// ---------------------------------------------------------------------------
// API Versioning
// ---------------------------------------------------------------------------

// APIVersion is a date string in YYYY-MM-DD format, e.g. "2026-03-15".
type APIVersion string

const (
	// APIVersionLatest is the current default version assigned to new keys.
	APIVersionLatest APIVersion = "2026-03-15"
	// APIVersionMinimum is the oldest supported version.
	APIVersionMinimum APIVersion = "2026-03-15"
)

// IsValid reports whether v is a known, supported version.
func (v APIVersion) IsValid() bool {
	switch v {
	case APIVersionLatest:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Scopes
// ---------------------------------------------------------------------------

// Scope represents a permission granted to an API key.
type Scope string

const (
	ScopeAll Scope = "*" // full access — default for secret keys

	ScopeChargesRead    Scope = "charges:read"
	ScopeChargesWrite   Scope = "charges:write"
	ScopePaymentsRead   Scope = "payments:read"
	ScopePaymentsWrite  Scope = "payments:write"
	ScopeCustomersRead  Scope = "customers:read"
	ScopeCustomersWrite Scope = "customers:write"
	ScopeBillingRead    Scope = "billing:read"
	ScopeBillingWrite   Scope = "billing:write"
	ScopeFilesRead      Scope = "files:read"
	ScopeFilesWrite     Scope = "files:write"
	ScopeWebhooksRead   Scope = "webhooks:read"
	ScopeWebhooksWrite  Scope = "webhooks:write"
	ScopeRiskRead       Scope = "risk:read"
	ScopeRiskWrite      Scope = "risk:write"
)

// DefaultSecretScopes returns the full-access scope set for a secret key.
func DefaultSecretScopes() []Scope {
	return []Scope{ScopeAll}
}

// DefaultPublishableScopes returns the read-only scopes for a publishable key.
func DefaultPublishableScopes() []Scope {
	return []Scope{
		ScopeChargesRead,
		ScopePaymentsRead,
		ScopeCustomersRead,
	}
}

// HasScope reports whether scopes contains the required scope.
// A scopes list containing ScopeAll always returns true.
func HasScope(scopes []Scope, required Scope) bool {
	for _, s := range scopes {
		if s == ScopeAll || s == required {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Rich errors
// ---------------------------------------------------------------------------

// ErrorDetail is the standard error body returned on every non-2xx response.
// It is designed to be human-readable, actionable, and traceable.
type ErrorDetail struct {
	// Code is a stable, machine-readable error identifier, e.g. "charge_not_found".
	Code string `json:"code"`
	// Message is a plain-English description of what went wrong.
	Message string `json:"message"`
	// Suggestion tells the developer exactly what to do next.
	Suggestion string `json:"suggestion"`
	// DocsURL points to the documentation page for this specific error.
	DocsURL string `json:"docs_url"`
	// RequestID can be quoted to the support team for tracing.
	RequestID string `json:"request_id"`
	// Param is the request field that caused the error, if applicable.
	Param *string `json:"param,omitempty"`
}

// docsBase is the base URL for error documentation pages.
// Update this when the docs site is live.
const docsBase = "https://docs.example.com/errors"

// NewError constructs an ErrorDetail with a docs URL derived from code.
func NewError(requestID, code, message, suggestion string) ErrorDetail {
	return ErrorDetail{
		Code:       code,
		Message:    message,
		Suggestion: suggestion,
		DocsURL:    fmt.Sprintf("%s/%s", docsBase, code),
		RequestID:  requestID,
	}
}

// WithParam returns a copy of e with Param set.
func (e ErrorDetail) WithParam(param string) ErrorDetail {
	e.Param = &param
	return e
}
