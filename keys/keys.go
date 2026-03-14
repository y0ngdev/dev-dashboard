package keys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/agentstation/publicid"
	"github.com/agentstation/utc"

	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/storage/sqldb"
)

// keys service owns the "keys" database.
var db = sqldb.NewDatabase("keys", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

// ---------------------------------------------------------------------------
// Key type
// ---------------------------------------------------------------------------

// KeyType distinguishes live (production) keys from test (sandbox) keys.
type KeyType string

const (
	KeyTypeLive KeyType = "live"
	KeyTypeTest KeyType = "test"
)

// prefix returns the string prefix for this key type.
func (kt KeyType) prefix() string {
	switch kt {
	case KeyTypeTest:
		return "sk_test_"
	default:
		return "sk_live_"
	}
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

// keyBodyLen is the number of random bytes used to build the key body.
// base64.RawURLEncoding produces 4 chars per 3 bytes, so 54 bytes → 72 chars.
// prefix (8) + body (72) = 80 characters total.
const keyBodyLen = 54

// generateKey creates a new 80-character API key of the requested type.
// Only the SHA-256 hash and a display preview are stored — the full key is
// returned once to the caller and cannot be recovered by the backend.
func generateKey(kt KeyType) (fullKey, keyHash, preview string, err error) {
	buf := make([]byte, keyBodyLen)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", err
	}

	body := base64.RawURLEncoding.EncodeToString(buf) // 72 URL-safe chars
	prefix := kt.prefix()
	fullKey = prefix + body // e.g. "sk_live_<72 chars>" = 80 chars

	sum := sha256.Sum256([]byte(fullKey))
	keyHash = hex.EncodeToString(sum[:])

	// Preview: prefix + first 6 body chars + "…"
	preview = prefix + body[:6] + "…"
	return fullKey, keyHash, preview, nil
}

// hashKey returns the SHA-256 hex hash of a raw key for DB lookups.
func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// APIKey represents a single API key record returned to the dashboard.
// The full key value is never included — only the preview hint.
type APIKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	KeyType     KeyType   `json:"key_type"`
	KeyPreview  string    `json:"key_preview"` // e.g. "sk_live_Ab3xY9…"
	IsActive    bool      `json:"is_active"`
	LastUsedAt  *utc.Time `json:"last_used_at,omitempty"`
	CreatedAt   utc.Time  `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Create API Key
// ---------------------------------------------------------------------------

type CreateKeyRequest struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	KeyType     KeyType `json:"key_type"` // "live" (default) or "test"
}

type CreateKeyResponse struct {
	// Key is the full 80-character API key. It is shown exactly once — the
	// backend stores only the hash; this value cannot be recovered later.
	Key    string  `json:"key"`
	APIKey *APIKey `json:"api_key"`
}

// Create generates a new API key for the authenticated dashboard user.
//
//encore:api auth method=POST path=/keys
func Create(ctx context.Context, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	eb := errs.B()
	uid, _ := auth.UserID()

	if req.Name == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("key name is required").Err()
	}

	kt := req.KeyType
	if kt != KeyTypeLive && kt != KeyTypeTest {
		kt = KeyTypeLive // default
	}

	fullKey, keyHash, preview, err := generateKey(kt)
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("failed to generate key").Err()
	}

	// Use publicid for a short, URL-safe record ID.
	keyID, err := publicid.New()
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("failed to generate key ID").Err()
	}

	var createdAt utc.Time
	err = db.QueryRow(ctx, `
		INSERT INTO api_keys (id, user_id, key_hash, key_preview, key_type, name, description, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, true)
		RETURNING created_at
	`, keyID, uid, keyHash, preview, string(kt), req.Name, req.Description).Scan(&createdAt)
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to create API key").Err()
	}

	return &CreateKeyResponse{
		Key: fullKey,
		APIKey: &APIKey{
			ID:          keyID,
			Name:        req.Name,
			Description: req.Description,
			KeyType:     kt,
			KeyPreview:  preview,
			IsActive:    true,
			CreatedAt:   createdAt,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// List API Keys
// ---------------------------------------------------------------------------

type ListKeysResponse struct {
	Keys []*APIKey `json:"keys"`
}

// List returns all API keys for the authenticated dashboard user.
//
//encore:api auth method=GET path=/keys
func List(ctx context.Context) (*ListKeysResponse, error) {
	uid, _ := auth.UserID()

	rows, err := db.Query(ctx, `
		SELECT id, name, description, key_type, key_preview, is_active, last_used_at, created_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, uid)
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to list API keys").Err()
	}
	defer rows.Close()

	var apiKeys []*APIKey
	for rows.Next() {
		var k APIKey
		var kt string
		if err := rows.Scan(
			&k.ID, &k.Name, &k.Description, &kt,
			&k.KeyPreview, &k.IsActive, &k.LastUsedAt, &k.CreatedAt,
		); err != nil {
			return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to scan key").Err()
		}
		k.KeyType = KeyType(kt)
		apiKeys = append(apiKeys, &k)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("row iteration error").Err()
	}

	if apiKeys == nil {
		apiKeys = []*APIKey{}
	}

	return &ListKeysResponse{Keys: apiKeys}, nil
}

// ---------------------------------------------------------------------------
// Revoke API Key
// ---------------------------------------------------------------------------

type RevokeKeyResponse struct {
	Message string `json:"message"`
}

// Revoke deactivates an API key (soft delete — kept for audit).
//
//encore:api auth method=DELETE path=/keys/:id
func Revoke(ctx context.Context, id string) (*RevokeKeyResponse, error) {
	eb := errs.B()
	uid, _ := auth.UserID()

	res, err := db.Exec(ctx, `
		UPDATE api_keys SET is_active = false
		WHERE id = $1 AND user_id = $2
	`, id, uid)
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to revoke key").Err()
	}
	if res.RowsAffected() == 0 {
		return nil, eb.Code(errs.NotFound).Msg("API key not found").Err()
	}

	return &RevokeKeyResponse{Message: "API key revoked"}, nil
}

// ---------------------------------------------------------------------------
// Roll (regenerate) an API Key
// ---------------------------------------------------------------------------

type RollKeyResponse struct {
	// Key is the new 80-character API key, shown once. The old key is
	// immediately invalidated — there is no overlap window.
	Key    string  `json:"key"`
	APIKey *APIKey `json:"api_key"`
}

// Roll replaces an existing key with a freshly generated one of the same type.
// The old key hash is overwritten instantly — the old key stops working
// immediately and cannot be recovered.
//
//encore:api auth method=POST path=/keys/:id/roll
func Roll(ctx context.Context, id string) (*RollKeyResponse, error) {
	eb := errs.B()
	uid, _ := auth.UserID()

	// Fetch existing key type first.
	var ktStr string
	err := db.QueryRow(ctx, `
		SELECT key_type FROM api_keys WHERE id = $1 AND user_id = $2
	`, id, uid).Scan(&ktStr)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.NotFound).Msg("API key not found").Err()
	}
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to fetch key type").Err()
	}

	kt := KeyType(ktStr)
	newKey, newHash, newPreview, err := generateKey(kt)
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("failed to generate key").Err()
	}

	var k APIKey
	err = db.QueryRow(ctx, `
		UPDATE api_keys
		SET key_hash = $1, key_preview = $2, is_active = true, last_used_at = NULL
		WHERE id = $3 AND user_id = $4
		RETURNING id, name, description, key_type, key_preview, is_active, last_used_at, created_at
	`, newHash, newPreview, id, uid).Scan(
		&k.ID, &k.Name, &k.Description, &ktStr,
		&k.KeyPreview, &k.IsActive, &k.LastUsedAt, &k.CreatedAt,
	)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.NotFound).Msg("API key not found").Err()
	}
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to roll key").Err()
	}

	k.KeyType = KeyType(ktStr)
	return &RollKeyResponse{Key: newKey, APIKey: &k}, nil
}

// ---------------------------------------------------------------------------
// ValidateKey — private, called by other services to authenticate API callers
// ---------------------------------------------------------------------------

// KeyInfo is returned to internal callers that validate an API key.
type KeyInfo struct {
	KeyID   string  `json:"key_id"`
	UserID  string  `json:"user_id"`
	KeyType KeyType `json:"key_type"`
}

type ValidateKeyRequest struct {
	Key string `json:"key"`
}

// ValidateKey looks up an active API key by its hash, records last_used_at,
// and returns the resolved key_id, user_id, and key_type.
// This is a private endpoint — callable only by services within this app.
//
//encore:api private method=POST path=/internal/keys/validate
func ValidateKey(ctx context.Context, req *ValidateKeyRequest) (*KeyInfo, error) {
	eb := errs.B()

	if req.Key == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("key is required").Err()
	}

	h := hashKey(req.Key)

	var info KeyInfo
	var kt string
	err := db.QueryRow(ctx, `
		SELECT id, user_id, key_type FROM api_keys
		WHERE key_hash = $1 AND is_active = true
	`, h).Scan(&info.KeyID, &info.UserID, &kt)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.Unauthenticated).Msg("invalid or inactive API key").Err()
	}
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("key lookup failed").Err()
	}

	info.KeyType = KeyType(kt)

	_, _ = db.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, info.KeyID)

	return &info, nil
}
