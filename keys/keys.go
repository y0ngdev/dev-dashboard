package keys

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/storage/sqldb"
)

// keys service shares the "user" database owned by the auth service.
var db = sqldb.Named("user")

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// APIKey represents a single API key record.
type APIKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	KeyPreview  string     `json:"key_preview"` // first 11 chars + "..."
	IsActive    bool       `json:"is_active"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Create API Key
// ---------------------------------------------------------------------------

type CreateKeyRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type CreateKeyResponse struct {
	Key    string  `json:"key"` // Full key — shown ONCE
	APIKey *APIKey `json:"api_key"`
}

// Create generates a new API key for the authenticated user.
//
//encore:api auth method=POST path=/keys
func Create(ctx context.Context, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	eb := errs.B()
	uid, _ := auth.UserID()

	if req.Name == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("key name is required").Err()
	}

	// Generate key: "sk_" prefix + 48 random hex bytes
	rawBytes := make([]byte, 48)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, eb.Code(errs.Internal).Msg("failed to generate key").Err()
	}
	fullKey := "sk_" + hex.EncodeToString(rawBytes)

	var keyID string
	var createdAt time.Time
	err := db.QueryRow(ctx, `
		INSERT INTO api_keys (user_id, key, name, description, is_active)
		VALUES ($1, $2, $3, $4, true)
		RETURNING id, created_at
	`, uid, fullKey, req.Name, req.Description).Scan(&keyID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	return &CreateKeyResponse{
		Key: fullKey,
		APIKey: &APIKey{
			ID:          keyID,
			Name:        req.Name,
			Description: req.Description,
			KeyPreview:  fullKey[:11] + "...",
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

// List returns all API keys for the authenticated user.
//
//encore:api auth method=GET path=/keys
func List(ctx context.Context) (*ListKeysResponse, error) {
	uid, _ := auth.UserID()

	rows, err := db.Query(ctx, `
		SELECT id, name, description, key, is_active, last_used_at, created_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, uid)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		var k APIKey
		var fullKey string
		if err := rows.Scan(&k.ID, &k.Name, &k.Description, &fullKey, &k.IsActive, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}
		k.KeyPreview = fullKey[:11] + "..."
		keys = append(keys, &k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	if keys == nil {
		keys = []*APIKey{}
	}

	return &ListKeysResponse{Keys: keys}, nil
}

// ---------------------------------------------------------------------------
// Revoke API Key
// ---------------------------------------------------------------------------

type RevokeKeyResponse struct {
	Message string `json:"message"`
}

// Revoke deactivates an API key. The key stays in the DB for audit purposes.
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
		return nil, fmt.Errorf("failed to revoke key: %w", err)
	}

	if res.RowsAffected() == 0 {
		return nil, eb.Code(errs.NotFound).Msg("API key not found").Err()
	}

	return &RevokeKeyResponse{Message: "API key revoked successfully"}, nil
}

// ---------------------------------------------------------------------------
// Roll (regenerate) an API key
// ---------------------------------------------------------------------------

type RollKeyResponse struct {
	Key    string  `json:"key"` // New full key — shown ONCE
	APIKey *APIKey `json:"api_key"`
}

// Roll replaces an existing API key with a new one (same name/description).
//
//encore:api auth method=POST path=/keys/:id/roll
func Roll(ctx context.Context, id string) (*RollKeyResponse, error) {
	eb := errs.B()
	uid, _ := auth.UserID()

	rawBytes := make([]byte, 48)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, eb.Code(errs.Internal).Msg("failed to generate key").Err()
	}
	newKey := "sk_" + hex.EncodeToString(rawBytes)

	var k APIKey
	var fullKey string
	err := db.QueryRow(ctx, `
		UPDATE api_keys
		SET key = $1, is_active = true, last_used_at = NULL
		WHERE id = $2 AND user_id = $3
		RETURNING id, name, description, key, is_active, last_used_at, created_at
	`, newKey, id, uid).Scan(
		&k.ID, &k.Name, &k.Description, &fullKey, &k.IsActive, &k.LastUsedAt, &k.CreatedAt,
	)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.NotFound).Msg("API key not found").Err()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to roll key: %w", err)
	}

	k.KeyPreview = fullKey[:11] + "..."

	return &RollKeyResponse{Key: fullKey, APIKey: &k}, nil
}

// ---------------------------------------------------------------------------
// ValidateKey — internal helper for usage tracking
// ---------------------------------------------------------------------------

// KeyInfo is returned when a key is successfully validated.
type KeyInfo struct {
	KeyID  string `json:"key_id"`
	UserID string `json:"user_id"`
}

type ValidateKeyRequest struct {
	Key string `json:"key"`
}

// ValidateKey looks up an active API key and updates last_used_at.
// Private — called internally by the usage service.
//
//encore:api private method=POST path=/internal/keys/validate
func ValidateKey(ctx context.Context, req *ValidateKeyRequest) (*KeyInfo, error) {
	eb := errs.B()

	if req.Key == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("key is required").Err()
	}

	var info KeyInfo
	err := db.QueryRow(ctx, `
		SELECT id, user_id FROM api_keys
		WHERE key = $1 AND is_active = true
	`, req.Key).Scan(&info.KeyID, &info.UserID)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.Unauthenticated).Msg("invalid or inactive API key").Err()
	}
	if err != nil {
		return nil, fmt.Errorf("key lookup failed: %w", err)
	}

	_, _ = db.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, info.KeyID)

	return &info, nil
}
