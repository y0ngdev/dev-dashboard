package keys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/agentstation/publicid"
	"github.com/agentstation/utc"
	"github.com/agentstation/uuidkey"
	"github.com/google/uuid"

	"encore.app/types"
	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/storage/sqldb"
)

// keys service owns the "keys" database.
var db = sqldb.NewDatabase("keys", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

// WebhookEncKey is a 32-byte AES-256 key (hex-encoded) used to encrypt webhook
// signing secrets at rest. Set with:
//
//	encore secret set --type development WebhookEncKey
//	encore secret set --type production  WebhookEncKey
var secrets struct {
	WebhookEncKey string
}

// ---------------------------------------------------------------------------
// Key type & capability
// ---------------------------------------------------------------------------

// KeyType distinguishes production keys from sandbox keys.
type KeyType string

const (
	KeyTypeLive KeyType = "live"
	KeyTypeTest KeyType = "test"
)

// KeyCapability distinguishes server-side secret keys, client-safe publishable keys,
// and webhook signing secrets used to sign outbound webhook payloads.
type KeyCapability string

const (
	KeyCapabilitySecret      KeyCapability = "secret"
	KeyCapabilityPublishable KeyCapability = "publishable"
	KeyCapabilityWebhook     KeyCapability = "webhook"
)

// uuidkeyPrefix returns the uuidkey-compatible prefix for a given type+capability pair.
//
// Underscores are intentionally absent from the prefix: ParseAPIKey splits on "_"
// and expects exactly three parts (prefix_keybody_checksum), so the prefix itself
// must be a single token with no underscores.
//
// Mapping to Stripe-style conceptual names:
//
//	SKLIVE → sk_live_...  secret      + live
//	SKTEST → sk_test_...  secret      + test
//	PKLIVE → pk_live_...  publishable + live
//	PKTEST → pk_test_...  publishable + test
//	WHLIVE → wh_live_...  webhook     + live
//	WHTEST → wh_test_...  webhook     + test
func uuidkeyPrefix(kt KeyType, kc KeyCapability) string {
	switch {
	case kc == KeyCapabilityWebhook && kt == KeyTypeTest:
		return "WHTEST"
	case kc == KeyCapabilityWebhook:
		return "WHLIVE"
	case kc == KeyCapabilityPublishable && kt == KeyTypeTest:
		return "PKTEST"
	case kc == KeyCapabilityPublishable:
		return "PKLIVE"
	case kt == KeyTypeTest:
		return "SKTEST"
	default:
		return "SKLIVE"
	}
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

// generateKey creates a new API key using uuidkey.NewAPIKey with:
//   - A UUIDv7 base  (time-sortable, unique)
//   - 256-bit BLAKE2b entropy  (payment-processor grade)
//
// The format follows GitHub's Secret Scanning spec so any accidentally committed
// key will be automatically flagged by GitHub.
//
// For secret/publishable keys: only the SHA-256 hash and preview are stored.
// For webhook keys: additionally the raw key is encrypted (AES-256-GCM) and
// stored so the server can sign outbound webhook payloads.
func generateKey(kt KeyType, kc KeyCapability) (fullKey, keyHash, preview string, err error) {
	u, err := uuid.NewV7()
	if err != nil {
		return "", "", "", errors.New("failed to generate UUID")
	}

	prefix := uuidkeyPrefix(kt, kc)
	apiKey, err := uuidkey.NewAPIKey(prefix, u.String(), uuidkey.With256BitEntropy)
	if err != nil {
		return "", "", "", errors.New("failed to generate API key")
	}

	fullKey = apiKey.String()

	sum := sha256.Sum256([]byte(fullKey))
	keyHash = hex.EncodeToString(sum[:])

	// Preview: first 20 chars + "…"  e.g. "WHLIVE_00SSVNX0Y08YW…"
	const previewLen = 20
	preview = fullKey[:previewLen] + "…"

	return fullKey, keyHash, preview, nil
}

// hashKey returns the SHA-256 hex hash of a raw key, used for DB lookups.
func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// AES-256-GCM encryption for webhook signing secrets
// ---------------------------------------------------------------------------

// encryptSecret encrypts plaintext using AES-256-GCM with a random nonce.
// Returns hex(nonce || ciphertext).
// The key must be 32 hex-encoded bytes (64 hex chars).
func encryptSecret(plaintext string) (string, error) {
	keyBytes, err := hex.DecodeString(secrets.WebhookEncKey)
	if err != nil || len(keyBytes) != 32 {
		return "", errors.New("WebhookEncKey must be 32 bytes hex-encoded")
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", errors.New("failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.New("failed to generate nonce")
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decryptSecret decrypts a value produced by encryptSecret.
func decryptSecret(hexCiphertext string) (string, error) {
	keyBytes, err := hex.DecodeString(secrets.WebhookEncKey)
	if err != nil || len(keyBytes) != 32 {
		return "", errors.New("WebhookEncKey must be 32 bytes hex-encoded")
	}

	data, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return "", errors.New("invalid ciphertext encoding")
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", errors.New("failed to create cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("failed to create GCM")
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	return string(plaintext), nil
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// APIKey represents a single API key record returned to the dashboard.
// The full key value is never included — only the display preview.
type APIKey struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Description   string           `json:"description"`
	KeyType       KeyType          `json:"key_type"`
	KeyCapability KeyCapability    `json:"key_capability"`
	KeyPreview    string           `json:"key_preview"` // e.g. "WHLIVE_00SSVNX0Y08YW…"
	Scopes        []types.Scope    `json:"scopes"`
	Version       types.APIVersion `json:"version"`
	IsActive      bool             `json:"is_active"`
	LastUsedAt    *utc.Time        `json:"last_used_at,omitempty"`
	CreatedAt     utc.Time         `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Create API Key
// ---------------------------------------------------------------------------

type CreateKeyRequest struct {
	Name          string           `json:"name"`
	Description   string           `json:"description"`
	KeyType       KeyType          `json:"key_type"`       // "live" (default) or "test"
	KeyCapability KeyCapability    `json:"key_capability"` // "secret" (default), "publishable", or "webhook"
	Scopes        []types.Scope    `json:"scopes,omitempty"`
	Version       types.APIVersion `json:"version,omitempty"`
}

type CreateKeyResponse struct {
	// Key is the full API key string. It is shown exactly once — the backend
	// stores only the SHA-256 hash (and an encrypted copy for webhook keys).
	// This value cannot be recovered later.
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
		kt = KeyTypeLive
	}

	kc := req.KeyCapability
	if kc != KeyCapabilitySecret && kc != KeyCapabilityPublishable && kc != KeyCapabilityWebhook {
		kc = KeyCapabilitySecret
	}

	fullKey, keyHash, preview, err := generateKey(kt, kc)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to generate key").Err()
	}

	// For webhook keys, encrypt the raw secret so the server can sign payloads later.
	var keySecretEnc *string
	if kc == KeyCapabilityWebhook {
		enc, err := encryptSecret(fullKey)
		if err != nil {
			return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to encrypt webhook secret").Err()
		}
		keySecretEnc = &enc
	}

	// Resolve scopes: default to * for secret keys, read-only for publishable.
	scopes := req.Scopes
	if len(scopes) == 0 {
		if kc == KeyCapabilityPublishable {
			scopes = types.DefaultPublishableScopes()
		} else {
			scopes = types.DefaultSecretScopes()
		}
	}

	// Resolve version: default to latest.
	version := req.Version
	if version == "" || !version.IsValid() {
		version = types.APIVersionLatest
	}

	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to encode scopes").Err()
	}

	keyID, err := publicid.New()
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to generate key ID").Err()
	}

	var createdAt utc.Time
	err = db.QueryRow(ctx, `
		INSERT INTO api_keys
			(id, user_id, key_hash, key_preview, key_type, key_capability,
			 name, description, is_active, key_secret_enc, scopes, api_version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9, $10, $11)
		RETURNING created_at
	`, keyID, uid, keyHash, preview, string(kt), string(kc),
		req.Name, req.Description, keySecretEnc, scopesJSON, string(version),
	).Scan(&createdAt)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to create API key").Err()
	}

	return &CreateKeyResponse{
		Key: fullKey,
		APIKey: &APIKey{
			ID:            keyID,
			Name:          req.Name,
			Description:   req.Description,
			KeyType:       kt,
			KeyCapability: kc,
			KeyPreview:    preview,
			Scopes:        scopes,
			Version:       version,
			IsActive:      true,
			CreatedAt:     createdAt,
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
		SELECT id, name, description, key_type, key_capability, key_preview,
		       scopes, api_version, is_active, last_used_at, created_at
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
		var kt, kc, ver string
		var scopesJSON []byte
		if err := rows.Scan(
			&k.ID, &k.Name, &k.Description, &kt, &kc,
			&k.KeyPreview, &scopesJSON, &ver,
			&k.IsActive, &k.LastUsedAt, &k.CreatedAt,
		); err != nil {
			return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to scan key").Err()
		}
		k.KeyType = KeyType(kt)
		k.KeyCapability = KeyCapability(kc)
		k.Version = types.APIVersion(ver)
		if err := json.Unmarshal(scopesJSON, &k.Scopes); err != nil {
			k.Scopes = types.DefaultSecretScopes()
		}
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
// Roll (regenerate) API Key
// ---------------------------------------------------------------------------

type RollKeyResponse struct {
	// Key is the new API key string, shown once. The old key is immediately
	// invalidated — there is no overlap window.
	Key    string  `json:"key"`
	APIKey *APIKey `json:"api_key"`
}

// Roll replaces an existing key with a freshly generated one of the same type
// and capability. The old key hash is overwritten atomically — the old key
// stops working immediately and cannot be recovered.
//
//encore:api auth method=POST path=/keys/:id/roll
func Roll(ctx context.Context, id string) (*RollKeyResponse, error) {
	eb := errs.B()
	uid, _ := auth.UserID()

	// Fetch the existing key's type and capability to preserve them.
	var ktStr, kcStr string
	err := db.QueryRow(ctx, `
		SELECT key_type, key_capability
		FROM api_keys WHERE id = $1 AND user_id = $2
	`, id, uid).Scan(&ktStr, &kcStr)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.NotFound).Msg("API key not found").Err()
	}
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to fetch key").Err()
	}

	kt := KeyType(ktStr)
	kc := KeyCapability(kcStr)

	newKey, newHash, newPreview, err := generateKey(kt, kc)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to generate key").Err()
	}

	// For webhook keys, re-encrypt the new secret.
	var newSecretEnc *string
	if kc == KeyCapabilityWebhook {
		enc, err := encryptSecret(newKey)
		if err != nil {
			return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to encrypt webhook secret").Err()
		}
		newSecretEnc = &enc
	}

	var k APIKey
	var scanKt, scanKc, scanVer string
	var scanScopesJSON []byte
	err = db.QueryRow(ctx, `
		UPDATE api_keys
		SET key_hash = $1, key_preview = $2, key_secret_enc = $3, is_active = true, last_used_at = NULL
		WHERE id = $4 AND user_id = $5
		RETURNING id, name, description, key_type, key_capability, key_preview,
		          scopes, api_version, is_active, last_used_at, created_at
	`, newHash, newPreview, newSecretEnc, id, uid).Scan(
		&k.ID, &k.Name, &k.Description, &scanKt, &scanKc, &k.KeyPreview,
		&scanScopesJSON, &scanVer, &k.IsActive, &k.LastUsedAt, &k.CreatedAt,
	)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.NotFound).Msg("API key not found").Err()
	}
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to roll key").Err()
	}

	k.KeyType = KeyType(scanKt)
	k.KeyCapability = KeyCapability(scanKc)
	k.Version = types.APIVersion(scanVer)
	if err := json.Unmarshal(scanScopesJSON, &k.Scopes); err != nil {
		k.Scopes = types.DefaultSecretScopes()
	}
	return &RollKeyResponse{Key: newKey, APIKey: &k}, nil
}

// ---------------------------------------------------------------------------
// ValidateKey — private, called by other services to authenticate API callers
// ---------------------------------------------------------------------------

// KeyInfo is returned to internal callers that validate an API key.
type KeyInfo struct {
	KeyID      string           `json:"key_id"`
	UserID     string           `json:"user_id"`
	KeyType    KeyType          `json:"key_type"`
	Capability KeyCapability    `json:"key_capability"`
	Version    types.APIVersion `json:"version"`
	Scopes     []types.Scope    `json:"scopes"`
}

type ValidateKeyRequest struct {
	Key string `json:"key"`
}

// ValidateKey looks up an active API key by its SHA-256 hash, records
// last_used_at, and returns the resolved key metadata.
// This is a private endpoint — callable only by services within this app.
//
// Webhook signing secrets (capability="webhook") are rejected here — they are
// not valid for API authentication. Use GetWebhookSecret to retrieve them for
// signing outbound payloads.
//
// The checksum embedded in the key format is verified before any DB round-trip,
// so typos are rejected immediately without a database hit.
//
//encore:api private method=POST path=/internal/keys/validate
func ValidateKey(ctx context.Context, req *ValidateKeyRequest) (*KeyInfo, error) {
	eb := errs.B()

	if req.Key == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("key is required").Err()
	}

	// Verify the embedded CRC32 checksum before hitting the DB.
	if _, err := uuidkey.ParseAPIKey(req.Key); err != nil {
		return nil, eb.Code(errs.Unauthenticated).Msg("invalid or inactive API key").Err()
	}

	h := hashKey(req.Key)

	var info KeyInfo
	var kt, kc string
	var scopesJSON []byte
	err := db.QueryRow(ctx, `
		SELECT id, user_id, key_type, key_capability, scopes, api_version
		FROM api_keys
		WHERE key_hash = $1 AND is_active = true
	`, h).Scan(&info.KeyID, &info.UserID, &kt, &kc, &scopesJSON, &info.Version)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.Unauthenticated).Msg("invalid or inactive API key").Err()
	}
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("key lookup failed").Err()
	}

	info.KeyType = KeyType(kt)
	info.Capability = KeyCapability(kc)
	if err := json.Unmarshal(scopesJSON, &info.Scopes); err != nil {
		info.Scopes = types.DefaultSecretScopes()
	}

	// Webhook signing secrets are not valid for API authentication.
	if info.Capability == KeyCapabilityWebhook {
		return nil, eb.Code(errs.Unauthenticated).Msg("invalid or inactive API key").Err()
	}

	_, _ = db.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, info.KeyID)

	return &info, nil
}

// ---------------------------------------------------------------------------
// GetWebhookSecret — private, called by the webhooks service to sign payloads
// ---------------------------------------------------------------------------

// WebhookSecretInfo contains the decrypted signing secret for a webhook key.
type WebhookSecretInfo struct {
	// Secret is the raw WHLIVE/WHTEST key string. Use it as the HMAC-SHA256
	// key when signing outbound webhook payloads.
	Secret  string  `json:"secret"`
	KeyID   string  `json:"key_id"`
	UserID  string  `json:"user_id"`
	KeyType KeyType `json:"key_type"`
}

type GetWebhookSecretRequest struct {
	// WebhookKeyID is the api_keys.id (publicid) of the webhook signing key.
	WebhookKeyID string `json:"webhook_key_id"`
}

// GetWebhookSecret retrieves and decrypts the raw webhook signing secret for a
// given active webhook key. Only returns secrets for capability="webhook" keys.
// This is a private endpoint — callable only by the webhooks service.
//
//encore:api private method=POST path=/internal/keys/webhook-secret
func GetWebhookSecret(ctx context.Context, req *GetWebhookSecretRequest) (*WebhookSecretInfo, error) {
	eb := errs.B()

	if req.WebhookKeyID == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("webhook_key_id is required").Err()
	}

	var info WebhookSecretInfo
	var kt string
	var encSecret string
	err := db.QueryRow(ctx, `
		SELECT id, user_id, key_type, key_secret_enc
		FROM api_keys
		WHERE id = $1 AND key_capability = 'webhook' AND is_active = true
	`, req.WebhookKeyID).Scan(&info.KeyID, &info.UserID, &kt, &encSecret)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.NotFound).Msg("webhook signing key not found or inactive").Err()
	}
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("webhook secret lookup failed").Err()
	}

	info.KeyType = KeyType(kt)

	secret, err := decryptSecret(encSecret)
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to decrypt webhook secret").Err()
	}
	info.Secret = secret

	_, _ = db.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, info.KeyID)

	return &info, nil
}
