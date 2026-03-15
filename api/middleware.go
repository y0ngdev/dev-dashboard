package api

import (
	"context"

	"encore.app/keys"
	"encore.app/types"
	"encore.dev/beta/errs"
	"encore.dev/middleware"
	"encore.dev/rlog"
)

// ---------------------------------------------------------------------------
// Context keys
// ---------------------------------------------------------------------------

// apiKeyContextKey stores the validated KeyInfo in the request context.
type apiKeyContextKey struct{}

// apiVersionContextKey stores the resolved API version in the request context.
type apiVersionContextKey struct{}

// ---------------------------------------------------------------------------
// Context accessors — exported so domain services can read them
// ---------------------------------------------------------------------------

// KeyInfoFromContext retrieves the validated KeyInfo injected by APIKeyMiddleware.
// Returns nil if called outside a tag:apikey endpoint (should not happen).
func KeyInfoFromContext(ctx context.Context) *keys.KeyInfo {
	v, _ := ctx.Value(apiKeyContextKey{}).(*keys.KeyInfo)
	return v
}

// VersionFromContext retrieves the resolved API version for the current request.
// Falls back to types.APIVersionLatest if not set.
func VersionFromContext(ctx context.Context) types.APIVersion {
	v, ok := ctx.Value(apiVersionContextKey{}).(types.APIVersion)
	if !ok || v == "" {
		return types.APIVersionLatest
	}
	return v
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// APIKeyMiddleware authenticates all merchant-facing API endpoints tagged with
// tag:apikey. It:
//  1. Extracts the Bearer token from the Authorization header.
//  2. Validates the token via keys.ValidateKey (CRC32 check + DB hash lookup).
//  3. Resolves the API version from the X-API-Version header, falling back to
//     the version stored on the key, then to the global latest.
//  4. Injects KeyInfo and the resolved version into the request context.
//
// Webhook signing secrets (capability="webhook") are rejected — only secret
// and publishable keys may call the merchant API.
//
//encore:middleware target=tag:apikey
func APIKeyMiddleware(req middleware.Request, next middleware.Next) middleware.Response {
	data := req.Data()
	ctx := req.Context()

	// 1. Extract Bearer token.
	authHeader := data.Headers.Get("Authorization")
	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) {
		return middleware.Response{
			Err: errs.B().Code(errs.Unauthenticated).Msg("missing or malformed Authorization header — expected: Authorization: Bearer <key>").Err(),
		}
	}
	rawKey := authHeader[len(prefix):]

	// 2. Validate via the keys service.
	info, err := keys.ValidateKey(ctx, &keys.ValidateKeyRequest{Key: rawKey})
	if err != nil {
		code := errs.Code(err)
		if code == errs.Unauthenticated || code == errs.InvalidArgument {
			return middleware.Response{Err: err}
		}
		rlog.Warn("api key validation error", "err", err)
		return middleware.Response{
			Err: errs.B().Code(errs.Internal).Msg("authentication failed").Err(),
		}
	}

	// 3. Resolve API version.
	// Priority: X-API-Version header > key's default version > global latest.
	version := types.APIVersion(data.Headers.Get("X-API-Version"))
	if !version.IsValid() {
		version = info.Version
	}
	if !version.IsValid() {
		version = types.APIVersionLatest
	}

	// 4. Inject into context.
	ctx = context.WithValue(ctx, apiKeyContextKey{}, info)
	ctx = context.WithValue(ctx, apiVersionContextKey{}, version)
	req = req.WithContext(ctx)

	return next(req)
}
