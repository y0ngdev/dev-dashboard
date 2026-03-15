// Package api is the API gateway layer. It contains no business logic.
//
// Responsibilities:
//   - APIKeyMiddleware (middleware.go): authenticates all tag:apikey endpoints
//     across every service by validating Bearer tokens via the keys service.
//   - Version resolution: parses the X-API-Version header and injects it into
//     the request context alongside KeyInfo.
//   - Scope enforcement: checks that the key's granted scopes satisfy the
//     requirement declared on each endpoint tag.
//
// All domain logic lives in the service packages:
//
//	payments/   → charges, payment intents, refunds
//	customers/  → customers, customer sessions
//	billing/    → products, prices, invoices, subscriptions
//	identity/   → accounts, files
//	risk/       → fraud reviews, radar rules
package api
