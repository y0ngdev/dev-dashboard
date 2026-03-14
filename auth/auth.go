package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"encore.app/mailer"
	"encore.dev/beta/auth"
	"encore.dev/beta/errs"
	"encore.dev/rlog"
	"encore.dev/storage/sqldb"
	"golang.org/x/crypto/argon2"
)

var db = sqldb.NewDatabase("user", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

var secrets struct {
	SigningSecret string
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// UserData is the custom auth data attached to every authenticated request.
type UserData struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// User is the full user record returned in responses.
type User struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Auth Handler
// ---------------------------------------------------------------------------

// AuthHandler validates a Bearer session token and returns the user's UID + data.
//
//encore:authhandler
func AuthHandler(ctx context.Context, token string) (auth.UID, *UserData, error) {
	eb := errs.B().Code(errs.Unauthenticated)

	if token == "" {
		return "", nil, eb.Msg("missing token").Err()
	}

	var userID, name, email string
	err := db.QueryRow(ctx, `
		SELECT u.id, u.name, u.email
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.token = $1 AND s.expires_at > NOW()
	`, token).Scan(&userID, &name, &email)
	if errors.Is(err, sqldb.ErrNoRows) {
		return "", nil, eb.Msg("invalid or expired session").Err()
	}
	if err != nil {
		return "", nil, eb.Msg("internal error").Err()
	}

	return auth.UID(userID), &UserData{ID: userID, Name: name, Email: email}, nil
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

type RegisterRequest struct {
	Name            string `json:"name"`
	Email           string `json:"email"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

type RegisterResponse struct {
	Message string `json:"message"`
	UserID  string `json:"user_id"`
}

// Register creates a new user account and sends a verification email.
//
//encore:api public method=POST path=/auth/register
func Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	eb := errs.B()

	if req.Name == "" || req.Email == "" || req.Password == "" || req.ConfirmPassword == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("all fields are required").Err()
	}

	if !isValidEmail(req.Email) {
		return nil, eb.Code(errs.InvalidArgument).Msg("invalid email address").Err()
	}

	if err := validatePassword(req.Password, defaultRules); err != nil {
		return nil, eb.Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}

	if req.Password != req.ConfirmPassword {
		return nil, eb.Code(errs.InvalidArgument).Msg("passwords do not match").Err()
	}

	// Check for duplicate email
	var exists bool
	_ = db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, req.Email).Scan(&exists)
	if exists {
		return nil, eb.Code(errs.AlreadyExists).Msg("an account with this email already exists").Err()
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		return nil, eb.Code(errs.Internal).Msg("failed to process password").Err()
	}

	var userID string
	err = db.QueryRow(ctx, `
		INSERT INTO users (name, email, password_hash, email_verified)
		VALUES ($1, $2, $3, false)
		RETURNING id
	`, req.Name, req.Email, hashedPassword).Scan(&userID)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to create user").Err()
	}

	// Generate and store verification token
	token, expiresAt, err := createAndStoreVerificationToken(ctx, userID, req.Email)
	if err != nil {
		// Non-fatal: user created, email sending failed
		rlog.Warn("failed to create verification token", "user_id", userID, "err", err)
	} else {
		signedToken := signToken(token, req.Email, expiresAt)
		verificationURL := fmt.Sprintf("https://yourdomain.com/auth/verify/email?token=%s", signedToken)
		if err := mailer.SendTemplate(ctx, &mailer.SendTemplateRequest{
			To:           req.Email,
			TemplateName: "verification",
			Data:         map[string]string{"name": req.Name, "url": verificationURL},
		}); err != nil {
			rlog.Warn("failed to send verification email", "user_id", userID, "err", err)
		}
	}

	return &RegisterResponse{
		Message: "Account created. Please check your email to verify your account.",
		UserID:  userID,
	}, nil
}

// ---------------------------------------------------------------------------
// Login / Logout
// ---------------------------------------------------------------------------

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      *User     `json:"user"`
}

// Login authenticates a user and returns a session token.
//
//encore:api public method=POST path=/auth/login
func Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	eb := errs.B()

	if req.Email == "" || req.Password == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("email and password are required").Err()
	}

	var u User
	var passwordHash string
	err := db.QueryRow(ctx, `
		SELECT id, name, email, email_verified, password_hash, created_at
		FROM users WHERE email = $1
	`, req.Email).Scan(&u.ID, &u.Name, &u.Email, &u.EmailVerified, &passwordHash, &u.CreatedAt)
	if errors.Is(err, sqldb.ErrNoRows) {
		// Same error for missing user and wrong password (prevent user enumeration)
		return nil, eb.Code(errs.Unauthenticated).Msg("invalid email or password").Err()
	}
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("login failed").Err()
	}

	match, err := compareHash(req.Password, passwordHash)
	if err != nil || !match {
		return nil, eb.Code(errs.Unauthenticated).Msg("invalid email or password").Err()
	}

	if !u.EmailVerified {
		return nil, eb.Code(errs.FailedPrecondition).Msg("please verify your email before logging in").Err()
	}

	// Generate secure session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to generate session token").Err()
	}
	sessionToken := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	_, err = db.Exec(ctx, `
		INSERT INTO sessions (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`, u.ID, sessionToken, expiresAt)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to create session").Err()
	}

	return &LoginResponse{
		Token:     sessionToken,
		ExpiresAt: expiresAt,
		User:      &u,
	}, nil
}

// LogoutResponse holds the logout response.
type LogoutResponse struct {
	Message string `json:"message"`
}

// Logout invalidates the current session.
//
//encore:api auth method=POST path=/auth/logout
func Logout(ctx context.Context) (*LogoutResponse, error) {
	uid, _ := auth.UserID()

	_, err := db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, uid)
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to invalidate sessions").Err()
	}

	return &LogoutResponse{Message: "Logged out successfully"}, nil
}

// ---------------------------------------------------------------------------
// Email Verification
// ---------------------------------------------------------------------------

type VerifyEmailParams struct {
	Token string `query:"token"`
}

type VerifyEmailResponse struct {
	Message string `json:"message"`
}

// VerifyEmail verifies a user's email using the signed token from their email.
//
//encore:api public method=GET path=/auth/verify/email
func VerifyEmail(ctx context.Context, params *VerifyEmailParams) (*VerifyEmailResponse, error) {
	eb := errs.B()

	if params.Token == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("verification token is required").Err()
	}

	rawToken, email, _, err := verifySignedToken(params.Token)
	if err != nil {
		return nil, eb.Code(errs.InvalidArgument).Msg("invalid or expired verification link").Err()
	}

	// Confirm token exists in DB and belongs to this email
	var userID string
	err = db.QueryRow(ctx, `
		SELECT ev.user_id FROM email_verifications ev
		JOIN users u ON ev.user_id = u.id
		WHERE ev.token = $1 AND u.email = $2 AND ev.expires_at > NOW()
	`, rawToken, email).Scan(&userID)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, eb.Code(errs.NotFound).Msg("invalid or expired verification link").Err()
	}
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("verification lookup failed").Err()
	}

	_, err = db.Exec(ctx, `UPDATE users SET email_verified = true, updated_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to verify email").Err()
	}

	_, _ = db.Exec(ctx, `DELETE FROM email_verifications WHERE token = $1`, rawToken)

	// Fetch name for welcome email
	var name string
	_ = db.QueryRow(ctx, `SELECT name FROM users WHERE id = $1`, userID).Scan(&name)
	_ = mailer.SendTemplate(ctx, &mailer.SendTemplateRequest{
		To:           email,
		TemplateName: "welcome",
		Data:         map[string]string{"name": name},
	})

	return &VerifyEmailResponse{Message: "Email verified successfully. You can now log in."}, nil
}

// ---------------------------------------------------------------------------
// Resend Verification
// ---------------------------------------------------------------------------

type ResendVerificationEmailParams struct {
	Email string `json:"email"`
}

type ResendVerificationEmailResponse struct {
	Message string `json:"message"`
}

// ResendVerificationEmail resends the verification email for an unverified account.
//
//encore:api public method=POST path=/auth/resend-verification
func ResendVerificationEmail(ctx context.Context, params *ResendVerificationEmailParams) (*ResendVerificationEmailResponse, error) {
	eb := errs.B()

	if params.Email == "" {
		return nil, eb.Code(errs.InvalidArgument).Msg("email is required").Err()
	}

	var userID, name string
	var emailVerified bool
	err := db.QueryRow(ctx, `
		SELECT id, name, email_verified FROM users WHERE email = $1
	`, params.Email).Scan(&userID, &name, &emailVerified)
	if errors.Is(err, sqldb.ErrNoRows) {
		// Don't reveal whether the account exists
		return &ResendVerificationEmailResponse{
			Message: "If an unverified account exists with that email, a new verification link has been sent.",
		}, nil
	}
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("lookup failed").Err()
	}

	if emailVerified {
		return nil, eb.Code(errs.FailedPrecondition).Msg("email is already verified").Err()
	}

	// Invalidate old tokens
	_, _ = db.Exec(ctx, `DELETE FROM email_verifications WHERE user_id = $1`, userID)

	token, expiresAt, err := createAndStoreVerificationToken(ctx, userID, params.Email)
	if err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to create verification token").Err()
	}

	signedToken := signToken(token, params.Email, expiresAt)
	verificationURL := fmt.Sprintf("https://yourdomain.com/auth/verify/email?token=%s", signedToken)
	if err := mailer.SendTemplate(ctx, &mailer.SendTemplateRequest{
		To:           params.Email,
		TemplateName: "verification",
		Data:         map[string]string{"name": name, "url": verificationURL},
	}); err != nil {
		return nil, eb.Cause(err).Code(errs.Internal).Msg("failed to send verification email").Err()
	}

	return &ResendVerificationEmailResponse{
		Message: "If an unverified account exists with that email, a new verification link has been sent.",
	}, nil
}

// ---------------------------------------------------------------------------
// Change Password
// ---------------------------------------------------------------------------

type ChangePasswordRequest struct {
	OldPassword     string `json:"old_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// ChangePassword updates the authenticated user's password and invalidates all sessions.
//
//encore:api auth method=POST path=/auth/change-password
func ChangePassword(ctx context.Context, req *ChangePasswordRequest) error {
	eb := errs.B()
	uid, _ := auth.UserID()

	if req.OldPassword == "" || req.NewPassword == "" || req.ConfirmPassword == "" {
		return eb.Code(errs.InvalidArgument).Msg("all fields are required").Err()
	}

	if err := validatePassword(req.NewPassword, defaultRules); err != nil {
		return eb.Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}

	if req.NewPassword != req.ConfirmPassword {
		return eb.Code(errs.InvalidArgument).Msg("passwords do not match").Err()
	}

	var storedHash string
	err := db.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, uid).Scan(&storedHash)
	if err != nil {
		return eb.Cause(err).Code(errs.Internal).Msg("failed to fetch user").Err()
	}

	match, err := compareHash(req.OldPassword, storedHash)
	if err != nil || !match {
		return eb.Code(errs.Unauthenticated).Msg("current password is incorrect").Err()
	}

	// Prevent reusing the same password
	samePassword, _ := compareHash(req.NewPassword, storedHash)
	if samePassword {
		return eb.Code(errs.InvalidArgument).Msg("new password must be different from the current password").Err()
	}

	newHash, err := hashPassword(req.NewPassword)
	if err != nil {
		return eb.Code(errs.Internal).Msg("failed to process password").Err()
	}

	_, err = db.Exec(ctx, `
		UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2
	`, newHash, uid)
	if err != nil {
		return eb.Cause(err).Code(errs.Internal).Msg("failed to update password").Err()
	}

	// Invalidate all sessions to force re-login
	_, _ = db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, uid)

	return nil
}

// ---------------------------------------------------------------------------
// Me — get current user profile
// ---------------------------------------------------------------------------

// Me returns the authenticated user's profile.
//
//encore:api auth method=GET path=/auth/me
func Me(ctx context.Context) (*User, error) {
	uid, _ := auth.UserID()

	var u User
	err := db.QueryRow(ctx, `
		SELECT id, name, email, email_verified, created_at
		FROM users WHERE id = $1
	`, uid).Scan(&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.CreatedAt)
	if errors.Is(err, sqldb.ErrNoRows) {
		return nil, errs.B().Code(errs.NotFound).Msg("user not found").Err()
	}
	if err != nil {
		return nil, errs.B().Cause(err).Code(errs.Internal).Msg("failed to fetch user").Err()
	}

	return &u, nil
}

// ---------------------------------------------------------------------------
// Password helpers
// ---------------------------------------------------------------------------

type passwordRules struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

var defaultRules = passwordRules{
	MinLength:      8,
	RequireUpper:   true,
	RequireLower:   true,
	RequireNumber:  true,
	RequireSpecial: true,
}

func validatePassword(password string, rules passwordRules) error {
	if len(password) < rules.MinLength {
		return fmt.Errorf("password must be at least %d characters long", rules.MinLength)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsNumber(ch):
			hasNumber = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	if rules.RequireUpper && !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if rules.RequireLower && !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if rules.RequireNumber && !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if rules.RequireSpecial && !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

type argon2Config struct {
	TimeCost   uint32
	MemoryCost uint32
	Threads    uint8
	KeyLength  uint32
}

var defaultArgon2Config = &argon2Config{
	TimeCost:   2,
	MemoryCost: 64 * 1024,
	Threads:    4,
	KeyLength:  32,
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 24)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("salt generation failed")
	}

	cfg := defaultArgon2Config
	hash := argon2.IDKey([]byte(password), salt, cfg.TimeCost, cfg.MemoryCost, cfg.Threads, cfg.KeyLength)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		cfg.MemoryCost,
		cfg.TimeCost,
		cfg.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func compareHash(password, storedHash string) (bool, error) {
	cfg, salt, hash, err := parseArgon2Hash(storedHash)
	if err != nil {
		return false, err
	}

	computed := argon2.IDKey([]byte(password), salt, cfg.TimeCost, cfg.MemoryCost, cfg.Threads, cfg.KeyLength)
	return subtle.ConstantTimeCompare(hash, computed) == 1, nil
}

func parseArgon2Hash(encoded string) (*argon2Config, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid hash format")
	}
	if parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, errors.New("invalid hash version")
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("unsupported argon2 version: %d", version)
	}

	cfg := &argon2Config{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &cfg.MemoryCost, &cfg.TimeCost, &cfg.Threads); err != nil {
		return nil, nil, nil, errors.New("invalid hash params")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, errors.New("invalid hash salt encoding")
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, errors.New("invalid hash encoding")
	}

	cfg.KeyLength = uint32(len(hash))
	return cfg, salt, hash, nil
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

func createAndStoreVerificationToken(ctx context.Context, userID, email string) (string, time.Time, error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", time.Time{}, errors.New("token generation failed")
	}
	token := hex.EncodeToString(rawBytes)
	expiresAt := time.Now().Add(24 * time.Hour)

	_, err := db.Exec(ctx, `
		INSERT INTO email_verifications (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`, userID, token, expiresAt)
	if err != nil {
		return "", time.Time{}, errors.New("failed to store token")
	}

	return token, expiresAt, nil
}

// signToken creates a signed token: rawToken.email.expiry.signature
func signToken(token, email string, expiresAt time.Time) string {
	expiry := fmt.Sprintf("%d", expiresAt.Unix())
	payload := fmt.Sprintf("%s.%s.%s", token, email, expiry)

	h := hmac.New(sha256.New, []byte(secrets.SigningSecret))
	h.Write([]byte(payload))
	sig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s", payload, sig)
}

// verifySignedToken validates signature and expiry, returns (rawToken, email, expiresAt).
func verifySignedToken(signedToken string) (string, string, time.Time, error) {
	parts := strings.Split(signedToken, ".")
	if len(parts) != 4 {
		return "", "", time.Time{}, errors.New("invalid token format")
	}

	rawToken, email, expiryStr, providedSig := parts[0], parts[1], parts[2], parts[3]
	payload := fmt.Sprintf("%s.%s.%s", rawToken, email, expiryStr)

	h := hmac.New(sha256.New, []byte(secrets.SigningSecret))
	h.Write([]byte(payload))
	expectedSig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(expectedSig), []byte(providedSig)) {
		return "", "", time.Time{}, errors.New("invalid token signature")
	}

	var expiryUnix int64
	if _, err := fmt.Sscanf(expiryStr, "%d", &expiryUnix); err != nil {
		return "", "", time.Time{}, errors.New("invalid token expiry")
	}

	expiresAt := time.Unix(expiryUnix, 0)
	if time.Now().After(expiresAt) {
		return "", "", time.Time{}, errors.New("token has expired")
	}

	return rawToken, email, expiresAt, nil
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}
