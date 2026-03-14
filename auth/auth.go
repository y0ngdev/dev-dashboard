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
	"encore.dev/beta/errs"
	"golang.org/x/crypto/argon2"
	
	"encore.dev/storage/sqldb"
	//"golang.org/x/crypto/argon2"
)

//var db = sqldb.NewDatabase("user", sqldb.DatabaseConfig{
//	Migrations: "./migrations",
//})

var db = sqldb.NewDatabase("user", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

var secrets struct {
	SigningSecret string
}

type User struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"-"`
	CreatedAt int64  `json:"created"`
}
type RegisterRequest struct {
	Name            string `json:"name"`
	Email           string `json:"email"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

type RegisterResponse struct {
	Message string
	UserID  int64
}

//encore:api public method=POST path=/auth/register
func Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	
	if req.Name == "" || req.Email == "" || req.Password == "" || req.ConfirmPassword == "" {
		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: "missing required fields",
		}
	}
	
	// Check if the email follows the valid definitions
	emailRegex := `^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`
	
	re := regexp.MustCompile(emailRegex)
	
	if !re.MatchString(req.Email) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid email").Err()
	}
	
	// Check if user exists
	//var exists bool
	//_ = db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", req.Email).Scan(&exists)
	//if exists {
	//	return nil, &errs.Error{
	//		Code:    errs.AlreadyExists,
	//		Message: "user already exists",
	//	}
	//}
	
	// Check if both password matches and if it fulfils
	if err := ValidatePassword(req.Password, defaultRules); err != nil {
		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: err.Error(),
		}
	}
	
	// Validate password matches
	if err := ValidatePasswordMatch(req.Password, req.ConfirmPassword); err != nil {
		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: err.Error(),
		}
	}
	
	// Hash password
	_, err := hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	
	// Create user
	//var user User
	//err = db.QueryRow(ctx, `
	//	INSERT INTO users (email, password, name, email_verified)
	//	VALUES ($1, $2, $3, false)
	//	RETURNING id, email, name, created_at
	//`, req.Email, hashedPassword, req.Name).Scan(
	//	&user.ID, &user.Email, &user.Name, &user.CreatedAt,
	//)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to create user: %w", err)
	//}
	
	if _, err := sendVerificationEmailWithToken(ctx, req.Email, req.Name); err != nil {
		//if token, err := sendVerificationEmailWithToken(ctx, req.Email, req.Name); err != nil {
		// Log the error but don't fail registration
		fmt.Printf("Failed to send verification email: %v\n", err)
	}
	// Store verification token
	// _, err = db.Exec(ctx, `
	//    INSERT INTO email_verifications (user_id, token, expires_at)
	//    VALUES ($1, $2, $3)
	// `, &user.ID, token, expiresAt)
	//
	// if err != nil {
	//    return nil, fmt.Errorf("failed to store verification token: %w", err)
	// }
	
	return &RegisterResponse{
		Message: "User registered successfully. Please check your email to verify your account.",
		UserID:  1, // Replace with actual userID
	}, nil
}

// sendVerificationEmailWithToken generates a token and sends verification email
func sendVerificationEmailWithToken(ctx context.Context, userEmail, name string) (string, error) {
	// Generate email verification token
	token, err := generateVerificationToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate verification token: %w", err)
	}
	
	// Set token expiration (24 hours from now)
	expiresAt := time.Now().Add(24 * time.Hour)
	
	// Create signed verification token
	signedToken := signToken(token, userEmail, expiresAt)
	
	// Generate verification URL with signed token
	verificationURL := fmt.Sprintf("https://yourdomain.com/auth/verify/email?token=%s", signedToken)
	
	// Send verification email using the mail service
	return token, mailer.SendTemplate(ctx, &mailer.SendTemplateRequest{
		To:           userEmail,
		TemplateName: "verification",
		Data: map[string]string{
			"name": name,
			"url":  verificationURL,
		},
	})
}

// generateVerificationToken creates a secure random token
func generateVerificationToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// signToken creates a signed token containing: token.email.expiry.signature
func signToken(token, email string, expiresAt time.Time) string {
	// Create payload: token.email.expiry
	expiry := fmt.Sprintf("%d", expiresAt.Unix())
	payload := fmt.Sprintf("%s.%s.%s", token, email, expiry)
	
	// Create HMAC signature
	h := hmac.New(sha256.New, []byte(secrets.SigningSecret))
	h.Write([]byte(payload))
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))
	
	// Return signed token: payload.signature
	return fmt.Sprintf("%s.%s", payload, signature)
}

// verifySignedToken verifies and extracts data from a signed token
func verifySignedToken(signedToken string) (token, email string, expiresAt time.Time, err error) {
	// Split signed token into payload and signature
	parts := strings.Split(signedToken, ".")
	if len(parts) != 4 {
		return "", "", time.Time{}, fmt.Errorf("invalid signed token format")
	}
	
	token = parts[0]
	email = parts[1]
	expiryStr := parts[2]
	providedSignature := parts[3]
	
	// Recreate payload and verify signature
	payload := fmt.Sprintf("%s.%s.%s", token, email, expiryStr)
	h := hmac.New(sha256.New, []byte(secrets.SigningSecret))
	h.Write([]byte(payload))
	expectedSignature := base64.URLEncoding.EncodeToString(h.Sum(nil))
	
	if !hmac.Equal([]byte(expectedSignature), []byte(providedSignature)) {
		return "", "", time.Time{}, fmt.Errorf("invalid token signature")
	}
	
	// Parse expiry time
	var expiryUnix int64
	_, err = fmt.Sscanf(expiryStr, "%d", &expiryUnix)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("invalid expiry time")
	}
	expiresAt = time.Unix(expiryUnix, 0)
	
	// Check if token has expired
	if time.Now().After(expiresAt) {
		return "", "", time.Time{}, fmt.Errorf("token has expired")
	}
	
	return token, email, expiresAt, nil
}

// VerifyEmailParams holds the verification request
type VerifyEmailParams struct {
	Token string `query:"token"`
}

// VerifyEmailResponse holds the verification response
type VerifyEmailResponse struct {
	Message string
}

// VerifyEmail is an Encore API endpoint that verifies the email using the signed token
//
//encore:api public method=GET path=/auth/verify/email
func VerifyEmail(ctx context.Context, params *VerifyEmailParams) (*VerifyEmailResponse, error) {
	if params.Token == "" {
		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: "The link appears to be broken. Please request for another",
		}
	}
	
	// Verify and extract data from signed token
	//token, email, _, err := verifySignedToken(params.Token)
	//if err != nil {
	//	return nil, &errs.Error{
	//		Code:    errs.InvalidArgument,
	//		Message: fmt.Sprintf("invalid or expired verification token: %v", err),
	//	}
	//}
	
	// Verify the token exists in database and matches the email
	// var userID int64
	// var dbEmail string
	// err = db.QueryRow(ctx, `
	//    SELECT user_id, email FROM email_verifications ev
	//    JOIN users u ON ev.user_id = u.id
	//    WHERE ev.token = $1 AND u.email = $2
	// `, token, email).Scan(&userID, &dbEmail)
	//
	// if err != nil {
	//    return nil, &errs.Error{
	//       Code:    errs.NotFound,
	//       Message: "invalid verification token",
	//    }
	// }
	
	// Update user's email_verified status
	// _, err = db.Exec(ctx, `
	//    UPDATE users SET email_verified = true WHERE id = $1
	// `, userID)
	//
	// if err != nil {
	//    return nil, fmt.Errorf("failed to verify email: %w", err)
	// }
	
	// Delete the used verification token
	// _, err = db.Exec(ctx, `
	//    DELETE FROM email_verifications WHERE token = $1
	// `, token)
	
	return &VerifyEmailResponse{
		Message: "Email verified successfully! You can now log in.",
	}, nil
}

// ResendVerificationEmailParams holds the resend request
type ResendVerificationEmailParams struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// ResendVerificationEmailResponse holds the resend response
type ResendVerificationEmailResponse struct {
	Message string
}

// ResendVerificationEmail is an Encore API endpoint that resends the verification email
//
//encore:api public method=POST path=/auth/resend-verification
func ResendVerificationEmail(ctx context.Context, params *ResendVerificationEmailParams) (*ResendVerificationEmailResponse, error) {
	if params.Email == "" {
		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: "email is required",
		}
	}
	
	// Check if user exists and is not already verified
	// var userID int64
	// var name string
	// var emailVerified bool
	// err := db.QueryRow(ctx, `
	//    SELECT id, name, email_verified FROM users WHERE email = $1
	// `, params.Email).Scan(&userID, &name, &emailVerified)
	//
	// if err != nil {
	//    return nil, &errs.Error{
	//       Code:    errs.NotFound,
	//       Message: "user not found",
	//    }
	// }
	//
	// if emailVerified {
	//    return nil, &errs.Error{
	//       Code:    errs.InvalidArgument,
	//       Message: "email already verified",
	//    }
	// }
	
	// Delete old verification tokens
	// _, err = db.Exec(ctx, `
	//    DELETE FROM email_verifications WHERE user_id = $1
	// `, userID)
	
	if _, err := sendVerificationEmailWithToken(ctx, params.Email, params.Name); err != nil {
		//if token, err := sendVerificationEmailWithToken(ctx, req.Email, req.Name); err != nil {
		// Log the error but don't fail registration
		fmt.Printf("Failed to send verification email: %v\n", err)
	}
	
	// Store verification token
	// _, err = db.Exec(ctx, `
	//    INSERT INTO email_verifications (user_id, token, expires_at)
	//    VALUES ($1, $2, $3)
	// `, userID, token, expiresAt)
	//
	// if err != nil {
	//    return nil, fmt.Errorf("failed to store verification token: %w", err)
	// }
	
	return &ResendVerificationEmailResponse{
		Message: "Verification email sent successfully",
	}, nil
}

type PasswordRules struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

var defaultRules = PasswordRules{
	MinLength:      8,
	RequireUpper:   true,
	RequireLower:   true,
	RequireNumber:  true,
	RequireSpecial: true,
}

func ValidatePassword(password string, rules PasswordRules) error {
	if len(password) < rules.MinLength {
		return errors.New("password must be at least 8 characters long")
	}
	
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
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

func ValidatePasswordMatch(password, confirmPassword string) error {
	if password != confirmPassword {
		return errors.New("passwords do not match")
	}
	return nil
}

type Argon2Configuration struct {
	TimeCost   uint32
	MemoryCost uint32
	Threads    uint8
	KeyLength  uint32
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 24)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt generation failed: %w", err)
	}
	
	config := &Argon2Configuration{
		TimeCost:   2,
		MemoryCost: 64 * 1024,
		Threads:    4,
		KeyLength:  32,
	}
	
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		config.TimeCost,
		config.MemoryCost,
		config.Threads,
		config.KeyLength,
	)
	
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		config.MemoryCost,
		config.TimeCost,
		config.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func compareHash(password, storedHash string) (bool, error) {
	config, salt, hash, err := parseArgon2Hash(storedHash)
	if err != nil {
		return false, err // Already wrapped in parseArgon2Hash
	}
	
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		config.TimeCost,
		config.MemoryCost,
		config.Threads,
		config.KeyLength,
	)
	
	return subtle.ConstantTimeCompare(hash, computedHash) == 1, nil
}

func parseArgon2Hash(encodedHash string) (*Argon2Configuration, []byte, []byte, error) {
	components := strings.Split(encodedHash, "$")
	if len(components) != 6 {
		return nil, nil, nil, errors.New("invalid hash format: expected 6 components")
	}
	
	if components[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", components[1])
	}
	
	var version int
	if _, err := fmt.Sscanf(components[2], "v=%d", &version); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid version format: %w", err)
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("unsupported version: %d", version)
	}
	
	config := &Argon2Configuration{}
	if _, err := fmt.Sscanf(components[3], "m=%d,t=%d,p=%d",
		&config.MemoryCost, &config.TimeCost, &config.Threads); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid parameters format: %w", err)
	}
	
	salt, err := base64.RawStdEncoding.DecodeString(components[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("salt decoding failed: %w", err)
	}
	
	hash, err := base64.RawStdEncoding.DecodeString(components[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hash decoding failed: %w", err)
	}
	
	config.KeyLength = uint32(len(hash))
	
	return config, salt, hash, nil
}

type ChangePasswordRequest struct {
	OldPassword     string `json:"oldPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

//encore:api public method=POST path=/auth/change-password

func ChangePassword(ctx context.Context, req *ChangePasswordRequest) error {
	// Get current user ID from auth context
	// userID := auth.UserID()
	
	// TODO: Fetch user from database
	// TODO: Verify current password with VerifyPassword(storedHash, req.CurrentPassword)
	
	// Validate new password rules
	if err := ValidatePassword(req.NewPassword, defaultRules); err != nil {
		return &errs.Error{
			Code:    errs.InvalidArgument,
			Message: err.Error(),
		}
	}
	
	// Validate password match
	if err := ValidatePasswordMatch(req.NewPassword, req.ConfirmPassword); err != nil {
		return &errs.Error{
			Code:    errs.InvalidArgument,
			Message: err.Error(),
		}
	}
	
	// Ensure new password is different from old
	// if err := VerifyPassword(storedHash, req.NewPassword); err == nil {
	//     return &errs.Error{
	//         Code:    errs.InvalidArgument,
	//         Message: "new password must be different from current password",
	//     }
	// }
	
	// Hash new password
	hashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		return &errs.Error{
			Code:    errs.Internal,
			Message: "failed to process password",
		}
	}
	
	// TODO: Update password in database
	// TODO: Invalidate all existing sessions
	// TODO: Send confirmation email
	
	_ = hashedPassword // Use the hashed password in your DB update
	
	return nil
}
