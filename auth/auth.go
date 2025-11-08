package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"encore.dev/beta/errs"
	//"encore.dev/storage/sqldb"
	"golang.org/x/crypto/argon2"
)

//var db = sqldb.NewDatabase("user", sqldb.DatabaseConfig{
//	Migrations: "./migrationsz",
//})

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

//encore:api public method=POST path=/register
func Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {

	if req.Name == "" || req.Email == "" || req.Password == "" || req.ConfirmPassword == "" {

		return nil, &errs.Error{
			Code:    errs.InvalidArgument,
			Message: "missing required fields",
		}
	}

	//check if the email follows the valid definitions,
	emailRegex := `^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`

	re := regexp.MustCompile(emailRegex)

	if !re.MatchString(req.Email) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid email").Err()
	}
	//Check if user exists
	//var exists bool
	//_ = db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", req.Email).Scan(&exists)
	//if exists {
	//	return nil, &errs.Error{
	//		Code:    errs.AlreadyExists,
	//		Message: "user already exists",
	//	}
	//
	//}

	//check if both password matches and if it fulfils
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
	//	INSERT INTO users (email, password, name)
	//	VALUES ($1, $2, $3)
	//	RETURNING id, email, name, created_at
	//`, req.Email, hashedPassword, req.Name).Scan(
	//	&user.ID, &user.Email, &user.Name, &user.CreatedAt,
	//)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to create user: %w", err)
	//}

	// Generate email verification token
	token, err := generateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Set token expiration (24 hours from now)
	expiresAt := time.Now().Add(24 * time.Hour)

	// Store verification token
	// _, err = db.Exec(ctx, `
	//    INSERT INTO email_verifications (user_id, token, expires_at)
	//    VALUES ($1, $2, $3)
	// `, userID, token, expiresAt)
	//
	// if err != nil {
	//    return nil, fmt.Errorf("failed to store verification token: %w", err)
	// }

	// Send verification email
	verificationURL := fmt.Sprintf("https://yourdomain.com/verify-email?token=%s", token)
	err = sendVerificationEmail(req.Email, req.Name, verificationURL)
	if err != nil {
		// Log the error but don't fail registration
		fmt.Printf("Failed to send verification email: %v\n", err)
	}

	return &RegisterResponse{
		Message: "User registered successfully. Please check your email to verify your account.",
		UserID:  1, // Replace with actual userID
	}, nil

}
func generateVerificationToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// sendVerificationEmail sends the verification email to the user
func sendVerificationEmail(email, name, verificationURL string) error {
	// TODO: Implement actual email sending logic using your email service
	// Example services: SendGrid, AWS SES, Mailgun, SMTP

	subject := "Verify Your Email Address"
	body := fmt.Sprintf(`
		Hi %s,
		
		Thank you for registering! Please verify your email address by clicking the link below:
		
		%s
		
		This link will expire in 24 hours.
		
		If you didn't create an account, please ignore this email.
		
		Best regards,
		Your Team
	`, name, verificationURL)

	// Placeholder for actual email sending
	fmt.Printf("Sending email to %s with subject: %s\nBody: %s\n", email, subject, body)

	return nil
}

func VerifyEmail(ctx context.Context, token string) error {
	if token == "" {
		return &errs.Error{
			Code:    errs.InvalidArgument,
			Message: "verification token is required",
		}
	}

	// Check if token exists and is not expired
	// var userID int64
	// var expiresAt time.Time
	// err := db.QueryRow(ctx, `
	//    SELECT user_id, expires_at FROM email_verifications
	//    WHERE token = $1
	// `, token).Scan(&userID, &expiresAt)
	//
	// if err != nil {
	//    return &errs.Error{
	//       Code:    errs.NotFound,
	//       Message: "invalid or expired verification token",
	//    }
	// }

	// Check if token has expired
	// if time.Now().After(expiresAt) {
	//    return &errs.Error{
	//       Code:    errs.InvalidArgument,
	//       Message: "verification token has expired",
	//    }
	// }

	// Update user's email_verified status
	// _, err = db.Exec(ctx, `
	//    UPDATE users SET email_verified = true WHERE id = $1
	// `, userID)
	//
	// if err != nil {
	//    return fmt.Errorf("failed to verify email: %w", err)
	// }

	// Delete the used verification token
	// _, err = db.Exec(ctx, `
	//    DELETE FROM email_verifications WHERE token = $1
	// `, token)

	return nil
}

// ResendVerificationEmail resends the verification email
func ResendVerificationEmail(ctx context.Context, email string) error {
	if email == "" {
		return &errs.Error{
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
	// `, email).Scan(&userID, &name, &emailVerified)
	//
	// if err != nil {
	//    return &errs.Error{
	//       Code:    errs.NotFound,
	//       Message: "user not found",
	//    }
	// }
	//
	// if emailVerified {
	//    return &errs.Error{
	//       Code:    errs.InvalidArgument,
	//       Message: "email already verified",
	//    }
	// }

	// Delete old verification tokens
	// _, err = db.Exec(ctx, `
	//    DELETE FROM email_verifications WHERE user_id = $1
	// `, userID)

	// Generate new token
	token, err := generateVerificationToken()
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)

	// Store new verification token
	// _, err = db.Exec(ctx, `
	//    INSERT INTO email_verifications (user_id, token, expires_at)
	//    VALUES ($1, $2, $3)
	// `, userID, token, expiresAt)

	// Send verification email
	verificationURL := fmt.Sprintf("https://yourdomain.com/verify-email?token=%s", token)
	return sendVerificationEmail(email, "User", verificationURL) // Replace "User" with actual name
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

//encosre:api auth method=POST path=/auth/change-password
func ChangePassword(ctx context.Context, req *ChangePasswordRequest) error {
	// Validate new password matches
	if err := ValidatePasswordMatch(req.NewPassword, req.ConfirmPassword); err != nil {
		return &errs.Error{
			Code:    errs.InvalidArgument,
			Message: err.Error(),
		}
	}

	// Validate new password rules
	if err := ValidatePassword(req.NewPassword, defaultRules); err != nil {
		return &errs.Error{
			Code:    errs.InvalidArgument,
			Message: err.Error(),
		}
	}

	// Verify old password and update
	// ... your update logic here

	return nil
}
