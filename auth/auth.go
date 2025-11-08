package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"encore.dev/beta/errs"
	"encore.dev/storage/sqldb"
	"golang.org/x/crypto/argon2"
)

var db = sqldb.NewDatabase("user", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

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
	var exists bool
	_ = db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", req.Email).Scan(&exists)
	if exists {
		return nil, errs.B().Code(errs.AlreadyExists).Msg("user already exists").Err()
	}

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
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	var user User
	err = db.QueryRow(ctx, `
		INSERT INTO users (email, password, name)
		VALUES ($1, $2, $3)
		RETURNING id, email, name, created_at
	`, req.Email, hashedPassword, req.Name).Scan(
		&user.ID, &user.Email, &user.Name, &user.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &RegisterResponse{
		Message: "User registered successfully",
		UserID:  user.ID,
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
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %migrations", components[1])
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
