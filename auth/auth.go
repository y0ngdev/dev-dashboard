package auth

import (
	"context"
	"fmt"
)

type User struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Created  int64  `json:"created"`
}
type RegisterRequest struct {
	Name            string `json:"name"`
	Email           string `json:"email"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

type RegisterResponse struct {
	Message string
}

//encore:api public method=POST path=/register
func Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	// Check if the parameters aren't empty
	//check if the email follows the valid definitons,
	//check if both password matches and if it fufils

	msg := fmt.Sprintf("Hello, %s!", req.Name)
	return &RegisterResponse{Message: msg}, nil
}
