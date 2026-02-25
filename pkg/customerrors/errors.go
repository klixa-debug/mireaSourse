package customerrors

import (
	"errors"
)

type AuthError struct {
	Type    string
	Message string
	Err     error
}

func (e *AuthError) Error() string {
	return e.Message
}

func NewAuthError(errType string, message string, err error) *AuthError {
	return &AuthError{
		Type:    errType,
		Message: err.Error(),
		Err:     errors.New(message),
	}
}
