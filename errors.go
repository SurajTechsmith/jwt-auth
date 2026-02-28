package auth

import "errors"

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrInvalidTokenType = errors.New("invalid token type")
	ErrServiceNotReady  = errors.New("auth service not initialized")
	ErrConfigNotReady   = errors.New("config not ready")
	ErrMissingUserID    = errors.New("user_id is required")
)
