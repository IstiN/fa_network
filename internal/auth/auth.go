// Package auth validates caller credentials. Three pluggable providers
// (mock / ai-native / oidc) selected by env — switching is a deployment
// concern only, never a code change (issue #1 steering additions).
package auth

import (
	"context"
	"errors"
)

// Principal is the validated identity behind an ai-native JWT.
type Principal struct {
	UserID      string
	DisplayName string
}

// Provider validates bearer tokens issued by an auth service.
type Provider interface {
	// Validate returns the principal for a token, or an error wrapping
	// ErrInvalidToken. Never stores tokens.
	Validate(ctx context.Context, token string) (*Principal, error)
}

// ErrInvalidToken marks any token that cannot be validated.
var ErrInvalidToken = errors.New("invalid token")

// IsInvalidToken reports whether err is or wraps ErrInvalidToken.
func IsInvalidToken(err error) bool { return errors.Is(err, ErrInvalidToken) }

// IsMissing reports whether err is or wraps ErrMissingToken.
func IsMissing(err error) bool { return errors.Is(err, ErrMissingToken) }

// ErrMissingToken marks a request that carried no credentials at all.
var ErrMissingToken = errors.New("missing token")
