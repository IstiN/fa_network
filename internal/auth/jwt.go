package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the dmtools-compatible JWT claim shape shared by the mock
// provider (issuer) and every validating provider.
type Claims struct {
	jwt.RegisteredClaims
	Name string `json:"name,omitempty"`
	// UserID is the dmtools/IstiN-auth userId claim (sub stays email).
	UserID string `json:"userId,omitempty"`
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, args...))
}

// verifyHS validates an HMAC token against any accepted secret.
func verifyHS(token string, secrets [][]byte) (*jwt.Token, error) {
	var lastErr error
	for _, secret := range secrets {
		parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, invalid("unexpected signing method %q", t.Method.Alg())
			}
			return secret, nil
		}, jwt.WithValidMethods([]string{"HS256"}))
		if err == nil {
			return parsed, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// verifyRS validates an RSA token against any accepted public key.
func verifyRS(token string, keys []any) (*jwt.Token, error) {
	var lastErr error
	for _, key := range keys {
		parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, invalid("unexpected signing method %q", t.Method.Alg())
			}
			return key, nil
		}, jwt.WithValidMethods([]string{"RS256"}))
		if err == nil {
			return parsed, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// validateToken dispatch: tries RS256 keys then HS256 secrets.
func validateToken(token string, rsaKeys []any, hsSecrets [][]byte) (*Claims, error) {
	if claims, err := tryRS(token, rsaKeys); err == nil {
		return claims, nil
	}
	return tryHS(token, hsSecrets)
}

func tryRS(token string, rsaKeys []any) (*Claims, error) {
	if len(rsaKeys) == 0 {
		return nil, invalid("no rsa keys")
	}
	parsed, err := verifyRS(token, rsaKeys)
	if err != nil {
		return nil, invalid("rsa validation failed: %v", err)
	}
	return parsed.Claims.(*Claims), nil
}

func tryHS(token string, hsSecrets [][]byte) (*Claims, error) {
	if len(hsSecrets) == 0 {
		return nil, invalid("no verification keys configured")
	}
	parsed, err := verifyHS(token, hsSecrets)
	if err != nil {
		return nil, invalid("hmac validation failed: %v", err)
	}
	return parsed.Claims.(*Claims), nil
}

// claimsToPrincipal maps validated claims to a Principal. Sub is required.
func claimsToPrincipal(c *Claims) (*Principal, error) {
	if c.Subject == "" {
		return nil, invalid("missing sub claim")
	}
	name := c.Name
	if name == "" {
		name = c.Subject
	}
	return &Principal{UserID: c.Subject, DisplayName: name}, nil
}
