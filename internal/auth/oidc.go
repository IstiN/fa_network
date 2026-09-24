package auth

import (
	"context"
	"strings"
)

// OIDCOptions configures the generic OpenID Connect verifier (AC-B11).
type OIDCOptions struct {
	Issuer   string
	ClientID string
	JWKSURL  string
	Audience string
}

// OIDCProvider validates tokens from any compliant IdP (Google, Microsoft,
// Keycloak…) — issuer + JWKS from env only, no rebuild.
type OIDCProvider struct {
	jwks   *jwksCache
	issuer string
	aud    string
}

// NewOIDCProvider builds the verifier; JWKS URL is mandatory.
func NewOIDCProvider(opts OIDCOptions) (*OIDCProvider, error) {
	if opts.JWKSURL == "" {
		return nil, invalid("oidc: FA_NETWORK_AUTH_OIDC_JWKS_URL is required")
	}
	return &OIDCProvider{
		jwks:   newJWKSCache(opts.JWKSURL, nil),
		issuer: opts.Issuer,
		aud:    opts.Audience,
	}, nil
}

// Validate implements Provider.
func (o *OIDCProvider) Validate(ctx context.Context, token string) (*Principal, error) {
	keys, err := o.jwks.rsaKeys(ctx)
	if err != nil {
		return nil, err
	}
	claims, err := validateToken(token, keys, nil)
	if err != nil {
		return nil, err
	}
	if o.issuer != "" && !strings.EqualFold(claims.Issuer, o.issuer) {
		return nil, invalid("oidc: issuer mismatch %q", claims.Issuer)
	}
	if o.aud != "" && !audienceContains(claims, o.aud) {
		return nil, invalid("oidc: audience mismatch")
	}
	return claimsToPrincipal(claims)
}

// audienceContains checks the aud claim for the configured audience.
func audienceContains(c *Claims, want string) bool {
	for _, a := range c.Audience {
		if a == want {
			return true
		}
	}
	return false
}
