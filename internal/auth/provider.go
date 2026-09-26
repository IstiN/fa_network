package auth

import (
	"fmt"
	"os"
)

// Provider names selectable via FA_NETWORK_AUTH_PROVIDER.
const (
	ProviderMock     = "mock"
	ProviderAINative = "ai-native"
	ProviderOIDC     = "oidc"
)

// FromEnv builds the provider named by FA_NETWORK_AUTH_PROVIDER (mock when
// unset). Every value comes from env — switching providers is a deployment
// concern only (issue #1, AC-B10/AC-B11).
func FromEnv() (Provider, error) {
	switch os.Getenv("FA_NETWORK_AUTH_PROVIDER") {
	case "", ProviderMock:
		return NewMockProvider([]byte(os.Getenv("FA_NETWORK_MOCK_SECRET"))), nil
	case ProviderAINative:
		return aiNativeFromEnv()
	case ProviderOIDC:
		return oidcFromEnv()
	default:
		return nil, fmt.Errorf("unknown FA_NETWORK_AUTH_PROVIDER %q", os.Getenv("FA_NETWORK_AUTH_PROVIDER"))
	}
}

func aiNativeFromEnv() (Provider, error) {
	base := os.Getenv("FA_NETWORK_AUTH_BASE_URL")
	if base == "" {
		return nil, fmt.Errorf("FA_NETWORK_AUTH_BASE_URL is required for ai-native auth")
	}
	secret := os.Getenv("FA_NETWORK_AUTH_AINATIVE_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("FA_NETWORK_AUTH_AINATIVE_SECRET is required for ai-native auth (shared JWT_SECRET of the IstiN/auth deployment)")
	}
	var extra []string
	if iss := os.Getenv("FA_NETWORK_AUTH_AINATIVE_ISSUER"); iss != "" {
		extra = append(extra, iss)
	}
	return NewAINativeProvider(base, []byte(secret), extra...), nil
}

func oidcFromEnv() (Provider, error) {
	return NewOIDCProvider(OIDCOptions{
		Issuer:   os.Getenv("FA_NETWORK_AUTH_OIDC_ISSUER"),
		ClientID: os.Getenv("FA_NETWORK_AUTH_OIDC_CLIENT_ID"),
		JWKSURL:  os.Getenv("FA_NETWORK_AUTH_OIDC_JWKS_URL"),
		Audience: os.Getenv("FA_NETWORK_AUTH_OIDC_AUDIENCE"),
	})
}
