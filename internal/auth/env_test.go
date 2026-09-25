package auth

import (
	"testing"
)

// auth.FromEnv provider selection (AC-B10/AC-B11 wiring).
func TestAuthFromEnv(t *testing.T) {
	t.Setenv("FA_NETWORK_AUTH_PROVIDER", "")
	p, err := FromEnv()
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	if _, ok := p.(*MockProvider); !ok {
		t.Fatalf("default provider = %T", p)
	}

	t.Setenv("FA_NETWORK_AUTH_PROVIDER", "ai-native")
	if _, err := FromEnv(); err == nil {
		t.Fatal("ai-native without base URL must fail")
	}
	t.Setenv("FA_NETWORK_AUTH_BASE_URL", "https://ai-native.cloud")
	if _, err := FromEnv(); err == nil {
		t.Fatal("ai-native without shared secret must fail")
	}
	t.Setenv("FA_NETWORK_AUTH_AINATIVE_SECRET", "dev-secret-0123456789abcdef")
	if _, err := FromEnv(); err != nil {
		t.Fatalf("ai-native: %v", err)
	}

	t.Setenv("FA_NETWORK_AUTH_PROVIDER", "oidc")
	if _, err := FromEnv(); err == nil {
		t.Fatal("oidc without jwks must fail")
	}
	t.Setenv("FA_NETWORK_AUTH_OIDC_JWKS_URL", "https://idp/jwks")
	if _, err := FromEnv(); err != nil {
		t.Fatalf("oidc: %v", err)
	}

	t.Setenv("FA_NETWORK_AUTH_PROVIDER", "bogus")
	if _, err := FromEnv(); err == nil {
		t.Fatal("bogus provider must fail")
	}
}
