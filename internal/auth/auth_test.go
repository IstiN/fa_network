package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func newMockWithUser(t *testing.T, login, password, name string) *MockProvider {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	m := NewMockProvider([]byte("0123456789abcdef0123456789abcdef"))
	m.AddUser(login, string(hash), name)
	return m
}

// AC-B10: with the mock provider the full login → JWT → validate flow runs
// with zero network access.
func TestMockProviderOfflineFlow(t *testing.T) {
	m := newMockWithUser(t, "neo", "secret123", "Thomas A.")

	token, err := m.IssueToken("neo", "secret123")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	principal, err := m.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if principal.UserID != "neo" || principal.DisplayName != "Thomas A." {
		t.Fatalf("principal = %+v", principal)
	}

	if _, err := m.IssueToken("neo", "wrong"); !IsInvalidToken(err) {
		t.Fatalf("wrong password err = %v", err)
	}
	if _, err := m.Validate(context.Background(), "garbage"); !IsInvalidToken(err) {
		t.Fatalf("garbage err = %v", err)
	}
	// Token from another issuer/secret must not validate.
	other := NewMockProvider([]byte("ffffffffffffffffffffffffffffffff"))
	other.AddUser("neo", string(mustBcrypt(t, "secret123")), "Thomas A.")
	foreign, err := other.IssueToken("neo", "secret123")
	if err != nil {
		t.Fatalf("foreign issue: %v", err)
	}
	if _, err := m.Validate(context.Background(), foreign); !IsInvalidToken(err) {
		t.Fatalf("cross-secret validation must fail, got %v", err)
	}
}

func TestMockProviderExpiry(t *testing.T) {
	m := newMockWithUser(t, "neo", "secret123", "")
	m.AddUser("trinity", string(mustBcrypt(t, "secret123")), "")
	now := time.Now()
	m.SetClock(func() time.Time { return now })
	token, err := m.IssueToken("trinity", "secret123")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := m.Validate(context.Background(), token); err != nil {
		t.Fatalf("fresh token: %v", err)
	}
	// Move past the 24h expiry.
	m.SetClock(func() time.Time { return now.Add(25 * time.Hour) })
	if _, err := m.Validate(context.Background(), token); !IsInvalidToken(err) {
		t.Fatalf("expired token err = %v", err)
	}
}

func mustBcrypt(t *testing.T, password string) []byte {
	t.Helper()
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return b
}

// rsaJWKSHandler serves a JWKS document for the test RSA key.
func rsaJWKSHandler(t *testing.T, key *rsaKey) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{jwkOf(key)},
		})
	})
}

func jwkOf(key *rsaKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.nBytes()),
		"e":   base64.RawURLEncoding.EncodeToString(key.eBytes()),
	}
}

// signRS256 mints an RS256 token for the claims via the test key.
func signRS256(t *testing.T, key *rsaKey, claims Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(key.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// AC-B11: an OIDC issuer/JWKS wired via env-only options validates its
// tokens; foreign tokens do not.
func TestOIDCProviderWithFakeIdP(t *testing.T) {
	key := newRSAKey(t)
	server := httptest.NewServer(rsaJWKSHandler(t, key))
	defer server.Close()

	provider, err := NewOIDCProvider(OIDCOptions{
		Issuer:   "https://idp.example.com",
		ClientID: "fa-network",
		JWKSURL:  server.URL,
		Audience: "fa-network-api",
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	now := time.Now()
	good := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "https://idp.example.com",
			Audience:  jwt.ClaimStrings{"fa-network-api"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		Name: "Ada Lovelace",
	}
	principal, err := provider.Validate(context.Background(), signRS256(t, key, good))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if principal.UserID != "user-1" || principal.DisplayName != "Ada Lovelace" {
		t.Fatalf("principal = %+v", principal)
	}

	wrongIssuer := good
	wrongIssuer.Issuer = "https://evil.example.com"
	if _, err := provider.Validate(context.Background(), signRS256(t, key, wrongIssuer)); !IsInvalidToken(err) {
		t.Fatalf("issuer mismatch err = %v", err)
	}
	wrongAud := good
	wrongAud.Audience = jwt.ClaimStrings{"other-api"}
	if _, err := provider.Validate(context.Background(), signRS256(t, key, wrongAud)); !IsInvalidToken(err) {
		t.Fatalf("audience mismatch err = %v", err)
	}
}

// The ai-native provider validates the real IstiN/auth contract: HS256
// with the shared JWT_SECRET, iss = auth base host, locked display name
// from GET /api/auth/user (cached).
func TestAINativeProviderContract(t *testing.T) {
	var base string
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/user", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+strings.TrimSpace(currentTestToken) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "name": "Grace Hopper"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	base = server.URL

	provider := NewAINativeProvider(base, []byte("shared-jwt-secret"))
	iss := strings.TrimPrefix(base, "http://")
	claims := Claims{
		UserID: "usr-42",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   "grace@example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	currentTestToken = signHS256(t, claims)
	principal, err := provider.Validate(context.Background(), currentTestToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if principal.UserID != "usr-42" || principal.DisplayName != "Grace Hopper" {
		t.Fatalf("principal = %+v", principal)
	}
	// The display name is cached: a second validation must not refetch.
	currentTestToken = signHS256(t, claims)
	if _, err := provider.Validate(context.Background(), currentTestToken); err != nil {
		t.Fatalf("second validate: %v", err)
	}
	if calls != 1 {
		t.Fatalf("/api/auth/user calls = %d, want 1 (cached)", calls)
	}
}

var currentTestToken string

func signHS256(t *testing.T, claims Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("shared-jwt-secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// Issuer and signature are enforced; a failing profile lookup degrades to
// the email subject instead of rejecting the request.
func TestAINativeProviderGuards(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/user", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	provider := NewAINativeProvider(server.URL, []byte("shared-jwt-secret"))

	good := Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer:    strings.TrimPrefix(server.URL, "http://"),
		Subject:   "ada@example.com",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}

	if _, err := provider.Validate(context.Background(), signHS256(t, good)); err != nil {
		t.Fatalf("validate: %v", err)
	}
	wrongSecret := NewAINativeProvider(server.URL, []byte("other-secret"))
	if _, err := wrongSecret.Validate(context.Background(), signHS256(t, good)); !IsInvalidToken(err) {
		t.Fatalf("wrong secret err = %v, want invalid", err)
	}
	wrongIss := good
	wrongIss.Issuer = "evil.example.com"
	if _, err := provider.Validate(context.Background(), signHS256(t, wrongIss)); !IsInvalidToken(err) {
		t.Fatalf("issuer mismatch err = %v, want invalid", err)
	}
	// The canonical IstiN/auth issuer is the "ai-native" constant, not the
	// host — real tokens carry it.
	canonical := good
	canonical.Issuer = "ai-native"
	if _, err := provider.Validate(context.Background(), signHS256(t, canonical)); err != nil {
		t.Fatalf("canonical iss rejected: %v", err)
	}
	noIss := good
	noIss.Issuer = ""
	if _, err := provider.Validate(context.Background(), signHS256(t, noIss)); err != nil {
		t.Fatalf("legacy token without iss rejected: %v", err)
	}
	// Env override extends the accept-set.
	custom := NewAINativeProvider(server.URL, []byte("shared-jwt-secret"), "custom.iss")
	overridden := good
	overridden.Issuer = "custom.iss"
	if _, err := custom.Validate(context.Background(), signHS256(t, overridden)); err != nil {
		t.Fatalf("extra issuer rejected: %v", err)
	}
}

