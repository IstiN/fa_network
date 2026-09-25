package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IstiN/fa_network/internal/auth"
)

func TestDevLoginIssuesToken(t *testing.T) {
	env := newTestEnv(t)
	env.auth.AddUser("dev", "devpass", "Dev User")

	rec := env.do(http.MethodPost, "/api/dev/login", map[string]string{"login": "dev", "password": "devpass"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	decodeBody(t, rec, &body)
	if body.Token == "" {
		t.Fatal("empty token")
	}
	// The minted token must pass the server's own auth gate (create network).
	rec = env.do(http.MethodPost, "/api/networks", map[string]string{"name": "dev-net", "password": "dev-password"}, body.Token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with dev token: %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestDevLoginRejectsBadPassword(t *testing.T) {
	env := newTestEnv(t)
	env.auth.AddUser("dev", "devpass", "Dev User")

	rec := env.do(http.MethodPost, "/api/dev/login", map[string]string{"login": "dev", "password": "wrong"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestDevLoginDisabledOutsideMock(t *testing.T) {
	env := newTestEnv(t)
	// Swap in a non-mock provider: the route must vanish (two-class law).
	srv := New(env.st, stubProvider{}, env.hub, env.srv.wake, Config{})
	raw, _ := json.Marshal(map[string]string{"login": "a", "password": "b"})
	req := httptest.NewRequest(http.MethodPost, "/api/dev/login", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// stubProvider implements auth.Provider without token issuing.
type stubProvider struct{}

func (stubProvider) Validate(context.Context, string) (*auth.Principal, error) {
	return nil, auth.ErrInvalidToken
}
