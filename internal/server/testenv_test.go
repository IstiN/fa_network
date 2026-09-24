package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/auth"
	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/store"
	"github.com/IstiN/fa_network/internal/wakeup"
	"golang.org/x/crypto/bcrypt"
)

// testEnv is a full server over an in-memory store with mock auth and a
// fake hub — the whole two-class flow, zero network access (AC-B10).
type testEnv struct {
	t    *testing.T
	srv  *Server
	http *httptest.Server
	st   *store.MemStore
	hub  *hub.FakeClient
	auth *auth.MockProvider
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	st := store.NewMemStore()
	fakeHub := hub.NewFakeClient("r_test")
	provider := auth.NewMockProvider([]byte("0123456789abcdef0123456789abcdef"))
	dispatcher := wakeup.NewDispatcher(wakeup.Options{Store: st, Secret: []byte("sec")})
	srv := New(st, provider, fakeHub, dispatcher, Config{
		RetentionInactivityDays: 30,
		RetentionSweepInterval:  time.Hour,
	})
	env := &testEnv{t: t, srv: srv, st: st, hub: fakeHub, auth: provider}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	srv.RunRelay(ctx)
	env.http = httptest.NewServer(srv.Handler())
	t.Cleanup(env.http.Close)
	return env
}

func (e *testEnv) do(method, path string, body any, token string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.http.Config.Handler.ServeHTTP(rec, req)
	return rec
}

// authedToken mints a mock JWT for a user. Any MockProvider with the same
// dev secret validates it, so a throwaway issuer is enough.
func (e *testEnv) authedToken(login, name string) string {
	e.t.Helper()
	m := auth.NewMockProvider([]byte("0123456789abcdef0123456789abcdef"))
	m.AddUser(login, string(bcryptHash(e.t, "secret123")), name)
	token, err := m.IssueToken(login, "secret123")
	if err != nil {
		e.t.Fatalf("issue: %v", err)
	}
	return token
}

func bcryptHash(t *testing.T, password string) []byte {
	t.Helper()
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return b
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	decodeBody(t, rec, &body)
	return body.Error.Code
}

// createNetwork creates a network as an authed user; returns networkID.
func (e *testEnv) createNetwork(t *testing.T, ownerToken, name, password string) string {
	t.Helper()
	rec := e.do("POST", "/api/networks", map[string]string{"name": name, "password": password}, ownerToken)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create network: status %d body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Network struct {
			ID string `json:"id"`
		} `json:"network"`
	}
	decodeBody(t, rec, &body)
	return body.Network.ID
}

// join wraps the join endpoint; returns the session token.
func (e *testEnv) join(t *testing.T, networkID, password, displayName, token string) (string, map[string]any) {
	t.Helper()
	body := map[string]string{"password": password}
	if displayName != "" {
		body["displayName"] = displayName
	}
	rec := e.do("POST", "/api/networks/"+networkID+"/join", body, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("join: status %d body %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	decodeBody(t, rec, &out)
	sess, _ := out["sessionToken"].(string)
	return sess, out
}
