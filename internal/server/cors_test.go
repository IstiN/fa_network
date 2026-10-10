package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

func TestCORSPreflight(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/networks", nil)
	req.Header.Set("Origin", "https://fa1.dev")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	rec := httptest.NewRecorder()
	env.http.Config.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://fa1.dev" {
		t.Fatalf("ACAO = %q", got)
	}
	if rec.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Fatal("missing ACAH")
	}
}

func TestCORSSimpleRequest(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	req.Header.Set("Origin", "https://app.fa1.dev")
	rec := httptest.NewRecorder()
	env.http.Config.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.fa1.dev" {
		t.Fatalf("ACAO = %q, want subdomain echo", got)
	}
}

func TestCORSDisallowedOrigin(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	env.http.Config.Handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("ACAO leaked for disallowed origin")
	}
}

func TestWSAuthViaQueryToken(t *testing.T) {
	env := newTestEnv(t)
	networkID := env.createNetwork(t, env.authedToken("o1", "Owner"), "cors-net", "test-pass-1")
	sess, _ := env.join(t, networkID, "test-pass-1", "", env.authedToken("o1", "Owner"))

	// Browser WebSocket cannot set Authorization — the session token rides
	// in ?token= instead.
	url := "ws" + strings.TrimPrefix(env.http.URL, "http") + "/ws?token=" + sess
	conn, _, err := websocket.Dial(t.Context(), url, nil)
	if err != nil {
		t.Fatalf("dial ws with ?token=: %v", err)
	}
	defer conn.CloseNow()
	ws := &wsClient{t: t, conn: conn}

	if frame := ws.next("roster.snapshot"); frame.Type != "roster.snapshot" {
		t.Fatalf("first frame = %q, want roster.snapshot", frame.Type)
	}
}
