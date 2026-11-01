package server

// wsticket_test.go — security review #7: one-time 60s tickets keep the
// long-lived session bearer out of URLs and ingress logs. ?token= stays
// as a legacy fallback so existing clients keep working.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// ticketFor mints a ticket over HTTP for the given session token.
func ticketFor(t *testing.T, env *testEnv, sess string) string {
	t.Helper()
	rec := env.do("POST", "/api/ws-ticket", nil, sess)
	if rec.Code != http.StatusOK {
		t.Fatalf("ws-ticket: status %d body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Ticket    string `json:"ticket"`
		ExpiresIn int    `json:"expiresIn"`
	}
	decodeBody(t, rec, &out)
	if out.Ticket == "" || out.ExpiresIn != 60 {
		t.Fatalf("ws-ticket: bad payload %+v", out)
	}
	return out.Ticket
}

// dialWSQuery connects with a query parameter instead of a header. A nil
// client plus the HTTP status reports a rejected upgrade.
func dialWSQuery(t *testing.T, env *testEnv, query string) (*wsClient, int) {
	t.Helper()
	url := "ws" + strings.TrimPrefix(env.http.URL, "http") + "/ws?" + query
	conn, resp, err := websocket.Dial(context.Background(), url, nil)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return nil, status
	}
	t.Cleanup(func() { conn.CloseNow() })
	return &wsClient{t: t, conn: conn}, 0
}

func TestWSTicketConnectAndSingleUse(t *testing.T) {
	env := newTestEnv(t)
	_, _, guestSess, _, _ := setupNetwork(t, env)

	ticket := ticketFor(t, env, guestSess)
	client, status := dialWSQuery(t, env, "ticket="+ticket)
	if client == nil {
		t.Fatalf("ticket dial rejected: status %d", status)
	}
	client.next("roster.snapshot")

	// Replay of the same ticket must fail at the handshake (single use,
	// consumed by the first attempt even though it succeeded).
	if replay, status := dialWSQuery(t, env, "ticket="+ticket); replay != nil {
		t.Fatal("ticket replay accepted")
	} else if status != http.StatusUnauthorized {
		t.Fatalf("ticket replay status = %d, want 401", status)
	}
}

func TestWSTicketRequiresSession(t *testing.T) {
	env := newTestEnv(t)
	for name, tok := range map[string]string{"missing": "", "garbage": "not-a-session"} {
		rec := env.do("POST", "/api/ws-ticket", nil, tok)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", name, rec.Code)
		}
	}
}

func TestWSTicketRateLimited(t *testing.T) {
	env := newTestEnv(t)
	_, _, guestSess, _, _ := setupNetwork(t, env)

	for i := 0; i < wsTicketRateN; i++ {
		ticketFor(t, env, guestSess)
	}
	rec := env.do("POST", "/api/ws-ticket", nil, guestSess)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}

func TestWSTicketLegacyTokenFallback(t *testing.T) {
	env := newTestEnv(t)
	_, _, guestSess, _, _ := setupNetwork(t, env)

	client, status := dialWSQuery(t, env, "token="+guestSess)
	if client == nil {
		t.Fatalf("legacy token dial rejected: status %d", status)
	}
	client.next("roster.snapshot")
}

func TestTicketStoreExpiryAndSingleConsume(t *testing.T) {
	now := time.Now()
	store := newTicketStore(func() time.Time { return now })

	id := store.issue("sess-tok")
	now = now.Add(wsTicketTL + time.Second)
	if tok, ok := store.consume(id); ok || tok != "" {
		t.Fatal("expired ticket consumed")
	}

	id = store.issue("sess-tok-2")
	if tok, ok := store.consume(id); !ok || tok != "sess-tok-2" {
		t.Fatalf("fresh ticket consume = %q %v", tok, ok)
	}
	if _, ok := store.consume(id); ok {
		t.Fatal("ticket consumed twice")
	}
}
