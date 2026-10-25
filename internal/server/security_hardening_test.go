package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// Review #5: unauthenticated JSON bodies are capped (2 MiB join payload
// is rejected at decode, not verified against the password hash).
func TestJSONBodyCap(t *testing.T) {
	env := newTestEnv(t)
	_, _, _, _, networkID := setupNetwork(t, env)
	big := strings.Repeat("x", 2<<20)
	body := map[string]string{}
	body["pass"+"word"] = big
	rec := env.do("POST", "/api/networks/"+networkID+"/join", body, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized join = %d, want 400", rec.Code)
	}
	// Normal-sized bodies still work (join fatals on failure).
	env.join(t, networkID, "secret123", "ok-guest", "")
}

func joinAttempt(env *testEnv, networkID, remoteAddr, xff string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/networks/"+networkID+"/join",
		strings.NewReader(`{"password":"wrong"}`))
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rec, req)
	return rec
}

// Review #11: source-PORT changes must not reset the join-password
// throttle; behind a proxy the stable client IP comes from XFF.
func TestJoinThrottleStableClientIP(t *testing.T) {
	env := newTestEnv(t)
	_, _, _, _, networkID := setupNetwork(t, env)
	for i := 0; i < 5; i++ {
		rec := joinAttempt(env, networkID, fmt.Sprintf("10.0.0.1:%d", 4000+i), "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d = %d, want 403", i, rec.Code)
		}
	}
	if rec := joinAttempt(env, networkID, "10.0.0.1:4999", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt (new source port) = %d, want 429", rec.Code)
	}
	// A different client is independent.
	if rec := joinAttempt(env, networkID, "10.0.0.2:5000", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("other client = %d, want 403", rec.Code)
	}
	// XFF identity: same proxied client across LB source addresses.
	env2 := newTestEnv(t)
	_, _, _, _, net2 := setupNetwork(t, env2)
	for i := 0; i < 5; i++ {
		joinAttempt(env2, net2, fmt.Sprintf("10.9.0.%d:6000", i), "203.0.113.7, 10.9.0.1")
	}
	if rec := joinAttempt(env2, net2, "10.9.9.9:6000", "203.0.113.7, 10.9.0.1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("XFF-keyed 6th attempt = %d, want 429", rec.Code)
	}
}

func dialWSOrigin(env *testEnv, token, origin string) error {
	url := "ws" + strings.TrimPrefix(env.http.URL, "http") + "/ws"
	header := map[string][]string{"Authorization": {"Bearer " + token}}
	if origin != "" {
		header["Origin"] = []string{origin}
	}
	conn, _, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		return err
	}
	conn.CloseNow()
	return nil
}

// Review #13: the CORS allowlist applies to WS upgrades — legitimate
// cross-origin app hosts connect, unknown web origins are rejected.
func TestWSOriginAllowlist(t *testing.T) {
	env := newTestEnv(t)
	_, _, guestSess, _, _ := setupNetwork(t, env)
	if err := dialWSOrigin(env, guestSess, "https://network.fa1.dev"); err != nil {
		t.Fatalf("allowlisted origin rejected: %v", err)
	}
	if err := dialWSOrigin(env, guestSess, "https://evil.example"); err == nil {
		t.Fatal("evil origin must be rejected")
	}
	if err := dialWSOrigin(env, guestSess, ""); err != nil {
		t.Fatalf("origin-less agent dial broke: %v", err)
	}
}

// Review #6: WS sends share the REST per-member rate limit and the
// per-channel stored-byte cap.
func TestWSSendRateLimit(t *testing.T) {
	env := newTestEnv(t)
	_, _, guestSess, channelID, _ := setupNetwork(t, env)
	browser := dialWS(t, env, guestSess)
	browser.next("roster.snapshot")
	for i := 0; i < 21; i++ {
		browser.send(map[string]any{"type": "envelope.send", "channelId": channelID,
			"id": fmt.Sprintf("rl-%d", i), "payload": "Y2lwaGVy"})
	}
	frame := browser.next("error")
	payload, _ := json.Marshal(frame.Payload)
	if !strings.Contains(string(payload), CodeThrottled) {
		t.Fatalf("expected throttled error, got %s", payload)
	}
}

func TestWSSendChannelByteCap(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, guestSess, channelID, _ := setupNetwork(t, env)
	env.srv.cfg.ChannelBytesCap = 1 // first send exceeds nothing, second trips
	browser := dialWS(t, env, guestSess)
	browser.next("roster.snapshot")
	for i := 0; i < 2; i++ {
		browser.send(map[string]any{"type": "envelope.send", "channelId": channelID,
			"id": fmt.Sprintf("cap-%d", i), "payload": "Y2lwaGVyY2lwaGVy"})
	}
	frame := browser.next("error")
	payload, _ := json.Marshal(frame.Payload)
	if !strings.Contains(string(payload), CodeThrottled) {
		t.Fatalf("expected cap error, got %s", payload)
	}
	rec := env.do("GET", "/api/channels/"+channelID+"/messages", nil, ownerSess)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	decodeBody(t, rec, &page)
	if len(page.Items) != 1 {
		t.Fatalf("over-cap envelope was stored: %d items", len(page.Items))
	}
}

// Review #9: a duplicated delivery id is acknowledged without repeating
// CI dispatches (provider retry / captured-request replay).
func TestWebhookDuplicateDelivery(t *testing.T) {
	env, ci := newTriggerEnv(t, nil)
	body := []byte(webhookComment)
	headers := ghHeaders(t, "whsec", "issue_comment", body)
	headers["X-GitHub-Delivery"] = "delivery-1"
	rec := postWebhook(t, env, "github", body, headers)
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("first delivery = %d %s", rec.Code, rec.Body.String())
	}
	waitFor(t, "dispatch", func() bool { return ciDispatchCount(ci) == 1 })

	rec = postWebhook(t, env, "github", body, headers)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "duplicate") {
		t.Fatalf("duplicate = %d %s", rec.Code, rec.Body.String())
	}
	time.Sleep(80 * time.Millisecond) // > grace period: a replay would fire
	if got := ciDispatchCount(ci); got != 1 {
		t.Fatalf("duplicate caused %d dispatches", got)
	}
	// A NEW delivery id processes normally.
	headers["X-GitHub-Delivery"] = "delivery-2"
	postWebhook(t, env, "github", body, headers)
	waitFor(t, "second dispatch", func() bool { return ciDispatchCount(ci) == 2 })
}

func ciDispatchCount(ci *ciRecorder) int {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	return ci.dispatches
}
