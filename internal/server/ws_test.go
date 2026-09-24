package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
)

// waitSubscribed blocks until the subscribe frame is processed: a ping →
// pong round-trip proves the read pump consumed everything before it
// (frames are processed in order).
func waitSubscribed(t *testing.T, browser *wsClient, channelID string) {
	t.Helper()
	browser.send(map[string]any{"type": "ping"})
	if frame := browser.next("pong"); frame.Type != "pong" {
		t.Fatal("subscribe not processed before pong")
	}
}

// httptestNewServer runs a webhook capture endpoint.
func httptestNewServer(t *testing.T, onCall func(body []byte)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		onCall(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// wsClient is a test browser socket.
type wsClient struct {
	t    *testing.T
	conn *websocket.Conn
}

func dialWS(t *testing.T, env *testEnv, token string) *wsClient {
	t.Helper()
	url := "ws" + strings.TrimPrefix(env.http.URL, "http") + "/ws"
	conn, _, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{
		HTTPHeader: map[string][]string{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return &wsClient{t: t, conn: conn}
}

// next returns the next event frame of one of the given types (deadline 2s).
func (c *wsClient) next(types ...string) wsFrame {
	c.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		_, raw, err := c.conn.Read(ctx)
		cancel()
		if err != nil {
			c.t.Fatalf("ws read: %v", err)
		}
		var frame wsFrame
		if err := json.Unmarshal(raw, &frame); err != nil {
			continue
		}
		for _, want := range types {
			if frame.Type == want {
				return frame
			}
		}
	}
	c.t.Fatalf("no frame of types %v within 2s", types)
	return wsFrame{}
}

func (c *wsClient) send(v any) {
	c.t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		c.t.Fatalf("marshal: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.conn.Write(ctx, websocket.MessageText, raw); err != nil {
		c.t.Fatalf("ws write: %v", err)
	}
}

// setupNetwork creates a network with one channel and returns the pieces.
func setupNetwork(t *testing.T, env *testEnv) (ownerToken, ownerSess, guestSess, channelID, networkID string) {
	t.Helper()
	ownerToken = env.authedToken("owner1", "Owner One")
	networkID = env.createNetwork(t, ownerToken, "fa-team", "secret123")
	ownerSess, _ = env.join(t, networkID, "secret123", "", ownerToken)
	guestSess, _ = env.join(t, networkID, "secret123", "watcher", "")
	rec := env.do("POST", "/api/networks/"+networkID+"/channels", map[string]string{"name": "general"}, ownerSess)
	var channel map[string]any
	decodeBody(t, rec, &channel)
	channelID, _ = channel["id"].(string)
	return
}

// AC-B9: an envelope sent from one session is received by a watcher on
// another socket through the same channel within 2s (and vice versa).
func TestCrossSessionRoundtripACB9(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, guestSess, channelID, _ := setupNetwork(t, env)

	browser := dialWS(t, env, guestSess)
	browser.next("roster.snapshot")
	browser.send(map[string]any{"type": "subscribe", "channelId": channelID})
	waitSubscribed(t, browser, channelID)

	// Mobile-ish session sends via REST; browser receives via WS.
	rec := env.do("POST", "/api/channels/"+channelID+"/messages",
		map[string]string{"id": "rt-1", "payload": "bW9iaWxlLWNpcGhlcg=="}, ownerSess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: %d", rec.Code)
	}
	frame := browser.next("envelope")
	raw, _ := json.Marshal(frame.Payload)
	var env2 model.EnvelopeWire
	if err := json.Unmarshal(raw, &env2); err != nil {
		t.Fatalf("envelope wire: %v", err)
	}
	if env2.ID != "rt-1" || env2.Payload != "bW9iaWxlLWNpcGhlcg==" {
		t.Fatalf("envelope = %+v", env2)
	}

	// Browser sends via WS; the REST history sees it (sender echo fanned
	// out to subscribers). Wait for the echo before reading history.
	browser.send(map[string]any{
		"type": "envelope.send", "channelId": channelID,
		"id": "rt-2", "payload": "YnJvd3Nlci1jaXBoZXI=",
	})
	echo := browser.next("envelope")
	raw2, _ := json.Marshal(echo.Payload)
	var echoWire model.EnvelopeWire
	_ = json.Unmarshal(raw2, &echoWire)
	if echoWire.ID != "rt-2" {
		t.Fatalf("echo = %+v", echoWire)
	}
	rec = env.do("GET", "/api/channels/"+channelID+"/messages?limit=10", nil, ownerSess)
	var page struct {
		Items []model.EnvelopeWire `json:"items"`
	}
	decodeBody(t, rec, &page)
	if len(page.Items) != 2 {
		t.Fatalf("history = %d items", len(page.Items))
	}
}

// Hub-originated envelopes reach subscribed sockets exactly once (dedup).
func TestHubInboundFanoutDedup(t *testing.T) {
	env := newTestEnv(t)
	_, _, guestSess, channelID, _ := setupNetwork(t, env)

	browser := dialWS(t, env, guestSess)
	browser.next("roster.snapshot")
	browser.send(map[string]any{"type": "subscribe", "channelId": channelID})
	waitSubscribed(t, browser, channelID)

	env.hub.EmitMsg(hubEnvelope(channelID, "hub-1", "aHViLWNpcGhlcg=="))
	frame := browser.next("envelope")
	raw, _ := json.Marshal(frame.Payload)
	var wire model.EnvelopeWire
	_ = json.Unmarshal(raw, &wire)
	if wire.ID != "hub-1" {
		t.Fatalf("wire = %+v", wire)
	}

	// Duplicate delivery (at-least-once retry) must fan out once: the
	// store dedups, the fan-out rides the stored flag.
	env.hub.EmitMsg(hubEnvelope(channelID, "hub-1", "aHViLWNpcGhlcg=="))
	deadline := time.Now().Add(300 * time.Millisecond)
	conn := browser.conn
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		_, _, err := conn.Read(ctx)
		cancel()
		if err != nil {
			break
		}
		t.Fatal("duplicate envelope fanned out")
	}
}

func hubEnvelope(channelID, id, payload string) hub.Envelope {
	return hub.Envelope{ChannelID: channelID, ID: id, Payload: payload, CreatedAt: time.Now()}
}

// AC-B7: hub down → network.offline + queueing; reconnect → drain once,
// in order, with id-dedup (no loss, no dupes).
func TestOfflineQueueDrainACB7(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, guestSess, channelID, _ := setupNetwork(t, env)

	browser := dialWS(t, env, guestSess)
	browser.next("roster.snapshot")
	browser.send(map[string]any{"type": "subscribe", "channelId": channelID})

	env.hub.SetOnline(false)
	browser.next("network.offline")

	// Sends while offline queue up (persisted + ordered).
	for _, id := range []string{"q-1", "q-2", "q-3"} {
		rec := env.do("POST", "/api/channels/"+channelID+"/messages",
			map[string]string{"id": id, "payload": "cXVldWVkLWNpcGhlcg=="}, ownerSess)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("queued send %s: %d", id, rec.Code)
		}
	}
	// Id-dedup at the store: same id retried → still one copy.
	rec := env.do("POST", "/api/channels/"+channelID+"/messages",
		map[string]string{"id": "q-2", "payload": "cWM="}, ownerSess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("retry send: %d", rec.Code)
	}
	if got := len(env.hub.Sent(channelID)); got != 0 {
		t.Fatalf("hub offline but received %d", got)
	}

	env.hub.SetOnline(true)
	drain := browser.next("network.drain")
	raw, _ := json.Marshal(drain.Payload)
	var payload struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(raw, &payload)

	sent := env.hub.Sent(channelID)
	if len(sent) != 3 {
		t.Fatalf("drained %d, want 3 (count frame said %d)", len(sent), payload.Count)
	}
	for i, want := range []string{"q-1", "q-2", "q-3"} {
		if sent[i].ID != want {
			t.Fatalf("order[%d] = %s, want %s", i, sent[i].ID, want)
		}
	}
}

// Presence flows over WS: connect → live, disconnect → offline (E7).
func TestPresenceOverWS(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, guestSess, _, _ := setupNetwork(t, env)

	ownerWS := dialWS(t, env, ownerSess)
	ownerWS.next("roster.snapshot")

	guestWS := dialWS(t, env, guestSess)
	guestWS.next("roster.snapshot")

	frame := ownerWS.next("presence.changed")
	raw, _ := json.Marshal(frame.Payload)
	var change struct {
		MemberID string `json:"memberId"`
		Presence string `json:"presence"`
	}
	_ = json.Unmarshal(raw, &change)
	if change.Presence != model.PresenceLive {
		t.Fatalf("presence = %+v", change)
	}

	guestWS.conn.Close(websocket.StatusNormalClosure, "bye")
	frame = ownerWS.next("presence.changed")
	raw, _ = json.Marshal(frame.Payload)
	_ = json.Unmarshal(raw, &change)
	if change.Presence != model.PresenceOffline {
		t.Fatalf("after disconnect = %+v", change)
	}
}

// AC-B6 through the API: a mention of an offline agent with a registered
// webhook fires exactly one identity-only dispatch.
func TestWakeupMentionACB6(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, guestSess, channelID, networkID := setupNetwork(t, env)

	var calls int
	webhook := httptestNewServer(t, func(body []byte) { calls++ })

	// A guest joins; its member id is what mentions address.
	agentSess, joinOut := env.join(t, networkID, "secret123", "guest-agent", "")
	_ = agentSess
	agentIdentity, _ := joinOut["identity"].(map[string]any)
	agentID, _ := agentIdentity["id"].(string)

	// Owner registers a wake-up for the offline guest agent.
	rec := env.do("POST", "/api/networks/"+networkID+"/agents/"+agentID+"/wakeups",
		map[string]any{"url": webhook, "secret": "s3cret", "debounceSeconds": 30}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	// The secret never comes back.
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatal("registration leaked the secret")
	}
	rec = env.do("GET", "/api/networks/"+networkID+"/agents/"+agentID+"/wakeups", nil, ownerSess)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("get registration: %d %s", rec.Code, rec.Body.String())
	}
	// Guests cannot register (management route).
	rec = env.do("POST", "/api/networks/"+networkID+"/agents/"+agentID+"/wakeups",
		map[string]any{"url": webhook}, guestSess)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("guest register: %d", rec.Code)
	}

	// Mention the offline agent → dispatch fires (agent has no live WS).
	rec = env.do("POST", "/api/channels/"+channelID+"/messages", map[string]any{
		"id": "tag-1", "payload": "Y2lwaGVy", "mentions": []string{agentID},
	}, ownerSess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("mention send: %d", rec.Code)
	}
	if calls != 1 {
		t.Fatalf("webhook calls = %d, want 1", calls)
	}

	// Dispatch log holds the audit entry (owner observable).
	rec = env.do("GET", "/api/networks/"+networkID+"/wakeups/log", nil, ownerSess)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "delivered") {
		t.Fatalf("log: %d %s", rec.Code, rec.Body.String())
	}
}
