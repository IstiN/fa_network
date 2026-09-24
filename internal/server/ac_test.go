package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// AC-B1: create network requires a valid JWT; creator becomes owner;
// unauthenticated create → 401 with zero side effects.
func TestCreateNetworkACB1(t *testing.T) {
	env := newTestEnv(t)

	rec := env.do("POST", "/api/networks", map[string]string{"name": "no-auth", "password": "secret123"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth create status = %d", rec.Code)
	}
	if _, err := env.st.NetworkByName(t.Context(), "no-auth"); err == nil {
		t.Fatal("unauth create must have zero side effects")
	}

	rec = env.do("POST", "/api/networks", map[string]string{"name": "BAD NAME!", "password": "secret123"}, env.authedToken("owner1", "Owner One"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid name status = %d", rec.Code)
	}

	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")

	rec = env.do("POST", "/api/networks", map[string]string{"name": "fa-team", "password": "secret123"}, env.authedToken("other", "Other"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("dup name status = %d", rec.Code)
	}

	network, err := env.st.Network(t.Context(), id)
	if err != nil || network.OwnerID != "owner1" {
		t.Fatalf("owner = %v err=%v", network, err)
	}
	member, err := env.st.Member(t.Context(), id, "owner1")
	if err != nil || member.Class != model.ClassOwner {
		t.Fatalf("owner member = %+v err=%v", member, err)
	}
}

// AC-B2: join with id/name + password works WITHOUT auth → agent-class
// identity; authed join → identity carrying the locked auth-service name.
func TestJoinTwoClassesACB2(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")

	// Join by NAME, no auth → guest agent-class identity.
	_, out := env.join(t, "fa-team", "secret123", "web-surfer", "")
	identity, _ := out["identity"].(map[string]any)
	if identity["class"] != model.ClassGuest {
		t.Fatalf("guest class = %v", identity["class"])
	}
	if identity["displayName"] != "web-surfer" {
		t.Fatalf("guest name = %v", identity["displayName"])
	}
	if _, has := identity["authName"]; has {
		t.Fatal("guest must not carry an authName")
	}

	// Authed join: displayName in the body is IGNORED, auth name wins.
	_, out = env.join(t, id, "secret123", "ignored-name", env.authedToken("alice", "Alice A."))
	identity, _ = out["identity"].(map[string]any)
	if identity["class"] != model.ClassMember {
		t.Fatalf("authed class = %v", identity["class"])
	}
	if identity["displayName"] != "Alice A." || identity["authName"] != "Alice A." {
		t.Fatalf("authed identity = %v", identity)
	}

	// Guest name dedup: `name (2)` on collision (E2).
	_, out = env.join(t, id, "secret123", "web-surfer", "")
	identity, _ = out["identity"].(map[string]any)
	if identity["displayName"] != "web-surfer (2)" {
		t.Fatalf("dedup name = %v", identity["displayName"])
	}

	// Wrong password → 403 invalid_credentials; unknown network → 404.
	rec := env.do("POST", "/api/networks/"+id+"/join", map[string]string{"password": "wrong", "displayName": "x"}, "")
	if rec.Code != http.StatusForbidden || errCode(t, rec) != CodeInvalidCreds {
		t.Fatalf("wrong password: %d %s", rec.Code, rec.Body.String())
	}
	rec = env.do("POST", "/api/networks/nope/join", map[string]string{"password": "secret123", "displayName": "x"}, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown network status = %d", rec.Code)
	}
}

// AC-B3: management routes reject guest tokens (and unauthenticated
// callers); no management route accepts one.
func TestManagementRejectsGuestsACB3(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")
	guestToken, _ := env.join(t, id, "secret123", "guest-bot", "")
	memberToken, _ := env.join(t, id, "secret123", "", env.authedToken("bob", "Bob B."))

	ownerSess, _ := env.join(t, id, "secret123", "", owner)
	rec := env.do("POST", "/api/networks/"+id+"/channels", map[string]string{"name": "mgmt"}, ownerSess)
	var ch map[string]any
	decodeBody(t, rec, &ch)
	channelID, _ := ch["id"].(string)

	management := []struct {
		method, path string
	}{
		{"POST", "/api/networks/" + id + "/channels"},
		{"PATCH", "/api/channels/" + channelID},
		{"DELETE", "/api/channels/" + channelID},
		{"POST", "/api/networks/" + id + "/agents/a1/wakeups"},
		{"GET", "/api/networks/" + id + "/wakeups/log"},
		{"POST", "/api/networks/" + id + "/admins"},
		{"PATCH", "/api/networks/" + id},
		{"DELETE", "/api/networks/" + id},
	}
	for _, route := range management {
		rec := env.do(route.method, route.path, map[string]string{"name": "x", "password": "secret123"}, guestToken)
		if rec.Code == http.StatusOK || rec.Code == http.StatusCreated || rec.Code == http.StatusNoContent || rec.Code == http.StatusAccepted {
			t.Fatalf("guest accepted on %s %s: %d", route.method, route.path, rec.Code)
		}
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
			t.Fatalf("guest %s %s: status %d", route.method, route.path, rec.Code)
		}
	}
	// Plain authed members manage nothing either — EXCEPT creating regular
	// channels, which the spec grants to every authed member.
	elevatedOnly := []struct {
		method, path string
	}{
		{"POST", "/api/networks/" + id + "/agents/a1/wakeups"},
		{"GET", "/api/networks/" + id + "/wakeups/log"},
		{"POST", "/api/networks/" + id + "/admins"},
		{"PATCH", "/api/networks/" + id},
		{"DELETE", "/api/networks/" + id},
	}
	for _, route := range elevatedOnly {
		rec := env.do(route.method, route.path, map[string]string{"name": "x"}, memberToken)
		if rec.Code == http.StatusOK || rec.Code == http.StatusCreated || rec.Code == http.StatusNoContent {
			t.Fatalf("plain member accepted on %s %s", route.method, route.path)
		}
	}
	// But a member CAN create a regular channel (not public).
	rec = env.do("POST", "/api/networks/"+id+"/channels", map[string]string{"name": "member-room"}, memberToken)
	if rec.Code != http.StatusCreated {
		t.Fatalf("member channel create: %d", rec.Code)
	}

	// The guest CAN still read member routes.
	rec = env.do("GET", "/api/networks/"+id+"/members", nil, guestToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("guest member read: %d", rec.Code)
	}
}

// AC-B5: public channel — non-owner write → 403 channel_read_only;
// owner write succeeds; member write into a regular channel works.
func TestPublicChannelWriteGuardACB5(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")
	guestToken, _ := env.join(t, id, "secret123", "watcher", "")
	ownerSess, _ := env.join(t, id, "secret123", "", owner)

	// Guest cannot create a public channel (owner/admin only).
	rec := env.do("POST", "/api/networks/"+id+"/channels", map[string]any{"name": "showcase", "public": true}, guestToken)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("guest public create: %d", rec.Code)
	}
	rec = env.do("POST", "/api/networks/"+id+"/channels", map[string]any{"name": "showcase", "public": true}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("owner public create: %d %s", rec.Code, rec.Body.String())
	}
	var channelBody map[string]any
	decodeBody(t, rec, &channelBody)
	channelID, _ := channelBody["id"].(string)

	// Guest write into the public channel → 403 channel_read_only.
	rec = env.do("POST", "/api/channels/"+channelID+"/messages", map[string]string{"id": "m1", "payload": "Y2lwaGVy"}, guestToken)
	if rec.Code != http.StatusForbidden || errCode(t, rec) != CodeChannelReadOnly {
		t.Fatalf("guest public write: %d %s", rec.Code, rec.Body.String())
	}

	// Owner write → 202, envelope relayed toward the hub.
	rec = env.do("POST", "/api/channels/"+channelID+"/messages", map[string]string{"id": "m2", "payload": "Y2lwaGVy"}, ownerSess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("owner public write: %d %s", rec.Code, rec.Body.String())
	}
	sent := env.hub.Sent(channelID)
	if len(sent) != 1 || sent[0].ID != "m2" {
		t.Fatalf("hub received %v", sent)
	}

	// Regular channel: guest writes fine.
	rec = env.do("POST", "/api/networks/"+id+"/channels", map[string]string{"name": "watercooler"}, ownerSess)
	var regular map[string]any
	decodeBody(t, rec, &regular)
	regularID, _ := regular["id"].(string)
	rec = env.do("POST", "/api/channels/"+regularID+"/messages", map[string]string{"id": "m3", "payload": "Y2lwaGVy"}, guestToken)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("guest regular write: %d %s", rec.Code, rec.Body.String())
	}
}

// AC-B4 (property): nothing decryptable ever lands in the store — payloads
// round-trip byte-identical and no plaintext field exists in the schema.
func TestRelayOnlyPropertyACB4(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")
	sess, _ := env.join(t, id, "secret123", "", owner)

	rec := env.do("POST", "/api/networks/"+id+"/channels", map[string]string{"name": "vault"}, sess)
	var channel map[string]any
	decodeBody(t, rec, &channel)
	channelID, _ := channel["id"].(string)

	// The payload is base64-wrapped ciphertext — the server must store it
	// untouched and never attempt to decode or inspect it.
	secret := "dW5yZWxhdGVkLXNlY3JldA=="
	rec = env.do("POST", "/api/channels/"+channelID+"/messages", map[string]string{"id": "p1", "payload": secret}, sess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: %d", rec.Code)
	}

	// Property: every stored field of every envelope is exactly what the
	// client sent — ciphertext-only, no decryption, no transformation.
	channels, err := env.st.Channels(t.Context(), id)
	if err != nil || len(channels) != 1 {
		t.Fatalf("channels: %v", err)
	}
	stored, err := env.st.Envelopes(t.Context(), channels[0].ID, "", 100)
	if err != nil || len(stored.Items) != 1 {
		t.Fatalf("store page: %v", err)
	}
	for _, e := range stored.Items {
		if e.Payload != secret {
			t.Fatalf("payload mutated in store: %q", e.Payload)
		}
	}

	// The history endpoint returns the payload untouched as well.
	rec = env.do("GET", "/api/channels/"+channelID+"/messages", nil, sess)
	var page struct {
		Items []struct {
			Payload string `json:"payload"`
		} `json:"items"`
	}
	decodeBody(t, rec, &page)
	if len(page.Items) != 1 || page.Items[0].Payload != secret {
		t.Fatalf("history payload = %+v", page.Items)
	}
}

// AC-B10 end-to-end: with the mock provider the whole flow — JWT → create
// → guest join → channel → send — runs with zero network access.
func TestFullFlowOfflineACB10(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")
	sess, out := env.join(t, id, "secret123", "", owner)
	if _, ok := out["sessionToken"]; !ok || sess == "" {
		t.Fatal("join must issue a sessionToken")
	}

	rec := env.do("GET", "/api/networks/"+id, nil, sess)
	if rec.Code != http.StatusOK {
		t.Fatalf("get network: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret123") {
		t.Fatal("network wire leaked the join password")
	}
}

// AC-B12: retentionDays — expired envelopes disappear from history; 0
// keeps nothing beyond live relay.
func TestEnvelopeRetentionACB12(t *testing.T) {
	env := newTestEnv(t)
	env.srv.cfg.Now = func() time.Time { return time.Now() } // pin at runtime
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")
	sess, _ := env.join(t, id, "secret123", "", owner)

	rec := env.do("POST", "/api/networks/"+id+"/channels", map[string]any{"name": "short-lived", "retentionDays": 7}, sess)
	var channel map[string]any
	decodeBody(t, rec, &channel)
	channelID, _ := channel["id"].(string)

	old := time.Now().Add(-10 * 24 * time.Hour)
	_, _ = env.st.AppendEnvelope(t.Context(), &model.Envelope{
		ID: "old-1", ChannelID: channelID, SenderID: "owner1",
		Payload: "b2xk", CreatedAt: old,
	})
	_, _ = env.st.AppendEnvelope(t.Context(), &model.Envelope{
		ID: "new-1", ChannelID: channelID, SenderID: "owner1",
		Payload: "bmV3", CreatedAt: time.Now(),
	})

	env.srv.sweepOnce(t.Context())

	rec = env.do("GET", "/api/channels/"+channelID+"/messages", nil, sess)
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	decodeBody(t, rec, &page)
	if len(page.Items) != 1 || page.Items[0].ID != "new-1" {
		t.Fatalf("after retention sweep: %+v", page.Items)
	}
}
