package server

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// A channel created via REST must be joined/created on the hub right
// away — enrolled agents must not hit access_denied ("channel creation
// requires the master secret") because the channel existed only in the
// fa_network store between relay reconnects.
func TestCreateChannelEnsuresHubJoin(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, _, _, networkID := setupNetwork(t, env)
	rec := env.do("POST", "/api/networks/"+networkID+"/channels", map[string]string{"name": "private-ops"}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var channel map[string]any
	decodeBody(t, rec, &channel)
	id, _ := channel["id"].(string)
	for _, joined := range env.hub.Joined() {
		if joined == id {
			return
		}
	}
	t.Fatalf("hub join missing for new channel %s (joined=%v)", id, env.hub.Joined())
}

// Kick removes a store guest, revokes their credentials, disconnects
// their socket and pushes a fresh roster to the remaining members.
func TestKickMember(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, guestSess, _, networkID := setupNetwork(t, env)
	victimSess, victimJoin := env.join(t, networkID, "secret123", "fa-probe", "")
	victimID := victimJoin["identity"].(map[string]any)["id"].(string)

	watcher := dialWS(t, env, guestSess)
	watcher.next("roster.snapshot")
	victim := dialWS(t, env, victimSess)
	victim.next("roster.snapshot")

	// Guests cannot kick; owner/admin rows are protected.
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/members/"+victimID, nil, guestSess); rec.Code != http.StatusForbidden {
		t.Fatalf("guest kick status = %d, want 403", rec.Code)
	}
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/members/owner1", nil, ownerSess); rec.Code != http.StatusForbidden {
		t.Fatalf("owner kick status = %d, want 403", rec.Code)
	}

	if rec := env.do("DELETE", "/api/networks/"+networkID+"/members/"+victimID, nil, ownerSess); rec.Code != http.StatusNoContent {
		t.Fatalf("kick status = %d body %s", rec.Code, rec.Body.String())
	}

	// The kicked socket dies promptly (deadline read, no sleep-sync).
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2*time.Second))
	defer cancel()
	if _, _, err := victim.conn.Read(ctx); err == nil {
		t.Fatal("kicked socket still readable")
	}

	// Remaining sockets get a roster without the kicked member.
	if _, ok := snapshotRoster(t, watcher.next("roster.snapshot"))[victimID]; ok {
		t.Fatal("kicked member still in roster.snapshot")
	}
	// Their token is useless immediately (member row is gone).
	if rec := env.do("GET", "/api/networks/"+networkID+"/members", nil, victimSess); rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
		t.Fatalf("kicked token status = %d, want 401/403", rec.Code)
	}
	// Idempotent re-kick.
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/members/"+victimID, nil, ownerSess); rec.Code != http.StatusNoContent {
		t.Fatalf("re-kick status = %d, want 204", rec.Code)
	}
}
