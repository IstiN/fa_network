package server

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/wakeup"
)

// Drop removes a hub agent from every roster view, survives reseeds and
// relay restarts, and never re-broadcasts the agent's presence.
func TestDropAgent(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, guestSess, _, networkID := setupNetwork(t, env)
	env.hub.SetPresence([]hub.PresenceInfo{{AgentID: "a1", Name: "public-agent", Online: true}})
	env.hub.SetOnline(false)
	env.hub.SetOnline(true)
	waitForCondition(t, "seed", func() bool { return env.srv.relay.hubAgentName("a1") == "public-agent" })

	browser := dialWS(t, env, guestSess)
	if _, ok := snapshotRoster(t, browser.next("roster.snapshot"))["a1"]; !ok {
		t.Fatal("a1 must be in the initial snapshot")
	}

	// Guests cannot manage agents.
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/a1", nil, guestSess); rec.Code != http.StatusForbidden {
		t.Fatalf("guest drop status = %d, want 403", rec.Code)
	}
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/a1", nil, ownerSess); rec.Code != http.StatusNoContent {
		t.Fatalf("owner drop status = %d body %s", rec.Code, rec.Body.String())
	}
	if got := env.hub.Evicted(); len(got) != 1 || got[0] != "a1" {
		t.Fatalf("hub evictions = %v", got)
	}

	// A fresh roster.snapshot without a1 is pushed to connected sockets.
	if _, ok := snapshotRoster(t, browser.next("roster.snapshot"))["a1"]; ok {
		t.Fatal("a1 must be gone from the post-drop snapshot")
	}
	// /agents excludes the dropped agent too.
	rec := env.do("GET", "/api/networks/"+networkID+"/agents", nil, ownerSess)
	var agents []map[string]any
	decodeBody(t, rec, &agents)
	for _, a := range agents {
		if a["agentId"] == "a1" {
			t.Fatalf("a1 still in /agents: %v", agents)
		}
	}

	// Reseed and presence events must not resurrect the tombstoned agent.
	if !env.srv.relay.seedHubPresenceOnce(context.Background()) {
		t.Fatal("reseed failed")
	}
	if got := env.srv.relay.hubPresence(); len(got) != 0 {
		t.Fatalf("dropped agent resurrected by reseed: %+v", got)
	}
	env.srv.relay.updateHubAgent(context.Background(), hub.Event{Kind: hub.EventPresence, AgentID: "a1", Name: "public-agent", Online: true})
	browser.send(map[string]any{"type": "ping"})
	if frame := browser.next("presence.changed", "pong"); frame.Type != "pong" {
		t.Fatalf("dropped agent produced presence.changed: %+v", frame)
	}

	// A fresh relay over the SAME store (restart) keeps the exclusion.
	restarted := NewRelay(env.st, env.hub, NewSessionRegistry(), wakeup.NewDispatcher(wakeup.Options{Store: env.st}), time.Now)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go restarted.Run(ctx)
	waitForCondition(t, "tombstones reloaded", func() bool {
		restarted.mu.Lock()
		defer restarted.mu.Unlock()
		return restarted.dropped["a1"]
	})
	if !restarted.seedHubPresenceOnce(context.Background()) {
		t.Fatal("restart reseed failed")
	}
	if members := restarted.hubAgentMembers(networkID, nil); len(members) != 0 {
		t.Fatalf("restart resurrected agents: %+v", members)
	}
}

// Hub eviction failure never blocks the roster tombstone (204 anyway).
func TestDropAgentEvictFailureStill204(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, _, _, networkID := setupNetwork(t, env)
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a2", Name: "kb-agent", Online: true})
	waitForCondition(t, "presence", func() bool { return env.srv.relay.hubAgentName("a2") == "kb-agent" })
	env.hub.SetEvictError(errors.New("hub admin unreachable"))
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/a2", nil, ownerSess); rec.Code != http.StatusNoContent {
		t.Fatalf("drop with failing evict = %d, want 204", rec.Code)
	}
	if !env.srv.relay.seedHubPresenceOnce(context.Background()) {
		t.Fatal("reseed failed")
	}
	for _, info := range env.srv.relay.hubPresence() {
		if info.AgentID == "a2" {
			t.Fatal("a2 must stay dropped despite evict failure")
		}
	}
	// Unknown agents are idempotent too.
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/never-seen", nil, ownerSess); rec.Code != http.StatusNoContent {
		t.Fatalf("unknown agent drop = %d, want 204", rec.Code)
	}
}
