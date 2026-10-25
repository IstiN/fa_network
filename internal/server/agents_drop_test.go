package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/hub"
)

// seedDropAgent puts a hub agent into the roster of a test network.
func seedDropAgent(t *testing.T, env *testEnv) {
	t.Helper()
	env.hub.SetPresence([]hub.PresenceInfo{{AgentID: "a1", Name: "public-agent", Online: true}})
	env.hub.SetOnline(false)
	env.hub.SetOnline(true)
	waitForCondition(t, "seed", func() bool { return env.srv.relay.hubAgentName("a1") == "public-agent" })
}

// Drop hides the hub agent ONLY in the dropping network: snapshots,
// /agents, reseeds and restarts respect the per-network tombstone; other
// networks keep seeing the agent; unowned agents are never hub-evicted.
func TestDropAgentPerNetwork(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, guestSess, _, networkID := setupNetwork(t, env)
	seedDropAgent(t, env)

	browser := dialWS(t, env, guestSess)
	if _, ok := snapshotRoster(t, browser.next("roster.snapshot"))["a1"]; !ok {
		t.Fatal("a1 must be in the initial snapshot")
	}
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/a1", nil, guestSess); rec.Code != http.StatusForbidden {
		t.Fatalf("guest drop status = %d, want 403", rec.Code)
	}
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/a1", nil, ownerSess); rec.Code != http.StatusNoContent {
		t.Fatalf("owner drop status = %d body %s", rec.Code, rec.Body.String())
	}
	// Unowned agent (not enrolled by this network): no global eviction.
	if got := env.hub.Evicted(); len(got) != 0 {
		t.Fatalf("unowned agent must not be hub-evicted: %v", got)
	}
	if _, ok := snapshotRoster(t, browser.next("roster.snapshot"))["a1"]; ok {
		t.Fatal("a1 must be gone from the post-drop snapshot")
	}
	rec := env.do("GET", "/api/networks/"+networkID+"/agents", nil, ownerSess)
	var agents []map[string]any
	decodeBody(t, rec, &agents)
	for _, a := range agents {
		if a["agentId"] == "a1" {
			t.Fatalf("a1 still in /agents: %v", agents)
		}
	}
	// Reseed must not resurrect the agent in this network's roster (the
	// global presence cache keeps it for other networks).
	if !env.srv.relay.seedHubPresenceOnce(context.Background()) {
		t.Fatal("reseed failed")
	}
	if got := env.srv.relay.hubAgentMembers(networkID, nil); len(got) != 0 {
		t.Fatalf("dropped agent resurrected in network roster: %+v", got)
	}
	if got := env.srv.relay.hubPresence(); len(got) != 1 {
		t.Fatalf("global presence cache should keep the agent for other networks: %+v", got)
	}
	// Idempotent re-drop: 204, still no eviction.
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/a1", nil, ownerSess); rec.Code != http.StatusNoContent {
		t.Fatalf("second drop status = %d", rec.Code)
	}
	if got := env.hub.Evicted(); len(got) != 0 {
		t.Fatalf("re-drop caused side effects: %v", got)
	}
	// Presence flaps of the dropped agent produce no presence.changed in
	// this network; a different agent's presence still flows.
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a1", Name: "public-agent", Online: false})
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a2", Name: "other-agent", Online: true})
	frame := browser.next("presence.changed")
	raw, _ := json.Marshal(frame.Payload)
	if string(raw) == "" || !strings.Contains(string(raw), "a2") {
		t.Fatalf("expected a2 presence frame, got %s", raw)
	}
}

// A manager of network B must not hide agents in network A's roster.
func TestDropAgentDoesNotAffectOtherNetworks(t *testing.T) {
	env := newTestEnv(t)
	ownerJWT := env.authedToken("owner1", "Owner One")
	netA := env.createNetwork(t, ownerJWT, "net-a", "secret123")
	sessA, _ := env.join(t, netA, "secret123", "", ownerJWT)
	netB := env.createNetwork(t, ownerJWT, "net-b", "secret123")
	seedDropAgent(t, env)
	if rec := env.do("DELETE", "/api/networks/"+netB+"/agents/a1", nil, sessA); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign session in network B = %d, want 403", rec.Code)
	}
	rec := env.do("DELETE", "/api/networks/"+netB+"/agents/a1", nil, ownerJWT)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("drop in own network B = %d %s", rec.Code, rec.Body.String())
	}
	if got := env.srv.relay.hubAgentMembers(netB, nil); len(got) != 0 {
		t.Fatalf("a1 must be gone from B: %+v", got)
	}
	if got := env.srv.relay.hubAgentMembers(netA, nil); len(got) != 1 {
		t.Fatalf("a1 must stay in A: %+v", got)
	}
}

// Unknown agents are a 404 no-op: no tombstones, eviction or broadcasts.
func TestDropUnknownAgent(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, _, _, networkID := setupNetwork(t, env)
	rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/nope", nil, ownerSess)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown drop = %d, want 404", rec.Code)
	}
	if got := env.hub.Evicted(); len(got) != 0 {
		t.Fatalf("evictions = %v", got)
	}
	drops, err := env.st.DroppedAgents(context.Background())
	if err != nil || len(drops) != 0 {
		t.Fatalf("no tombstones expected: %+v %v", drops, err)
	}
}

// Agents ENROLLED BY the dropping network are evicted from the hub too.
func TestDropOwnedAgentEvictsHub(t *testing.T) {
	env := newTestEnv(t)
	jwt, ownerSess, _, _, networkID := setupNetwork(t, env)
	rec := env.do("POST", "/api/networks/"+networkID+"/agents/enroll",
		map[string]string{"name": "public-agent"}, jwt)
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	seedDropAgent(t, env)
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/a1", nil, ownerSess); rec.Code != http.StatusNoContent {
		t.Fatalf("drop owned: %d %s", rec.Code, rec.Body.String())
	}
	if got := env.hub.Evicted(); len(got) != 1 || got[0] != "a1" {
		t.Fatalf("owned agent must be hub-evicted: %v", got)
	}
}

// Dropped agents survive relay restarts in the dropping network only.
func TestDropAgentPersistsAcrossRestart(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, _, _, networkID := setupNetwork(t, env)
	seedDropAgent(t, env)
	if rec := env.do("DELETE", "/api/networks/"+networkID+"/agents/a1", nil, ownerSess); rec.Code != http.StatusNoContent {
		t.Fatalf("drop: %d", rec.Code)
	}
	restarted := NewRelay(env.st, env.hub, env.srv.sessions, nil, time.Now)
	restarted.loadDropped(context.Background())
	if !env.srv.relay.isDropped(networkID, "a1") {
		t.Fatal("in-memory drop missing")
	}
	if got := restarted.hubAgentMembers(networkID, nil); len(got) != 0 {
		t.Fatalf("restart resurrected dropped agent: %+v", got)
	}
}
