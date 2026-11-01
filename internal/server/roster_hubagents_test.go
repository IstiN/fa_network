package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
)

func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// Issue #4: DAP agents already online before the app connects must be in
// the greeting roster.snapshot, and their later transitions must carry
// displayName/class so the app can count and render them.
func TestHubAgentsInRosterSnapshot(t *testing.T) {
	env := newTestEnv(t)
	_, _, guestSess, _, networkID := setupNetwork(t, env)
	if err := env.st.ClaimAgentOwner(context.Background(), networkID, "cli-agent"); err != nil {
		t.Fatalf("claim owner: %v", err)
	}
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a1", Name: "cli-agent", Online: true})
	waitForCondition(t, "hub agent cached", func() bool {
		return env.srv.relay.hubAgentName("a1") == "cli-agent"
	})

	ws := dialWS(t, env, guestSess)
	frame := ws.next("roster.snapshot")
	raw, _ := json.Marshal(frame.Payload)
	var snapshot struct {
		Members []model.MemberWire `json:"members"`
	}
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	var agent *model.MemberWire
	for i, m := range snapshot.Members {
		if m.ID == "a1" {
			agent = &snapshot.Members[i]
		}
	}
	if agent == nil {
		t.Fatalf("hub agent missing from roster.snapshot: %+v", snapshot.Members)
	}
	if agent.Class != model.ClassAgent || agent.Presence != model.PresenceLive || agent.DisplayName != "cli-agent" {
		t.Fatalf("hub agent wire = %+v", agent)
	}

	// Transition: offline with additive identity fields.
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a1", Online: false})
	frame = ws.next("presence.changed")
	raw, _ = json.Marshal(frame.Payload)
	var change struct {
		MemberID    string `json:"memberId"`
		Presence    string `json:"presence"`
		DisplayName string `json:"displayName"`
		Class       string `json:"class"`
	}
	if err := json.Unmarshal(raw, &change); err != nil {
		t.Fatalf("presence.changed: %v", err)
	}
	if change.MemberID != "a1" || change.Presence != model.PresenceOffline {
		t.Fatalf("change = %+v", change)
	}
	if change.DisplayName != "cli-agent" || change.Class != model.ClassAgent {
		t.Fatalf("additive identity missing: %+v", change)
	}
}

// hubAgentMembers unit contract: dedup against store members, name
// fallback to the agent id, offline presence, deterministic order.
func TestHubAgentMembersProjection(t *testing.T) {
	env := newTestEnv(t)
	r := env.srv.relay
	r.hubAgents["a-dup"] = hub.PresenceInfo{AgentID: "a-dup", Name: "member", Online: true}
	r.hubAgents["a-noname"] = hub.PresenceInfo{AgentID: "a-noname", Online: false}
	r.hubAgents["a-online"] = hub.PresenceInfo{AgentID: "a-online", Name: "zeta", Online: true}
	// n1 enrolled "member" and "zeta"; a-noname (no name) is unowned and
	// must stay hidden (review #16: ownership-scoped projection).
	if err := env.st.ClaimAgentOwner(context.Background(), "n1", "member"); err != nil {
		t.Fatalf("claim member: %v", err)
	}
	if err := env.st.ClaimAgentOwner(context.Background(), "n1", "zeta"); err != nil {
		t.Fatalf("claim zeta: %v", err)
	}
	existing := []*model.Member{{ID: "a-dup", NetworkID: "n1", Class: model.ClassGuest}}
	out := r.hubAgentMembers(context.Background(), "n1", existing)
	if len(out) != 1 {
		t.Fatalf("dedup/ownership filter failed: %+v", out)
	}
	if out[0].ID != "a-online" || out[0].DisplayName != "zeta" {
		t.Fatalf("projection = %+v", out[0])
	}
	if out[0].NetworkID != "n1" || out[0].Class != model.ClassAgent || out[0].Presence != model.PresenceLive {
		t.Fatalf("projection = %+v", out[0])
	}
	// Another network sees nothing: agents enrolled by n1 only.
	if got := r.hubAgentMembers(context.Background(), "n2", nil); len(got) != 0 {
		t.Fatalf("cross-network leak: %+v", got)
	}
}
