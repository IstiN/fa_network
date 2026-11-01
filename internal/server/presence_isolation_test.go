package server

// presence_isolation_test.go — review #16 end-to-end: a hub agent's
// presence.changed reaches ONLY the network that enrolled it; another
// network's live sockets never learn the agent exists.

import (
	"context"
	"testing"

	"github.com/IstiN/fa_network/internal/hub"
)

func TestPresenceChangedScopedToOwningNetwork(t *testing.T) {
	env := newTestEnv(t)
	ownerJWT := env.authedToken("owner1", "Owner One")
	netA := env.createNetwork(t, ownerJWT, "net-a", "secret123")
	sessA, _ := env.join(t, netA, "secret123", "", ownerJWT)
	netB := env.createNetwork(t, ownerJWT, "net-b", "secret123")
	sessB, _ := env.join(t, netB, "secret123", "", ownerJWT)

	// Agent "scoped-agent" enrolled by netA only.
	if err := env.st.ClaimAgentOwner(context.Background(), netA, "scoped-agent"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	env.hub.SetPresence([]hub.PresenceInfo{{AgentID: "a-9", Name: "scoped-agent", Online: true}})
	env.hub.SetOnline(false)
	env.hub.SetOnline(true)
	waitForCondition(t, "presence seed", func() bool { return env.srv.relay.hubAgentName("a-9") == "scoped-agent" })

	// Roster snapshots: A sees the agent, B does not.
	membersA, _ := env.st.Members(context.Background(), netA)
	if got := env.srv.relay.hubAgentMembers(context.Background(), netA, membersA); len(got) != 1 || got[0].DisplayName != "scoped-agent" {
		t.Fatalf("owner network must see the agent: %+v", got)
	}
	membersB, _ := env.st.Members(context.Background(), netB)
	if got := env.srv.relay.hubAgentMembers(context.Background(), netB, membersB); len(got) != 0 {
		t.Fatalf("foreign network must not see the agent: %+v", got)
	}

	// Live event: a presence flip must reach A's socket, never B's.
	browserA := dialWS(t, env, sessA)
	browserA.next("roster.snapshot")
	browserB := dialWS(t, env, sessB)
	browserB.next("roster.snapshot")

	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a-9", Name: "scoped-agent", Online: false})
	frame := browserA.next("presence.changed")
	name, _ := frame.Payload.(map[string]any)["displayName"].(string)
	if name != "scoped-agent" {
		t.Fatalf("A got wrong agent: %+v", frame.Payload)
	}
	// B must see no presence frame for the agent: a ping round-trip
	// proves the read pump processed everything queued before it.
	browserB.send(map[string]any{"type": "ping"})
	for f := browserB.next("pong", "presence.changed"); f.Type != "pong"; f = browserB.next("pong", "presence.changed") {
		if f.Type == "presence.changed" {
			t.Fatalf("cross-network presence leak: %+v", f.Payload)
		}
	}
}
