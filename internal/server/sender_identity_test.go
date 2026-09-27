package server

import (
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
)

// Issue #2 / IT-2: a hub-originated envelope keeps the TRUE dap sender
// (from field), not the relay's own agentId; the enrolled name rides as a
// render hint from the presence cache.
func TestHubInboundStampsTrueSender(t *testing.T) {
	env := newTestEnv(t)
	_, _, guestSess, channelID, _ := setupNetwork(t, env)

	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a_fa_agent", Name: "fa-agent", Online: true})

	msg := hubEnvelope(channelID, "hub-s1", "ZmFuZXQx")
	msg.SenderID = "a_fa_agent"
	env.hub.EmitMsg(msg)

	stored := waitEnvelope(t, env, channelID, "hub-s1")
	if stored.SenderID != "a_fa_agent" {
		t.Fatalf("SenderID = %q, want the hub sender a_fa_agent", stored.SenderID)
	}
	if stored.SenderName != "fa-agent" {
		t.Fatalf("SenderName = %q, want fa-agent (presence cache)", stored.SenderName)
	}

	// Wire projection exposes both fields.
	_ = guestSess
	wire := model.EnvelopeWireOf(stored)
	if wire.SenderID != "a_fa_agent" || wire.SenderName != "fa-agent" {
		t.Fatalf("wire = %+v", wire)
	}
}

// Issue #2 / REG-3: legacy hub frames without `from` fall back to the
// relay identity and no crash.
func TestHubInboundSenderFallback(t *testing.T) {
	env := newTestEnv(t)
	_, _, _, channelID, _ := setupNetwork(t, env)

	env.hub.EmitMsg(hubEnvelope(channelID, "hub-s2", "bGVnYWN5"))

	stored := waitEnvelope(t, env, channelID, "hub-s2")
	if stored.SenderID != env.hub.AgentID() {
		t.Fatalf("SenderID = %q, want relay fallback %q", stored.SenderID, env.hub.AgentID())
	}
	if stored.SenderName != "" {
		t.Fatalf("SenderName = %q, want empty for unknown sender", stored.SenderName)
	}
}

// waitEnvelope polls the store until the envelope id appears (relay loop
// is async).
func waitEnvelope(t *testing.T, env *testEnv, channelID, id string) *model.Envelope {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		page, err := env.st.Envelopes(t.Context(), channelID, "", 200)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for i := range page.Items {
			if page.Items[i].ID == id {
				return &page.Items[i]
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("envelope %s never stored", id)
	return nil
}
