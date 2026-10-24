package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
)

func TestAgentOnlineByNameOrID(t *testing.T) {
	env := newTestEnv(t)
	if id, online := env.srv.relay.AgentOnlineByNameOrID("nobody"); id != "" || online {
		t.Fatal("unknown agent must be offline with empty id")
	}
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a1", Name: "gh-o-r-1", Online: true})
	waitFor(t, "presence cache", func() bool {
		id, online := env.srv.relay.AgentOnlineByNameOrID("a1")
		return id == "a1" && online
	})
	if id, online := env.srv.relay.AgentOnlineByNameOrID("gh-o-r-1"); id != "a1" || !online {
		t.Fatalf("by name = %q %v", id, online)
	}
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a1", Online: false})
	waitFor(t, "offline transition", func() bool {
		_, online := env.srv.relay.AgentOnlineByNameOrID("gh-o-r-1")
		return !online
	})
	if id, _ := env.srv.relay.AgentOnlineByNameOrID("gh-o-r-1"); id != "a1" {
		t.Fatal("name must survive offline transition (cached name kept)")
	}
}

// TestMentionsWakesPureHubAgent covers issue #3: a DAP-only agent (no
// store membership) with a registered wakeup must be woken on @mention.
func TestMentionsWakesPureHubAgent(t *testing.T) {
	env := newTestEnv(t)
	var calls atomic.Int64
	var mu sync.Mutex
	var lastPayload map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("payload: %v", err)
		}
		mu.Lock()
		lastPayload = payload
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()
	ctx := context.Background()
	networkID := "n-hub"
	if err := env.st.UpsertWakeup(ctx, &model.WakeupRegistration{
		NetworkID: networkID, AgentID: "a1", URL: hook.URL, DebounceSeconds: 30,
	}); err != nil {
		t.Fatal(err)
	}
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a1", Name: "gh-o-r-1", Online: false})
	waitFor(t, "hub agent cached", func() bool {
		_, ok := env.srv.relay.hubAgentByID("a1")
		return ok
	})
	env.srv.relay.Mentions(ctx, networkID, &model.Envelope{Mentions: []string{"a1", "unknown-agent"}})
	waitFor(t, "hub agent wakeup", func() bool { return calls.Load() == 1 })
	mu.Lock()
	payload := lastPayload
	mu.Unlock()
	if payload["agentId"] != "a1" || payload["networkId"] != networkID {
		t.Fatalf("payload = %+v", payload)
	}
	if _, ok := payload["prompt"]; ok {
		t.Fatal("identity-only law: no content in wakeup payload")
	}
	// Online hub agents are skipped (presence gate).
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "a1", Online: true})
	waitFor(t, "online transition", func() bool {
		_, online := env.srv.relay.AgentOnlineByNameOrID("a1")
		return online
	})
	env.srv.relay.Mentions(ctx, networkID, &model.Envelope{Mentions: []string{"a1"}})
	if calls.Load() != 1 {
		t.Fatalf("online agent must not be woken, calls=%d", calls.Load())
	}
}
