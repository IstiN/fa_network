package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/store"
	"github.com/IstiN/fa_network/internal/wakeup"
)

// Agents present BEFORE a relay restart must be seeded back online from
// the hub roster on reconnect (the "0 online after deploy" regression).
func TestSeedHubPresenceOnReconnect(t *testing.T) {
	env := newTestEnv(t)
	env.hub.SetPresence([]hub.PresenceInfo{{AgentID: "a1", Name: "public-agent", Online: true}})
	env.hub.SetOnline(false)
	env.hub.SetOnline(true)
	waitForCondition(t, "presence seeded after reconnect", func() bool {
		return env.srv.relay.hubAgentName("a1") == "public-agent"
	})
	infos := env.srv.relay.hubPresence()
	if len(infos) != 1 || !infos[0].Online {
		t.Fatalf("seeded presence = %+v", infos)
	}
}

// flakyPresenceHub fails the first N presence queries (cold hub).
type flakyPresenceHub struct {
	hub.Client
	mu       sync.Mutex
	failures int
}

func (f *flakyPresenceHub) Presence(ctx context.Context) ([]hub.PresenceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures > 0 {
		f.failures--
		return nil, errors.New("hub cold")
	}
	return f.Client.Presence(ctx)
}

// A failed initial seed is retried in the background until the hub
// answers; the roster must still converge without any agent reconnect.
func TestSeedHubPresenceRetryAfterFailure(t *testing.T) {
	fake := hub.NewFakeClient("r_test")
	flaky := &flakyPresenceHub{Client: fake, failures: 1}
	st := store.NewMemStore()
	dispatcher := wakeup.NewDispatcher(wakeup.Options{Store: st})
	r := NewRelay(st, flaky, NewSessionRegistry(), dispatcher, time.Now)
	r.seedRetryDelays = []time.Duration{10 * time.Millisecond}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go r.Run(ctx)

	fake.SetPresence([]hub.PresenceInfo{{AgentID: "a2", Name: "public-agent", Online: true}})
	fake.SetOnline(false)
	fake.SetOnline(true)
	waitForCondition(t, "retry seeds presence", func() bool {
		return r.hubAgentName("a2") == "public-agent"
	})
	infos := r.hubPresence()
	if len(infos) != 1 || !infos[0].Online {
		t.Fatalf("presence after retry = %+v", infos)
	}
	flaky.mu.Lock()
	remaining := flaky.failures
	flaky.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected exactly one failed attempt, remaining=%d", remaining)
	}
}
