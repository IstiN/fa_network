package server

import (
	"context"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
	"github.com/IstiN/fa_network/internal/store"
)

// ownedCountStore counts NetworkAgentNames calls (the review-#16 hot
// path: one store query per network per hub presence flap).
type ownedCountStore struct {
	store.Store
	calls int
}

func (c *ownedCountStore) NetworkAgentNames(ctx context.Context, networkID string) ([]string, error) {
	c.calls++
	return c.Store.NetworkAgentNames(ctx, networkID)
}

// TestOwnedAgentNamesCache proves the enrollment set is loaded at most
// once per TTL window regardless of presence-event volume, and that
// TTL expiry + InvalidateOwned force a reload.
func TestOwnedAgentNamesCache(t *testing.T) {
	mem := store.NewMemStore()
	if err := mem.ClaimAgentOwner(context.Background(), "n1", "scoped-agent"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	cs := &ownedCountStore{Store: mem}
	reg := NewSessionRegistry()
	reg.Add(newWSConn(&model.Session{Token: "t1", NetworkID: "n1"}, "member"))
	r := NewRelay(cs, hub.NewFakeClient("relay"), reg, nil, func() time.Time { return now })

	for i := 0; i < 10; i++ { // burst of presence flaps
		r.updateHubAgent(context.Background(), hub.Event{Kind: hub.EventPresence, AgentID: "a1", Name: "scoped-agent", Online: true})
	}
	if cs.calls != 1 {
		t.Fatalf("expected 1 store load for 10 events, got %d", cs.calls)
	}

	r.InvalidateOwned("n1") // enroll/drop path
	r.updateHubAgent(context.Background(), hub.Event{Kind: hub.EventPresence, AgentID: "a1", Name: "scoped-agent", Online: false})
	if cs.calls != 2 {
		t.Fatalf("expected reload after invalidation, got %d calls", cs.calls)
	}

	now = now.Add(ownedCacheTTL + time.Second) // TTL lapse
	r.updateHubAgent(context.Background(), hub.Event{Kind: hub.EventPresence, AgentID: "a1", Name: "scoped-agent", Online: true})
	if cs.calls != 3 {
		t.Fatalf("expected reload after TTL, got %d calls", cs.calls)
	}
}

// TestTouchSessionThrottle proves activity stamps persist at most once
// per touchThrottle window per session.
func TestTouchSessionThrottle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &Server{cfg: Config{Now: func() time.Time { return now }}}
	if !s.shouldTouch("tok") {
		t.Fatal("first touch must persist")
	}
	if s.shouldTouch("tok") {
		t.Fatal("second touch inside window must be throttled")
	}
	now = now.Add(touchThrottle + time.Second)
	if !s.shouldTouch("tok") {
		t.Fatal("touch after window must persist")
	}
	if !s.shouldTouch("other") {
		t.Fatal("independent session must not be throttled")
	}
}
