package store

import (
	"context"
	"testing"
)

func TestMemAgentDropsPerNetwork(t *testing.T) {
	st := NewMemStore()
	ctx := context.Background()
	_ = st.DropAgent(ctx, "net-a", "a1")
	_ = st.DropAgent(ctx, "net-b", "a1")
	_ = st.DropAgent(ctx, "net-a", "a1") // idempotent
	drops, err := st.DroppedAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(drops["net-a"]) != 1 || drops["net-a"][0] != "a1" {
		t.Fatalf("drops = %+v", drops)
	}
	if len(drops["net-b"]) != 1 {
		t.Fatalf("net-b drops = %+v", drops)
	}
}

func TestMemAgentOwnershipFirstCome(t *testing.T) {
	st := NewMemStore()
	ctx := context.Background()
	if err := st.ClaimAgentOwner(ctx, "net-a", "kb"); err != nil {
		t.Fatal(err)
	}
	if err := st.ClaimAgentOwner(ctx, "net-a", "kb"); err != nil {
		t.Fatalf("same-network reclaim must be a no-op: %v", err)
	}
	if err := st.ClaimAgentOwner(ctx, "net-b", "kb"); !IsConflict(err) {
		t.Fatalf("cross-tenant claim = %v, want ErrConflict", err)
	}
	if _, err := st.AgentOwner(ctx, "unknown"); !IsNotFound(err) {
		t.Fatalf("unknown owner = %v, want ErrNotFound", err)
	}
	owner, err := st.AgentOwner(ctx, "kb")
	if err != nil || owner != "net-a" {
		t.Fatalf("owner = %q err %v", owner, err)
	}
}
