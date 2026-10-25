package store

import (
	"context"
	"testing"
)

func TestMemStoreDroppedHubAgents(t *testing.T) {
	st := NewMemStore()
	ctx := context.Background()
	for _, id := range []string{"b2", "a1", "b2"} {
		if err := st.DropHubAgent(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := st.DroppedHubAgentIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "a1" || ids[1] != "b2" {
		t.Fatalf("ids = %v (idempotent, sorted expected)", ids)
	}
}
