package server

import (
	"context"
	"log"
)

// loadDropped restores per-network roster exclusions at relay start.
func (r *Relay) loadDropped(ctx context.Context) {
	drops, err := r.st.DroppedAgents(ctx)
	if err != nil {
		log.Printf("relay: load dropped hub agents: %v", err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for networkID, ids := range drops {
		if r.dropped[networkID] == nil {
			r.dropped[networkID] = map[string]bool{}
		}
		for _, id := range ids {
			r.dropped[networkID][id] = true
		}
	}
}

// dropHubAgent applies a per-network roster exclusion in memory (the
// store already persists it) and refreshes the enrollment cache.
func (r *Relay) dropHubAgent(networkID, agentID string) {
	r.mu.Lock()
	if r.dropped[networkID] == nil {
		r.dropped[networkID] = map[string]bool{}
	}
	r.dropped[networkID][agentID] = true
	r.mu.Unlock()
	r.InvalidateOwned(networkID)
}

// isDropped reports the per-network exclusion (idempotent drop checks).
func (r *Relay) isDropped(networkID, agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped[networkID][agentID]
}

// droppedLocked reads the exclusion while r.mu is held by the caller.
func (r *Relay) droppedLocked(networkID, agentID string) bool {
	return r.dropped[networkID][agentID]
}
