package server

import (
	"context"
	"log"
)

// loadDropped restores roster tombstones at relay start so dropped hub
// agents never reappear after a restart/reseed.
func (r *Relay) loadDropped(ctx context.Context) {
	ids, err := r.st.DroppedHubAgentIDs(ctx)
	if err != nil {
		log.Printf("relay: load dropped hub agents: %v", err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		r.dropped[id] = true
	}
}

// dropHubAgent applies a roster tombstone in memory (the store already
// persists it) and evicts the agent from the presence cache.
func (r *Relay) dropHubAgent(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropped[agentID] = true
	delete(r.hubAgents, agentID)
}
