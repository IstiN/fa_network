package store

import (
	"context"
	"sort"
)

// DropHubAgent implements DroppedHubAgents (idempotent tombstone).
func (m *MemStore) DropHubAgent(_ context.Context, agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropped[agentID] = true
	return nil
}

// DroppedHubAgentIDs implements DroppedHubAgents.
func (m *MemStore) DroppedHubAgentIDs(_ context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.dropped))
	for id := range m.dropped {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
