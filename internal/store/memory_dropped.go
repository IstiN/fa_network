package store

import (
	"context"
	"sort"
)

// DropAgent implements AgentDrops (idempotent, per-network).
func (m *MemStore) DropAgent(_ context.Context, networkID, agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dropped[networkID] == nil {
		m.dropped[networkID] = map[string]bool{}
	}
	m.dropped[networkID][agentID] = true
	return nil
}

// DroppedAgents implements AgentDrops.
func (m *MemStore) DroppedAgents(_ context.Context) (map[string][]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string][]string{}
	for networkID, agents := range m.dropped {
		ids := make([]string, 0, len(agents))
		for id := range agents {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out[networkID] = ids
	}
	return out, nil
}

// ClaimAgentOwner implements AgentOwnership (first-come reservation).
func (m *MemStore) ClaimAgentOwner(_ context.Context, networkID, agentName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if owner, ok := m.owners[agentName]; ok {
		if owner != networkID {
			return ErrConflict
		}
		return nil
	}
	m.owners[agentName] = networkID
	return nil
}

// AgentOwner implements AgentOwnership.
func (m *MemStore) AgentOwner(_ context.Context, agentName string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	owner, ok := m.owners[agentName]
	if !ok {
		return "", ErrNotFound
	}
	return owner, nil
}
