package server

import (
	"context"
	"sort"

	"github.com/IstiN/fa_network/internal/model"
)

// ownedAgentNames returns the hub-agent-name set enrolled by this network
// (agent_owners). Fail-closed: on store errors the set is empty — an
// unknown ownership must hide, not leak (review #16). Results are cached
// for ownedCacheTTL (errors are never cached); enroll/drop invalidate
// explicitly via InvalidateOwned.
func (r *Relay) ownedAgentNames(ctx context.Context, networkID string) map[string]bool {
	r.ownedMu.Lock()
	if e, ok := r.ownedCache[networkID]; ok && r.now().Sub(e.at) < ownedCacheTTL {
		r.ownedMu.Unlock()
		return e.names
	}
	r.ownedMu.Unlock()
	names, err := r.st.NetworkAgentNames(ctx, networkID)
	if err != nil {
		return map[string]bool{} // fail-closed, uncached
	}
	owned := make(map[string]bool, len(names))
	for _, n := range names {
		owned[n] = true
	}
	r.ownedMu.Lock()
	r.ownedCache[networkID] = ownedNames{names: owned, at: r.now()}
	r.ownedMu.Unlock()
	return owned
}

// InvalidateOwned drops the cached enrollment set for one network — call
// after any agent_owners mutation (enroll, drop).
func (r *Relay) InvalidateOwned(networkID string) {
	r.ownedMu.Lock()
	delete(r.ownedCache, networkID)
	r.ownedMu.Unlock()
}

// hubAgentName resolves the enrolled display name of a hub agent from the
// presence cache (empty when unknown).
func (r *Relay) hubAgentName(agentID string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hubAgents[agentID].Name
}

// hubAgentMembers projects the network's pure-DAP hub agents as synthetic
// agent-class members for the WS roster snapshot (issue #4 + review #16):
// an agent appears ONLY in the network that enrolled it (agent_owners) —
// no cross-tenant name/presence leakage. Unowned agents (enrolled
// directly on the hub) belong to no network and appear in none. Store
// members are skipped (no duplicates), dropped agents are excluded
// (roster tombstones); the result is sorted by agent id.
func (r *Relay) hubAgentMembers(ctx context.Context, networkID string, members []*model.Member) []*model.Member {
	seen := map[string]bool{}
	for _, m := range members {
		seen[m.ID] = true
	}
	owned := r.ownedAgentNames(ctx, networkID)
	r.mu.Lock()
	ids := make([]string, 0, len(r.hubAgents))
	for id := range r.hubAgents {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	sort.Strings(ids)
	out := []*model.Member{}
	for _, id := range ids {
		if seen[id] || r.isDropped(networkID, id) {
			continue
		}
		info, ok := r.hubAgentByID(id)
		if !ok || !owned[info.Name] {
			continue // unknown or not enrolled by this network: hidden
		}
		name := info.Name
		if name == "" {
			name = id
		}
		out = append(out, &model.Member{
			ID: id, NetworkID: networkID, Class: model.ClassAgent,
			DisplayName: name, Presence: onlinePresence(info.Online),
		})
	}
	return out
}

// AgentOnlineByNameOrID resolves a dap agent by AgentID or by enrolled
// Name (the webhook session_key, issue #3) and reports its presence.
func (r *Relay) AgentOnlineByNameOrID(nameOrID string) (agentID string, online bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if info, ok := r.hubAgents[nameOrID]; ok {
		return info.AgentID, info.Online
	}
	for id, info := range r.hubAgents {
		if info.Name == nameOrID {
			return id, info.Online
		}
	}
	return "", false
}
