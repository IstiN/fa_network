package server

import (
	"sort"

	"github.com/IstiN/fa_network/internal/model"
)

// hubAgentName resolves the enrolled display name of a hub agent from the
// presence cache (empty when unknown).
func (r *Relay) hubAgentName(agentID string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hubAgents[agentID].Name
}

// hubAgentMembers projects pure-DAP hub agents as synthetic agent-class
// members for the WS roster snapshot (issue #4): without this, agents
// already online before a browser connected never appeared in the app
// roster ("0 online" despite live DAP agents). Store-member ids are
// skipped (no duplicates), dropped agents are excluded (roster
// tombstones); the result is sorted by agent id.
func (r *Relay) hubAgentMembers(networkID string, members []*model.Member) []*model.Member {
	seen := map[string]bool{}
	for _, m := range members {
		seen[m.ID] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.hubAgents))
	for id := range r.hubAgents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []*model.Member{}
	for _, id := range ids {
		if seen[id] || r.dropped[id] {
			continue
		}
		info := r.hubAgents[id]
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
