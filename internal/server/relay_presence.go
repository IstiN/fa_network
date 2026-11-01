package server

import (
	"context"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
)

// updateHubAgent refreshes the agent presence cache and notifies watchers
// per network. Review #16: only the network that ENROLLED the agent name
// (agent_owners) receives its presence.changed; agents dropped in that
// network get no event either (clients must not re-insert them). The
// cache itself stays global for wakeup lookups.
func (r *Relay) updateHubAgent(ctx context.Context, ev hub.Event) {
	r.mu.Lock()
	info, ok := r.hubAgents[ev.AgentID]
	if !ok {
		info = hub.PresenceInfo{AgentID: ev.AgentID, Name: ev.Name}
	}
	info.Online = ev.Online
	if ev.Name != "" {
		info.Name = ev.Name
	}
	r.hubAgents[ev.AgentID] = info
	r.mu.Unlock()
	for _, networkID := range r.sessions.ActiveNetworks() {
		if !r.ownedAgentNames(ctx, networkID)[info.Name] || r.isDropped(networkID, ev.AgentID) {
			continue
		}
		member := &model.Member{ID: ev.AgentID, NetworkID: networkID, Class: model.ClassAgent}
		access := r.memberAccess(ctx, member)
		// Recheck after the store read: a drop completed meanwhile must
		// not be followed by a stale presence frame (review #15).
		if r.isDropped(networkID, ev.AgentID) {
			continue
		}
		r.sessions.BroadcastTo(networkID, presenceChangedWire{
			MemberID: ev.AgentID, Presence: onlinePresence(ev.Online),
			DisplayName: info.Name, Class: model.ClassAgent,
			Access: access,
		})
	}
}
