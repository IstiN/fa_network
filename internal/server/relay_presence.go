package server

import (
	"context"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
)

// updateHubAgent refreshes the agent presence cache and notifies watchers.
// Dropped agents are ignored entirely (no cache resurrection, no
// presence.changed that would re-insert them into client rosters).
func (r *Relay) updateHubAgent(ctx context.Context, ev hub.Event) {
	r.mu.Lock()
	if r.dropped[ev.AgentID] {
		r.mu.Unlock()
		return
	}
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
	// Access scope is per-network: fan out per active network instead of
	// one global frame (issue: roster access badges).
	for _, networkID := range r.sessions.ActiveNetworks() {
		member := &model.Member{ID: ev.AgentID, NetworkID: networkID, Class: model.ClassAgent}
		r.sessions.BroadcastTo(networkID, presenceChangedWire{
			MemberID: ev.AgentID, Presence: onlinePresence(ev.Online),
			DisplayName: info.Name, Class: model.ClassAgent,
			Access: r.memberAccess(ctx, member),
		})
	}
}
