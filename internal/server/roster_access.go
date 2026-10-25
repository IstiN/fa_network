package server

import (
	"context"
	"sort"

	"github.com/IstiN/fa_network/internal/model"
)

// accessForMember derives the roster access badge from channel ACLs:
// empty ACL = open (network-wide); owner/admin always cover the whole
// network. "channels" lists every accessible channel (open plus those
// whose ACL names the member), so clients can render exact scope.
func accessForMember(m *model.Member, channels []*model.Channel) *model.AccessWire {
	if m.Class == model.ClassOwner || m.Class == model.ClassAdmin {
		return &model.AccessWire{Scope: "network"}
	}
	accessible := make([]string, 0, len(channels))
	for _, ch := range channels {
		if len(ch.ACL) == 0 || aclContains(ch.ACL, m.ID) {
			accessible = append(accessible, ch.ID)
		}
	}
	if len(accessible) == len(channels) {
		return &model.AccessWire{Scope: "network"}
	}
	sort.Strings(accessible)
	return &model.AccessWire{Scope: "channels", ChannelIDs: accessible}
}

func aclContains(acl []string, id string) bool {
	for _, entry := range acl {
		if entry == id {
			return true
		}
	}
	return false
}

// memberAccess computes one member's scope (nil on store error — the
// wire field is additive and simply omitted then).
func (r *Relay) memberAccess(ctx context.Context, m *model.Member) *model.AccessWire {
	channels, err := r.st.Channels(ctx, m.NetworkID)
	if err != nil {
		return nil
	}
	return accessForMember(m, channels)
}

// decorateAccess fills Access for a roster list grouped by network (one
// channel read per network).
func (r *Relay) decorateAccess(ctx context.Context, members []*model.Member) {
	byNetwork := map[string][]*model.Member{}
	for _, m := range members {
		byNetwork[m.NetworkID] = append(byNetwork[m.NetworkID], m)
	}
	for networkID, group := range byNetwork {
		channels, err := r.st.Channels(ctx, networkID)
		if err != nil {
			continue
		}
		for _, m := range group {
			m.Access = accessForMember(m, channels)
		}
	}
}

// broadcastRosterSnapshot pushes a fresh roster (members + hub agents +
// access scopes) to every socket of one network: used after agent drops
// and channel/ACL mutations, where presence.changed alone cannot carry
// the change.
func (s *Server) broadcastRosterSnapshot(ctx context.Context, networkID string) {
	members, err := s.st.Members(ctx, networkID)
	if err != nil {
		return
	}
	members = append(members, s.relay.hubAgentMembers(networkID, members)...)
	s.relay.decorateAccess(ctx, members)
	s.sessions.BroadcastTo(networkID, s.sessions.SnapshotFor(networkID, members).Payload)
}

// broadcastRosterSnapshotsAll refreshes rosters in every network with at
// least one connected socket (hub-agent drops are global).
func (s *Server) broadcastRosterSnapshotsAll(ctx context.Context) {
	for _, networkID := range s.sessions.ActiveNetworks() {
		s.broadcastRosterSnapshot(ctx, networkID)
	}
}
