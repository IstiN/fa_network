package server

import (
	"context"
	"sync"
	"time"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
	"github.com/IstiN/fa_network/internal/store"
	"github.com/IstiN/fa_network/internal/wakeup"
)

// Relay ties the store, the dap hub client, the WS session registry, and
// the wake-up dispatcher together. It owns:
//   - outbound envelope ordering + offline queueing + drain (AC-B7),
//   - inbound hub envelope persistence + WS fan-out,
//   - presence bookkeeping (members via WS, agents via hub),
//   - presence-gated wake-up dispatch on mentions (AC-B6).
type Relay struct {
	st       store.Store
	hub      hub.Client
	sessions *SessionRegistry
	wake     *wakeup.Dispatcher
	now      func() time.Time

	mu        sync.Mutex
	queues    map[string][]*model.Envelope // channelID -> pending outbound
	sending   map[string]bool              // per-channel send serialization
	hubAgents map[string]hub.PresenceInfo  // agentID -> last known
	online    bool
}

// NewRelay builds the relay.
func NewRelay(st store.Store, hubClient hub.Client, sessions *SessionRegistry, dispatcher *wakeup.Dispatcher, now func() time.Time) *Relay {
	return &Relay{
		st:        st,
		hub:       hubClient,
		sessions:  sessions,
		wake:      dispatcher,
		now:       now,
		queues:    map[string][]*model.Envelope{},
		sending:   map[string]bool{},
		hubAgents: map[string]hub.PresenceInfo{},
		online:    hubClient.Online(),
	}
}

// Run pumps hub events until ctx ends (started as a goroutine).
func (r *Relay) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-r.hub.Events():
			if !ok {
				return
			}
			r.handleEvent(ctx, ev)
		}
	}
}

func (r *Relay) handleEvent(ctx context.Context, ev hub.Event) {
	switch ev.Kind {
	case hub.EventMsg:
		r.inbound(ctx, ev.Msg)
	case hub.EventPresence:
		r.updateHubAgent(ev)
	case hub.EventOffline:
		r.setOnline(false)
		r.sessions.Broadcast(networkOfflineWire{Reason: "hub unreachable"})
	case hub.EventOnline:
		r.setOnline(true)
		count := r.drainAll(ctx)
		r.sessions.Broadcast(networkDrainWire{Count: count})
	}
}

func (r *Relay) setOnline(v bool) {
	r.mu.Lock()
	r.online = v
	r.mu.Unlock()
}

// Outbound stores nothing (the caller persisted); it forwards toward the
// hub, queueing per channel while offline — order preserved, at-least-once
// with id-dedup on every hop (AC-B7).
func (r *Relay) Outbound(ctx context.Context, env *model.Envelope) {
	r.mu.Lock()
	if !r.online {
		r.queues[env.ChannelID] = append(r.queues[env.ChannelID], cloneEnv(env))
		r.mu.Unlock()
		return
	}
	if r.sending[env.ChannelID] {
		r.queues[env.ChannelID] = append(r.queues[env.ChannelID], cloneEnv(env))
		r.mu.Unlock()
		return
	}
	r.sending[env.ChannelID] = true
	r.mu.Unlock()
	r.deliver(ctx, env)
}

// deliver sends one envelope, then any queue that accumulated behind it.
func (r *Relay) deliver(ctx context.Context, first *model.Envelope) {
	channelID := first.ChannelID
	env := first
	for env != nil {
		err := r.hub.Send(ctx, hub.Envelope{
			ChannelID: env.ChannelID,
			ID:        env.ID,
			Payload:   env.Payload,
			CreatedAt: env.CreatedAt,
		})
		if err != nil {
			r.setOnline(false)
			r.mu.Lock()
			r.queues[channelID] = append([]*model.Envelope{cloneEnv(env)}, r.queues[channelID]...)
			r.mu.Unlock()
			break
		}
		r.mu.Lock()
		if n := len(r.queues[channelID]); n > 0 {
			env = r.queues[channelID][0]
			r.queues[channelID] = r.queues[channelID][1:]
		} else {
			env = nil
		}
		r.mu.Unlock()
	}
	r.mu.Lock()
	delete(r.sending, channelID)
	r.mu.Unlock()
}

// drainAll flushes every queued channel after reconnect; returns the total
// drained count (announced via network.drain).
func (r *Relay) drainAll(ctx context.Context) int {
	r.mu.Lock()
	total := 0
	for channelID, queued := range r.queues {
		if len(queued) == 0 {
			continue
		}
		total += len(queued)
		if r.sending[channelID] {
			continue // a live sender drains its own queue
		}
		r.sending[channelID] = true
		first := queued[0]
		r.queues[channelID] = queued[1:]
		go r.deliver(ctx, cloneEnv(first))
	}
	r.mu.Unlock()
	return total
}

// inbound persists a hub-originated envelope (id-dedup) and fans it out to
// every subscribed browser session (sender echo included, per dap/1).
func (r *Relay) inbound(ctx context.Context, msg *hub.Envelope) {
	if msg == nil {
		return
	}
	channel, err := r.st.Channel(ctx, msg.ChannelID)
	if err != nil {
		// Unknown to fa_network: persist under its own id space is
		// impossible — drop (fa agents in channels fa_network never saw).
		return
	}
	env := &model.Envelope{
		ID:        msg.ID,
		ChannelID: msg.ChannelID,
		SenderID:  r.hub.AgentID(),
		Payload:   msg.Payload,
		CreatedAt: r.now(),
	}
	stored, err := r.st.AppendEnvelope(ctx, env)
	if err != nil || !stored {
		return
	}
	r.sessions.FanoutEnvelope(channel.NetworkID, model.EnvelopeWireOf(env))
}

// updateHubAgent refreshes the agent presence cache and notifies watchers.
func (r *Relay) updateHubAgent(ev hub.Event) {
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
	r.sessions.Broadcast(presenceChangedWire{MemberID: ev.AgentID, Presence: onlinePresence(ev.Online)})
}

// hubPresence returns the cached roster of dap agents.
func (r *Relay) hubPresence() []hub.PresenceInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]hub.PresenceInfo, 0, len(r.hubAgents))
	for _, info := range r.hubAgents {
		out = append(out, info)
	}
	return out
}

// Agents composes the network agent roster: agent-class members plus hub
// agents, with presence and wake-up registration state.
func (r *Relay) Agents(ctx context.Context, networkID string) ([]model.AgentWire, error) {
	members, err := r.st.Members(ctx, networkID)
	if err != nil {
		return nil, err
	}
	wires := r.memberAgents(ctx, networkID, members)
	return append(wires, r.hubAgentsWires(ctx, networkID, wires)...), nil
}

// memberAgents lists agent-class members of the network.
func (r *Relay) memberAgents(ctx context.Context, networkID string, members []*model.Member) []model.AgentWire {
	wires := []model.AgentWire{}
	for _, m := range members {
		if m.Class != model.ClassGuest && m.Class != model.ClassAgent {
			continue
		}
		wires = append(wires, model.AgentWire{
			AgentID:          m.ID,
			DisplayName:      m.DisplayName,
			Presence:         m.Presence,
			WakeupRegistered: r.registered(ctx, networkID, m.ID),
		})
	}
	return wires
}

// hubAgentsWires lists hub agents not already represented by members.
func (r *Relay) hubAgentsWires(ctx context.Context, networkID string, existing []model.AgentWire) []model.AgentWire {
	seen := map[string]bool{}
	for _, w := range existing {
		seen[w.AgentID] = true
	}
	wires := []model.AgentWire{}
	for _, info := range r.hubPresence() {
		if seen[info.AgentID] {
			continue
		}
		wires = append(wires, model.AgentWire{
			AgentID:          info.AgentID,
			DisplayName:      info.Name,
			Presence:         onlinePresence(info.Online),
			WakeupRegistered: r.registered(ctx, networkID, info.AgentID),
		})
	}
	return wires
}

func (r *Relay) registered(ctx context.Context, networkID, agentID string) bool {
	_, err := r.st.Wakeup(ctx, networkID, agentID)
	return err == nil
}

// Mentions fires presence-gated wake-ups for offline mentioned agents
// (identity-only payload — law #3). Mentions are agent ids, not content.
func (r *Relay) Mentions(ctx context.Context, networkID string, env *model.Envelope) {
	for _, agentID := range env.Mentions {
		member, err := r.st.Member(ctx, networkID, agentID)
		if err != nil {
			continue // not a network member — nothing to wake
		}
		_ = r.wake.Dispatch(ctx, networkID, agentID, member.Presence)
		r.sessions.NotifyManagers(networkID, wakeupDispatchedWire{AgentID: agentID, At: r.now()})
	}
}

// PresenceOf reports the member presence, consulting live sessions first.
func (r *Relay) PresenceOf(member *model.Member) string {
	if r.sessions.MemberLive(member.NetworkID, member.ID) {
		return model.PresenceLive
	}
	return model.PresenceOffline
}

// SyncMemberPresence refreshes a member's presence in the store and
// broadcasts presence.changed to the network's sessions.
func (r *Relay) SyncMemberPresence(ctx context.Context, member *model.Member) {
	presence := r.PresenceOf(member)
	if member.Presence == presence {
		return
	}
	member.Presence = presence
	_ = r.st.UpdateMemberPresence(ctx, member.NetworkID, member.ID, presence)
	r.sessions.BroadcastTo(member.NetworkID, presenceChangedWire{MemberID: member.ID, Presence: presence})
}

func cloneEnv(e *model.Envelope) *model.Envelope {
	cp := *e
	cp.Mentions = append([]string(nil), e.Mentions...)
	return &cp
}

func onlinePresence(online bool) string {
	if online {
		return model.PresenceLive
	}
	return model.PresenceOffline
}
