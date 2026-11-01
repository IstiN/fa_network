package server

import (
	"sort"
	"sync"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// wsConn is one browser WebSocket session.
type wsConn struct {
	session  *model.Session
	send     chan wsFrame
	subs     map[string]bool
	lastPong time.Time
	mu       sync.Mutex
	class    string
	// done signals shutdown without ever closing send (concurrent
	// broadcasters must never panic on a closed channel); closeConn
	// aborts the underlying socket so the read pump unblocks.
	done      chan struct{}
	closeOnce sync.Once
	closeConn func()
}

func newWSConn(sess *model.Session, class string) *wsConn {
	return &wsConn{
		session:  sess,
		send:     make(chan wsFrame, 64),
		subs:     map[string]bool{},
		lastPong: time.Now(),
		class:    class,
		done:     make(chan struct{}),
	}
}

// shutdown stops the writer and closes the socket exactly once.
func (c *wsConn) shutdown() {
	c.closeOnce.Do(func() {
		close(c.done)
		if c.closeConn != nil {
			c.closeConn()
		}
	})
}

func (c *wsConn) subscribed(channelID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.subs[channelID]
}

func (c *wsConn) setSub(channelID string, v bool) {
	c.mu.Lock()
	c.subs[channelID] = v
	c.mu.Unlock()
}

func (c *wsConn) markPong() {
	c.mu.Lock()
	c.lastPong = time.Now()
	c.mu.Unlock()
}

func (c *wsConn) silentFor(now time.Time, d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return now.Sub(c.lastPong) > d
}

// SessionRegistry tracks live browser sockets by session token. One
// session token may ride SEVERAL concurrent sockets (Chrome + Safari on
// the same account, reconnect overlap): the registry keys a token to a
// SET of connections, and removal is identity-safe (a closing old socket
// can never unregister its newer replacement).
type SessionRegistry struct {
	mu      sync.Mutex
	byToken map[string]map[*wsConn]struct{}
}

// NewSessionRegistry builds the registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{byToken: map[string]map[*wsConn]struct{}{}}
}

// Add registers a live socket.
func (r *SessionRegistry) Add(c *wsConn) {
	r.mu.Lock()
	set, ok := r.byToken[c.session.Token]
	if !ok {
		set = map[*wsConn]struct{}{}
		r.byToken[c.session.Token] = set
	}
	set[c] = struct{}{}
	r.mu.Unlock()
}

// Remove unregisters exactly this socket (idempotent, identity-safe:
// other sockets of the same token stay registered).
func (r *SessionRegistry) Remove(c *wsConn) {
	r.mu.Lock()
	if set, ok := r.byToken[c.session.Token]; ok {
		delete(set, c)
		if len(set) == 0 {
			delete(r.byToken, c.session.Token)
		}
	}
	r.mu.Unlock()
}

// collect returns every live socket matching the filter (a snapshot —
// broadcasting never holds the lock).
func (r *SessionRegistry) collect(match func(*wsConn) bool) []*wsConn {
	r.mu.Lock()
	targets := []*wsConn{}
	for _, set := range r.byToken {
		for c := range set {
			if match(c) {
				targets = append(targets, c)
			}
		}
	}
	r.mu.Unlock()
	return targets
}

// Get returns one socket for a session token (any of them — diagnostics
// only; delivery paths never assume a single socket).
func (r *SessionRegistry) Get(token string) *wsConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	for c := range r.byToken[token] {
		return c
	}
	return nil
}

// MemberLive reports whether any socket of a member is connected.
func (r *SessionRegistry) MemberLive(networkID, memberID string) bool {
	return len(r.collect(func(c *wsConn) bool {
		return c.session.NetworkID == networkID && c.session.MemberID == memberID
	})) > 0
}

// Broadcast delivers one event frame to every live socket.
func (r *SessionRegistry) Broadcast(payload any) {
	r.BroadcastTo("", payload)
}

// BroadcastTo delivers one event frame to the sockets of one network
// (empty networkID = all sockets).
func (r *SessionRegistry) BroadcastTo(networkID string, payload any) {
	targets := r.collect(func(c *wsConn) bool {
		return networkID == "" || c.session.NetworkID == networkID
	})
	frame := wsFrame{Type: frameTypeOf(payload), Payload: payload}
	for _, c := range targets {
		deliver(c, frame)
	}
}

// NotifyManagers delivers wakeup.dispatched to owner/admin sessions only
// (observability per the spec).
func (r *SessionRegistry) NotifyManagers(networkID string, payload any) {
	targets := r.collect(func(c *wsConn) bool {
		return c.session.NetworkID == networkID && (c.class == model.ClassOwner || c.class == model.ClassAdmin)
	})
	frame := wsFrame{Type: frameTypeOf(payload), Payload: payload}
	for _, c := range targets {
		deliver(c, frame)
	}
}

// FanoutEnvelope pushes one envelope to every socket subscribed to its
// channel within the given network.
func (r *SessionRegistry) FanoutEnvelope(networkID string, env model.EnvelopeWire) {
	targets := r.collect(func(c *wsConn) bool {
		return c.session.NetworkID == networkID && c.subscribed(env.ChannelID)
	})
	frame := wsFrame{Type: "envelope", Payload: env}
	for _, c := range targets {
		deliver(c, frame)
	}
}

// SnapshotFor returns the roster frame for one socket's network.
func (r *SessionRegistry) SnapshotFor(networkID string, members []*model.Member) wsFrame {
	wires := make([]model.MemberWire, 0, len(members))
	for _, m := range members {
		wires = append(wires, model.MemberWireOf(m))
	}
	return wsFrame{Type: "roster.snapshot", Payload: rosterSnapshotWire{Members: wires}}
}

// KickMember disconnects every socket of one member (agent/guest kick).
// Their sessions are already deleted store-side; the next read fails and
// the per-connection cleanup (including registry removal) runs.
func (r *SessionRegistry) KickMember(networkID, memberID string) {
	for _, c := range r.collect(func(c *wsConn) bool {
		return c.session.NetworkID == networkID && c.session.MemberID == memberID
	}) {
		c.shutdown()
	}
}

// ActiveNetworks lists networks with at least one connected socket.
func (r *SessionRegistry) ActiveNetworks() []string {
	set := map[string]bool{}
	for _, c := range r.collect(func(c *wsConn) bool { return c.session.NetworkID != "" }) {
		set[c.session.NetworkID] = true
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// deliver is a non-blocking frame push (slow consumers drop, never stall
// the relay).
func deliver(c *wsConn, frame wsFrame) {
	select {
	case c.send <- frame:
	default:
	}
}

// frameTypeOf maps a payload to its WS event type.
func frameTypeOf(payload any) string {
	switch payload.(type) {
	case presenceChangedWire:
		return "presence.changed"
	case rosterSnapshotWire:
		return "roster.snapshot"
	case networkOfflineWire:
		return "network.offline"
	case networkDrainWire:
		return "network.drain"
	case wakeupDispatchedWire:
		return "wakeup.dispatched"
	}
	return "unknown"
}
