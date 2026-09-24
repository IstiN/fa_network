package server

import (
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
}

func newWSConn(sess *model.Session, class string) *wsConn {
	return &wsConn{
		session:  sess,
		send:     make(chan wsFrame, 64),
		subs:     map[string]bool{},
		lastPong: time.Now(),
		class:    class,
	}
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

// SessionRegistry tracks live browser sockets by session token.
type SessionRegistry struct {
	mu      sync.Mutex
	byToken map[string]*wsConn
}

// NewSessionRegistry builds the registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{byToken: map[string]*wsConn{}}
}

// Add registers a live socket.
func (r *SessionRegistry) Add(c *wsConn) {
	r.mu.Lock()
	r.byToken[c.session.Token] = c
	r.mu.Unlock()
}

// Remove unregisters a socket (idempotent).
func (r *SessionRegistry) Remove(token string) {
	r.mu.Lock()
	delete(r.byToken, token)
	r.mu.Unlock()
}

// Get returns the socket for a session token.
func (r *SessionRegistry) Get(token string) *wsConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byToken[token]
}

// MemberLive reports whether any socket of a member is connected.
func (r *SessionRegistry) MemberLive(networkID, memberID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.byToken {
		if c.session.NetworkID == networkID && c.session.MemberID == memberID {
			return true
		}
	}
	return false
}

// Broadcast delivers one event frame to every live socket.
func (r *SessionRegistry) Broadcast(payload any) {
	r.BroadcastTo("", payload)
}

// BroadcastTo delivers one event frame to the sockets of one network
// (empty networkID = all sockets).
func (r *SessionRegistry) BroadcastTo(networkID string, payload any) {
	r.mu.Lock()
	targets := []*wsConn{}
	for _, c := range r.byToken {
		if networkID == "" || c.session.NetworkID == networkID {
			targets = append(targets, c)
		}
	}
	r.mu.Unlock()
	frame := wsFrame{Type: frameTypeOf(payload), Payload: payload}
	for _, c := range targets {
		deliver(c, frame)
	}
}

// NotifyManagers delivers wakeup.dispatched to owner/admin sessions only
// (observability per the spec).
func (r *SessionRegistry) NotifyManagers(networkID string, payload any) {
	r.mu.Lock()
	targets := []*wsConn{}
	for _, c := range r.byToken {
		if c.session.NetworkID == networkID && (c.class == model.ClassOwner || c.class == model.ClassAdmin) {
			targets = append(targets, c)
		}
	}
	r.mu.Unlock()
	frame := wsFrame{Type: frameTypeOf(payload), Payload: payload}
	for _, c := range targets {
		deliver(c, frame)
	}
}

// FanoutEnvelope pushes one envelope to every socket subscribed to its
// channel within the given network.
func (r *SessionRegistry) FanoutEnvelope(networkID string, env model.EnvelopeWire) {
	r.mu.Lock()
	targets := []*wsConn{}
	for _, c := range r.byToken {
		if c.session.NetworkID == networkID && c.subscribed(env.ChannelID) {
			targets = append(targets, c)
		}
	}
	r.mu.Unlock()
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
	case networkOfflineWire:
		return "network.offline"
	case networkDrainWire:
		return "network.drain"
	case wakeupDispatchedWire:
		return "wakeup.dispatched"
	}
	return "unknown"
}
