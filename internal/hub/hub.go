// Package hub abstracts the dap hub connection. fa_network is one dap
// agent (a relay identity): it forwards opaque ciphertext between browser
// sessions and dap channels and mirrors hub presence — never plaintext
// (relay-only invariant, issue #1).
package hub

import (
	"context"
	"time"
)

// Envelope is what the relay passes through — payload stays base64
// ciphertext end to end.
type Envelope struct {
	ChannelID string
	ID        string
	Payload   string
	CreatedAt time.Time
}

// PresenceInfo is one agent's presence snapshot from the hub.
type PresenceInfo struct {
	AgentID  string
	Name     string
	Online   bool
	LastSeen time.Time
}

// Event kinds emitted on the Events channel.
const (
	EventMsg      = "msg"
	EventPresence = "presence"
	EventOffline  = "offline"
	EventOnline   = "online"
)

// Event is one hub-side occurrence.
type Event struct {
	Kind    string
	Msg     *Envelope
	AgentID string
	Name    string
	Online  bool
	At      time.Time
}

// Client is the dap hub connection contract. Implementations: the real
// dap WS client (dap.go) and the offline test double (fake.go).
type Client interface {
	// AgentID is this relay's dap identity (hex sha256 of pubkey, 16 chars).
	AgentID() string
	// Online reports whether the hub connection is live.
	Online() bool
	// Send relays one envelope into a channel (joins the channel first
	// when needed). Envelope order per channel must be preserved.
	Send(ctx context.Context, env Envelope) error
	// Events streams hub occurrences (msg/presence/offline/online).
	Events() <-chan Event
	// Presence returns the current hub agent roster.
	Presence(ctx context.Context) ([]PresenceInfo, error)
	// Close terminates the connection loop.
	Close(ctx context.Context) error
	// Run serves the connection loop until ctx ends or Close.
	Run(ctx context.Context) error
}
