package model

import (
	"strings"
	"time"
)

// API wire shapes — JSON field names follow docs/openapi.yaml exactly.

// ErrorWire is the RFC-style error envelope of the spec.
type ErrorWire struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody carries the machine code and human message.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NetworkWire is the public Network projection (no password material).
type NetworkWire struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	OwnerID        string    `json:"ownerId"`
	Admins         []string  `json:"admins,omitempty"`
	PublicChannels []string  `json:"publicChannels"`
	CreatedAt      time.Time `json:"createdAt"`
}

// NetworkWireOf projects a Network for the API.
func NetworkWireOf(n *Network) NetworkWire {
	return NetworkWire{
		ID:             n.ID,
		Name:           n.Name,
		OwnerID:        n.OwnerID,
		Admins:         n.Admins,
		PublicChannels: n.PublicChannels,
		CreatedAt:      n.CreatedAt,
	}
}

// MemberWire is the roster projection.
type MemberWire struct {
	ID          string `json:"id"`
	Class       string `json:"class"`
	DisplayName string `json:"displayName"`
	Presence    string `json:"presence"`
}

// MemberWireOf projects a Member for the API.
func MemberWireOf(m *Member) MemberWire {
	return MemberWire{
		ID:          m.ID,
		Class:       m.Class,
		DisplayName: m.DisplayName,
		Presence:    m.Presence,
	}
}

// ChannelWire is the public Channel projection.
type ChannelWire struct {
	ID            string   `json:"id"`
	NetworkID     string   `json:"networkId"`
	Name          string   `json:"name"`
	Public        bool     `json:"public"`
	ACL           []string `json:"acl,omitempty"`
	RetentionDays *int     `json:"retentionDays,omitempty"`
}

// ChannelWireOf projects a Channel for the API.
func ChannelWireOf(c *Channel) ChannelWire {
	return ChannelWire{
		ID:            c.ID,
		NetworkID:     c.NetworkID,
		Name:          c.Name,
		Public:        c.Public,
		ACL:           c.ACL,
		RetentionDays: c.RetentionDays,
	}
}

// EnvelopeWire is the opaque envelope projection.
type EnvelopeWire struct {
	ID        string    `json:"id"`
	ChannelID string    `json:"channelId"`
	SenderID  string    `json:"senderId"`
	Payload   string    `json:"payload"`
	Mentions  []string  `json:"mentions,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// EnvelopeWireOf projects an Envelope for the API.
func EnvelopeWireOf(e *Envelope) EnvelopeWire {
	return EnvelopeWire{
		ID:        e.ID,
		ChannelID: e.ChannelID,
		SenderID:  e.SenderID,
		Payload:   e.Payload,
		Mentions:  e.Mentions,
		CreatedAt: e.CreatedAt,
	}
}

// IdentityWire is the join-response identity projection.
type IdentityWire struct {
	ID          string `json:"id"`
	Class       string `json:"class"`
	DisplayName string `json:"displayName"`
	AuthName    string `json:"authName,omitempty"`
}

// AgentWire is the agent roster projection.
type AgentWire struct {
	AgentID          string `json:"agentId"`
	DisplayName      string `json:"displayName"`
	Presence         string `json:"presence"`
	WakeupRegistered bool   `json:"wakeupRegistered"`
}

// WakeupRegistrationWire hides the stored secret (never returned).
type WakeupRegistrationWire struct {
	URL             string    `json:"url"`
	DebounceSeconds int       `json:"debounceSeconds"`
	CreatedAt       time.Time `json:"createdAt"`
}

// WakeupDispatchWire is one dispatch-log entry.
type WakeupDispatchWire struct {
	AgentID string    `json:"agentId"`
	At      time.Time `json:"at"`
	Outcome string    `json:"outcome"`
	Note    string    `json:"note,omitempty"`
}

// JoinCredentialsWire carries the out-of-band join secret once, at create.
type JoinCredentialsWire struct {
	NetworkID string `json:"networkId"`
	Password  string `json:"password"`
}

// Page is a generic cursor page.
type Page[T any] struct {
	Items      []T
	NextCursor string
}

// DedupeMentions normalizes a mentions list: trim, drop empties, de-dupe.
func DedupeMentions(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, m := range in {
		if key := strings.TrimSpace(m); key != "" && !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	return out
}
