// Package model holds the fa_network domain types shared by the HTTP/WS
// surface, the stores, and the dap hub client. Everything here is
// relay-only: message payloads are opaque ciphertext, never plaintext.
package model

import "time"

// Identity classes carried by session tokens (two-class access ruling).
const (
	ClassOwner  = "owner"
	ClassAdmin  = "admin"
	ClassMember = "member"
	ClassGuest  = "guest"
	ClassAgent  = "agent"
)

// Presence states for members and agents.
const (
	PresenceLive    = "live"
	PresenceBusy    = "busy"
	PresenceOffline = "offline"
)

// Identity is the authenticated principal attached to a request.
type Identity struct {
	ID          string
	Class       string
	DisplayName string
	// AuthName is the locked auth-service name for authed joiners.
	AuthName string
	// NetworkID scopes member-scoped identities to one network.
	NetworkID string
}

// Network is a joinable group of channels and members.
type Network struct {
	ID             string
	Name           string
	OwnerID        string
	Admins         []string
	PublicChannels []string
	CreatedAt      time.Time
	// PasswordHash is scrypt(salt, password), never returned by the API.
	PasswordHash []byte
	PasswordSalt []byte
}

// Member is one identity enrolled in a network.
type Member struct {
	ID          string
	NetworkID   string
	Class       string
	DisplayName string
	Presence    string
}

// Channel is a dap channel mirrored by the relay.
type Channel struct {
	ID            string
	NetworkID     string
	Name          string
	Public        bool
	ACL           []string
	RetentionDays *int
}

// Envelope is an opaque E2E ciphertext message (relay-only invariant).
type Envelope struct {
	ID        string
	ChannelID string
	SenderID  string
	// SenderKey is the sender's X25519 pubkey (base64) when known — public
	// directory material (dap whois), never message content (law #1).
	SenderKey string
	Payload   string
	Mentions  []string
	CreatedAt time.Time
}

// Session is a browser session token issued by join (memory only, E7).
type Session struct {
	Token     string
	NetworkID string
	MemberID  string
	CreatedAt time.Time
	LastSeen  time.Time
}

// WakeupRegistration is the webhook contract for offline wake-ups.
// The dispatch payload is identity-only — never message content (law #3).
type WakeupRegistration struct {
	NetworkID       string
	AgentID         string
	URL             string
	SecretHash      []byte
	DebounceSeconds int
	CreatedAt       time.Time
}

// WakeupDispatch is one audit-trail entry of a wake-up dispatch.
type WakeupDispatch struct {
	AgentID string
	At      time.Time
	Outcome string
	Note    string
}

// Wakeup outcomes for the dispatch log.
const (
	OutcomeDelivered     = "delivered"
	OutcomeTargetDown    = "target_down"
	OutcomeSkippedOnline = "skipped_online"
	OutcomeBackoff       = "backoff"
)
