// Package store defines the fa_network persistence contract and its
// implementations. The relay-only invariant holds at this boundary too:
// payloads are stored as opaque ciphertext and never inspected.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// ErrNotFound is returned for every missing-entity lookup (generic 404,
// no existence oracle).
var ErrNotFound = errors.New("not found")

// ErrConflict signals a unique-violation (e.g. network name taken).
var ErrConflict = errors.New("conflict")

// Networks persists networks and their join-secret hashes.
type Networks interface {
	CreateNetwork(ctx context.Context, n *model.Network) error
	Network(ctx context.Context, id string) (*model.Network, error)
	NetworkByName(ctx context.Context, name string) (*model.Network, error)
	UpdateNetwork(ctx context.Context, n *model.Network) error
	DeleteNetwork(ctx context.Context, id string) error
	// InactiveNetworks lists networks with no member-session activity
	// since cutoff (retention sweeper input).
	InactiveNetworks(ctx context.Context, cutoff time.Time) ([]string, error)
	AllNetworks(ctx context.Context) ([]*model.Network, error)
	// PublicNetworks lists opt-in catalog entries keyset-paginated by
	// (createdAt, id): rows strictly after (after, afterID), oldest
	// first. Zero after = first page. Callers pass limit+1 to detect
	// a next page.
	PublicNetworks(ctx context.Context, after time.Time, afterID string, limit int) ([]*model.Network, error)
	// MemberCount reports how many members a network has (catalog stat).
	MemberCount(ctx context.Context, networkID string) (int, error)
}

// Members persists per-network member identities.
type Members interface {
	UpsertMember(ctx context.Context, m *model.Member) error
	Member(ctx context.Context, networkID, memberID string) (*model.Member, error)
	Members(ctx context.Context, networkID string) ([]*model.Member, error)
	MemberByName(ctx context.Context, networkID, displayName string) (*model.Member, error)
	UpdateMemberPresence(ctx context.Context, networkID, memberID, presence string) error
	DeleteMember(ctx context.Context, networkID, memberID string) error
}

// Channels persists channel metadata (retentionDays included).
type Channels interface {
	CreateChannel(ctx context.Context, c *model.Channel) error
	Channel(ctx context.Context, id string) (*model.Channel, error)
	ChannelByName(ctx context.Context, networkID, name string) (*model.Channel, error)
	Channels(ctx context.Context, networkID string) ([]*model.Channel, error)
	UpdateChannel(ctx context.Context, c *model.Channel) error
	DeleteChannel(ctx context.Context, id string) error
	// ChannelsWithRetention lists channels having a retentionDays value
	// (envelope expiry sweep input).
	ChannelsWithRetention(ctx context.Context) ([]*model.Channel, error)
}

// Envelopes persists opaque ciphertext envelopes with id-dedup per channel.
type Envelopes interface {
	// AppendEnvelope stores e unless (channel, id) already exists
	// (at-least-once dedup); returns stored=true when newly written.
	AppendEnvelope(ctx context.Context, e *model.Envelope) (bool, error)
	Envelopes(ctx context.Context, channelID, cursor string, limit int) (*model.Page[model.Envelope], error)
	DeleteEnvelopesBefore(ctx context.Context, channelID string, cutoff time.Time) (int64, error)
	DeleteEnvelopes(ctx context.Context, channelID string) error
	// ChannelBytes is the per-channel stored-byte guard (abuse cap).
	ChannelBytes(ctx context.Context, channelID string) (int64, error)
}

// Sessions persists browser session tokens (activity = retention clock).
type Sessions interface {
	CreateSession(ctx context.Context, s *model.Session) error
	Session(ctx context.Context, token string) (*model.Session, error)
	TouchSession(ctx context.Context, token string, at time.Time) error
	DeleteSession(ctx context.Context, token string) error
	DeleteSessionsOfMember(ctx context.Context, networkID, memberID string) error
	// SessionsOfNetwork lists active sessions (fan-out and drain).
	SessionsOfNetwork(ctx context.Context, networkID string) ([]*model.Session, error)
	DeleteSessionsOfNetwork(ctx context.Context, networkID string) error
}

// Wakeups persists wake-up webhook registrations and the dispatch log.
type Wakeups interface {
	UpsertWakeup(ctx context.Context, w *model.WakeupRegistration) error
	Wakeup(ctx context.Context, networkID, agentID string) (*model.WakeupRegistration, error)
	DeleteWakeup(ctx context.Context, networkID, agentID string) error
	LogDispatch(ctx context.Context, networkID string, d *model.WakeupDispatch) error
	Dispatches(ctx context.Context, networkID, cursor string, limit int) (*model.Page[model.WakeupDispatch], error)
}

// Store composes every persistence facet. One handle per process.
type Store interface {
	Networks
	Members
	Channels
	Envelopes
	Sessions
	Wakeups
	// TouchActivity stamps network session activity (retention clock).
	TouchActivity(ctx context.Context, networkID string, at time.Time) error
	// DeleteNetworkData wipes a whole network (retention cleanup).
	DeleteNetworkData(ctx context.Context, networkID string) error
	// Close releases resources.
	Close(ctx context.Context) error
}

// IsNotFold reports whether err is or wraps ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// IsConflict reports whether err is or wraps ErrConflict.
func IsConflict(err error) bool { return errors.Is(err, ErrConflict) }

func notFound(what, id string) error {
	return fmt.Errorf("%s %q: %w", what, id, ErrNotFound)
}
