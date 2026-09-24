package store

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// MemStore is the offline in-memory Store. It backs dev and every test;
// production uses Postgres via the same contract.
type MemStore struct {
	mu         sync.RWMutex
	networks   map[string]*model.Network
	networkSeq int
	members    map[string]*model.Member  // networkID+"\x00"+id
	channels   map[string]*model.Channel // id
	sessions   map[string]*model.Session
	envSeq     int
	envs       map[string][]model.Envelope // channelID -> insertion order
	envIDs     map[string]map[string]bool  // channelID -> seen ids
	wakeups    map[string]*model.WakeupRegistration
	dispatches map[string][]model.WakeupDispatch
	activity   map[string]time.Time // networkID -> last session activity
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		networks:   map[string]*model.Network{},
		members:    map[string]*model.Member{},
		channels:   map[string]*model.Channel{},
		sessions:   map[string]*model.Session{},
		envs:       map[string][]model.Envelope{},
		envIDs:     map[string]map[string]bool{},
		wakeups:    map[string]*model.WakeupRegistration{},
		dispatches: map[string][]model.WakeupDispatch{},
		activity:   map[string]time.Time{},
	}
}

func memberKey(networkID, id string) string { return networkID + "\x00" + id }
func wakeupKey(networkID, agentID string) string {
	return memberKey(networkID, agentID)
}

// CreateNetwork implements Networks.
func (m *MemStore) CreateNetwork(_ context.Context, n *model.Network) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.networks[n.ID]; ok {
		return errIDConflict("network", n.ID)
	}
	if n.Name != "" {
		for _, existing := range m.networks {
			if existing.Name == n.Name {
				return errIDConflict("network name", n.Name)
			}
		}
	}
	if n.ID == "" {
		m.networkSeq++
		n.ID = netID(m.networkSeq)
	}
	m.networks[n.ID] = cloneNetwork(n)
	m.activity[n.ID] = n.CreatedAt
	return nil
}

// Network implements Networks.
func (m *MemStore) Network(_ context.Context, id string) (*model.Network, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.networks[id]
	if !ok {
		return nil, notFound("network", id)
	}
	return cloneNetwork(n), nil
}

// NetworkByName implements Networks.
func (m *MemStore) NetworkByName(_ context.Context, name string) (*model.Network, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, n := range m.networks {
		if n.Name == name {
			return cloneNetwork(n), nil
		}
	}
	return nil, notFound("network", name)
}

// UpdateNetwork implements Networks.
func (m *MemStore) UpdateNetwork(_ context.Context, n *model.Network) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.networks[n.ID]; !ok {
		return notFound("network", n.ID)
	}
	m.networks[n.ID] = cloneNetwork(n)
	return nil
}

// DeleteNetwork implements Networks.
func (m *MemStore) DeleteNetwork(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.networks, id)
	delete(m.activity, id)
	return nil
}

// InactiveNetworks implements Networks.
func (m *MemStore) InactiveNetworks(_ context.Context, cutoff time.Time) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for id, last := range m.activity {
		if last.Before(cutoff) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// AllNetworks implements Networks.
func (m *MemStore) AllNetworks(_ context.Context) ([]*model.Network, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*model.Network, 0, len(m.networks))
	for _, n := range m.networks {
		out = append(out, cloneNetwork(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// TouchActivity implements Store.
func (m *MemStore) TouchActivity(_ context.Context, networkID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activity[networkID] = at
	return nil
}

// DeleteNetworkData implements Store.
func (m *MemStore) DeleteNetworkData(_ context.Context, networkID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteMembersOf(networkID)
	m.deleteChannelsOf(networkID)
	m.deleteSessionsOf(networkID)
	m.deleteWakeupsOf(networkID)
	delete(m.dispatches, networkID)
	delete(m.activity, networkID)
	return nil
}

func (m *MemStore) deleteMembersOf(networkID string) {
	for key := range m.members {
		if hasNetworkPrefix(key, networkID) {
			delete(m.members, key)
		}
	}
}

func (m *MemStore) deleteChannelsOf(networkID string) {
	for id, c := range m.channels {
		if c.NetworkID == networkID {
			delete(m.channels, id)
			delete(m.envs, id)
			delete(m.envIDs, id)
		}
	}
}

func (m *MemStore) deleteSessionsOf(networkID string) {
	for tok, s := range m.sessions {
		if s.NetworkID == networkID {
			delete(m.sessions, tok)
		}
	}
}

func (m *MemStore) deleteWakeupsOf(networkID string) {
	for key := range m.wakeups {
		if hasNetworkPrefix(key, networkID) {
			delete(m.wakeups, key)
		}
	}
}

// Close implements Store.
func (m *MemStore) Close(context.Context) error { return nil }

func errIDConflict(what, id string) error {
	return &ConflictError{What: what, ID: id}
}

// ConflictError is a descriptive ErrConflict wrapper.
type ConflictError struct {
	What string
	ID   string
}

func (e *ConflictError) Error() string { return e.What + " " + e.ID + ": conflict" }
func (e *ConflictError) Unwrap() error { return ErrConflict }

// netID mints sequential network ids for tests and dev.
func netID(seq int) string { return "net-" + strconv.Itoa(seq) }

func cloneNetwork(n *model.Network) *model.Network {
	c := *n
	c.Admins = append([]string(nil), n.Admins...)
	c.PublicChannels = append([]string(nil), n.PublicChannels...)
	c.PasswordHash = append([]byte(nil), n.PasswordHash...)
	c.PasswordSalt = append([]byte(nil), n.PasswordSalt...)
	return &c
}

func hasNetworkPrefix(key, networkID string) bool {
	return len(key) > len(networkID) && key[:len(networkID)] == networkID && key[len(networkID)] == 0
}
