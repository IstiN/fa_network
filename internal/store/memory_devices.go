package store

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// MemStore device registry: devices of every user in one map, token
// hashes never reversed. Personal networks reuse the networks map.
//
// devicesMu guards the device maps independently of MemStore.mu so
// device auth (hot WS path) never contends with envelope writes.
type deviceRegistry struct {
	mu      sync.RWMutex
	byID    map[string]*model.Device
	byToken map[string]string // tokenHash-hex -> deviceID
}

func newDeviceRegistry() *deviceRegistry {
	return &deviceRegistry{
		byID:    map[string]*model.Device{},
		byToken: map[string]string{},
	}
}

func cloneDevice(d *model.Device) *model.Device {
	c := *d
	hash := make([]byte, len(d.TokenHash))
	copy(hash, d.TokenHash)
	c.TokenHash = hash
	if d.RevokedAt != nil {
		t := *d.RevokedAt
		c.RevokedAt = &t
	}
	return &c
}

func (r *deviceRegistry) create(d *model.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[d.ID]; ok {
		return ErrConflict
	}
	if len(d.TokenHash) == 0 {
		return ErrConflict // token-less devices cannot authenticate
	}
	r.byID[d.ID] = cloneDevice(d)
	r.byToken[tokenKey(d.TokenHash)] = d.ID
	return nil
}

func (r *deviceRegistry) byIDLookup(id string) (*model.Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.byID[id]
	if !ok {
		return nil, false
	}
	return cloneDevice(d), true
}

func (r *deviceRegistry) byTokenLookup(hash []byte) (*model.Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byToken[tokenKey(hash)]
	if !ok {
		return nil, false
	}
	d := r.byID[id]
	if d.RevokedAt != nil {
		return nil, false // revocation == deletion for auth
	}
	return cloneDevice(d), true
}

func (r *deviceRegistry) ofUser(userID string) []*model.Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*model.Device
	for _, d := range r.byID {
		if d.UserID == userID {
			out = append(out, cloneDevice(d))
		}
	}
	return out
}

func (r *deviceRegistry) revoke(id string, at time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.byID[id]
	if !ok {
		return false
	}
	t := at.UTC()
	d.RevokedAt = &t
	delete(r.byToken, tokenKey(d.TokenHash))
	return true
}

// tokenKey is the map key for a token hash (hex of the raw bytes).
func tokenKey(hash []byte) string { return strings.ToLower(hexEncode(hash)) }

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&0x0f])
	}
	return string(out)
}

// CreateDevice implements Devices.
func (m *MemStore) CreateDevice(_ context.Context, d *model.Device) error {
	return m.devices.create(d)
}

// Device implements Devices.
func (m *MemStore) Device(_ context.Context, deviceID string) (*model.Device, error) {
	d, ok := m.devices.byIDLookup(deviceID)
	if !ok {
		return nil, notFound("device", deviceID)
	}
	return d, nil
}

// DeviceByTokenHash implements Devices.
func (m *MemStore) DeviceByTokenHash(_ context.Context, hash []byte) (*model.Device, error) {
	d, ok := m.devices.byTokenLookup(hash)
	if !ok {
		return nil, notFound("device", "token")
	}
	return d, nil
}

// DevicesOfUser implements Devices.
func (m *MemStore) DevicesOfUser(_ context.Context, userID string) ([]*model.Device, error) {
	return m.devices.ofUser(userID), nil
}

// RevokeDevice implements Devices.
func (m *MemStore) RevokeDevice(_ context.Context, deviceID string, at time.Time) error {
	if !m.devices.revoke(deviceID, at) {
		return notFound("device", deviceID)
	}
	return nil
}

// PersonalNetwork implements Networks: the user's auto-provisioned
// personal network (machine-connector contract §2), ErrNotFound when
// none exists yet.
func (m *MemStore) PersonalNetwork(_ context.Context, userID string) (*model.Network, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, n := range m.networks {
		if n.Kind == model.NetworkPersonal && n.OwnerID == userID {
			return cloneNetwork(n), nil
		}
	}
	return nil, notFound("personal network", userID)
}
