package store

import (
	"context"
	"strings"

	"github.com/IstiN/fa_network/internal/model"
)

// UpsertMember implements Members.
func (m *MemStore) UpsertMember(_ context.Context, mem *model.Member) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.members[memberKey(mem.NetworkID, mem.ID)] = cloneMember(mem)
	return nil
}

// Member implements Members.
func (m *MemStore) Member(_ context.Context, networkID, id string) (*model.Member, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	mem, ok := m.members[memberKey(networkID, id)]
	if !ok {
		return nil, notFound("member", id)
	}
	return cloneMember(mem), nil
}

// Members implements Members.
func (m *MemStore) Members(_ context.Context, networkID string) ([]*model.Member, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*model.Member
	for key, mem := range m.members {
		if hasNetworkPrefix(key, networkID) {
			out = append(out, cloneMember(mem))
		}
	}
	sortMembers(out)
	return out, nil
}

// MemberByName implements Members (exact displayName match).
func (m *MemStore) MemberByName(_ context.Context, networkID, displayName string) (*model.Member, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for key, mem := range m.members {
		if hasNetworkPrefix(key, networkID) && mem.DisplayName == displayName {
			return cloneMember(mem), nil
		}
	}
	return nil, notFound("member", displayName)
}

// UpdateMemberPresence implements Members.
func (m *MemStore) UpdateMemberPresence(_ context.Context, networkID, id, presence string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mem, ok := m.members[memberKey(networkID, id)]
	if !ok {
		return notFound("member", id)
	}
	mem.Presence = presence
	return nil
}

// DeleteMember implements Members.
func (m *MemStore) DeleteMember(_ context.Context, networkID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.members, memberKey(networkID, id))
	return nil
}

func cloneMember(mem *model.Member) *model.Member {
	c := *mem
	return &c
}

func sortMembers(in []*model.Member) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j-1].ID > in[j].ID; j-- {
			in[j-1], in[j] = in[j], in[j-1]
		}
	}
}

// CreateChannel implements Channels.
func (m *MemStore) CreateChannel(_ context.Context, c *model.Channel) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.channels[c.ID]; ok {
		return errIDConflict("channel", c.ID)
	}
	if c.ID == "" {
		c.ID = chanID(c.NetworkID, c.Name)
	}
	m.channels[c.ID] = cloneChannel(c)
	return nil
}

// Channel implements Channels.
func (m *MemStore) Channel(_ context.Context, id string) (*model.Channel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.channels[id]
	if !ok {
		return nil, notFound("channel", id)
	}
	return cloneChannel(c), nil
}

// ChannelByName implements Channels.
func (m *MemStore) ChannelByName(_ context.Context, networkID, name string) (*model.Channel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.findChannelByName(networkID, name)
}

func (m *MemStore) findChannelByName(networkID, name string) (*model.Channel, error) {
	for _, c := range m.channels {
		if channelMatches(c, networkID, name) {
			return cloneChannel(c), nil
		}
	}
	return nil, notFound("channel", name)
}

func channelMatches(c *model.Channel, networkID, name string) bool {
	return c.NetworkID == networkID && c.Name == name
}

// Channels implements Channels.
func (m *MemStore) Channels(_ context.Context, networkID string) ([]*model.Channel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*model.Channel
	for _, c := range m.channels {
		if c.NetworkID == networkID {
			out = append(out, cloneChannel(c))
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].ID > out[j].ID; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, nil
}

// UpdateChannel implements Channels.
func (m *MemStore) UpdateChannel(_ context.Context, c *model.Channel) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.channels[c.ID]; !ok {
		return notFound("channel", c.ID)
	}
	m.channels[c.ID] = cloneChannel(c)
	return nil
}

// DeleteChannel implements Channels.
func (m *MemStore) DeleteChannel(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.channels, id)
	delete(m.envs, id)
	delete(m.envIDs, id)
	return nil
}

// ChannelsWithRetention implements Channels.
func (m *MemStore) ChannelsWithRetention(_ context.Context) ([]*model.Channel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*model.Channel
	for _, c := range m.channels {
		if c.RetentionDays != nil {
			out = append(out, cloneChannel(c))
		}
	}
	return out, nil
}

func cloneChannel(c *model.Channel) *model.Channel {
	cp := *c
	cp.ACL = append([]string(nil), c.ACL...)
	if c.RetentionDays != nil {
		d := *c.RetentionDays
		cp.RetentionDays = &d
	}
	return &cp
}

func chanID(networkID, name string) string {
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\x00", "-")
	return networkID + "/" + replacer.Replace(name)
}
