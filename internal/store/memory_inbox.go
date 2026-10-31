package store

import (
	"context"

	"github.com/IstiN/fa_network/internal/model"
)

// inboxMaxEntries caps the aggregate scan (a human account's network
// footprint; the handler sorts and paginates beyond this).
const inboxMaxEntries = 500

// userChannelsOf returns the channels of every network the user holds a
// membership row in (caller holds m.mu). Membership rows are keyed
// networkID+"\x00"+memberID, and authed members carry the account userID
// as their member id.
func (m *MemStore) userChannelsOf(userID string) []*model.Channel {
	nets := map[string]bool{}
	for _, member := range m.members {
		// Authed members carry the account userID as their member id.
		if member.ID == userID {
			nets[member.NetworkID] = true
		}
	}
	out := make([]*model.Channel, 0, len(m.channels))
	for _, ch := range m.channels {
		if nets[ch.NetworkID] {
			cp := *ch
			out = append(out, &cp)
		}
	}
	return out
}

// ReadCursor implements ReadState.
func (m *MemStore) ReadCursor(_ context.Context, userID, channelID string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.reads[userID][channelID], nil
}

// ChannelMaxSeq implements ReadState.
func (m *MemStore) ChannelMaxSeq(_ context.Context, channelID string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.chanSeq[channelID], nil
}

// MarkRead implements ReadState: monotonic per (user, channel); seq is
// clamped to the channel's current max so a client can never push the
// cursor into the future.
func (m *MemStore) MarkRead(_ context.Context, userID, channelID string, seq int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if seq > m.chanSeq[channelID] {
		seq = m.chanSeq[channelID]
	}
	cur := m.reads[userID][channelID]
	if seq <= cur {
		return nil
	}
	if m.reads[userID] == nil {
		m.reads[userID] = map[string]int64{}
	}
	m.reads[userID][channelID] = seq
	return nil
}

// BaselineRead implements ReadState: no row yet → cursor at the channel's
// current max (unread-0 history on first aggregate fetch); existing rows
// are never touched (monotonicity).
func (m *MemStore) BaselineRead(_ context.Context, userID, channelID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.reads[userID][channelID]; ok {
		return cur, nil
	}
	cur := m.chanSeq[channelID]
	if m.reads[userID] == nil {
		m.reads[userID] = map[string]int64{}
	}
	m.reads[userID][channelID] = cur
	return cur, nil
}

// InboxEntries implements Inbox: every channel conversation of the
// caller's networks with the newest envelope and per-user unread count.
// The first-touch baseline is materialized HERE (cursor at the channel's
// current max when the user has no row) so the returned counts are
// final: no historical unread flood on a new device, new mail counts.
func (m *MemStore) InboxEntries(_ context.Context, userID string) ([]*model.InboxEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	channels := m.userChannelsOf(userID)
	out := make([]*model.InboxEntry, 0, len(channels))
	for _, ch := range channels {
		// Inline baseline (write lock already held).
		if _, ok := m.reads[userID][ch.ID]; !ok {
			if m.reads[userID] == nil {
				m.reads[userID] = map[string]int64{}
			}
			m.reads[userID][ch.ID] = m.chanSeq[ch.ID]
		}
		cursor := m.reads[userID][ch.ID]
		all := m.envs[ch.ID]
		entry := &model.InboxEntry{Channel: ch}
		if n := len(all); n > 0 {
			last := all[n-1]
			cp := last
			cp.Mentions = append([]string(nil), last.Mentions...)
			entry.LastEnvelope = &cp
		}
		for _, e := range all {
			if e.Seq > cursor {
				entry.UnreadCount++
			}
		}
		out = append(out, entry)
		if len(out) >= inboxMaxEntries {
			break
		}
	}
	return out, nil
}

// EnvelopeByID implements Envelopes (ErrNotFound for unknown ids).
func (m *MemStore) EnvelopeByID(_ context.Context, channelID, id string) (*model.Envelope, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.envs[channelID] {
		if e.ID == id {
			cp := e
			cp.Mentions = append([]string(nil), e.Mentions...)
			return &cp, nil
		}
	}
	return nil, notFound("envelope", id)
}
