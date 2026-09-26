package store

import (
	"context"
	"strconv"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// AppendEnvelope implements Envelopes (id-dedup per channel).
func (m *MemStore) AppendEnvelope(_ context.Context, e *model.Envelope) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := m.envIDs[e.ChannelID]
	if seen == nil {
		seen = map[string]bool{}
		m.envIDs[e.ChannelID] = seen
	}
	if seen[e.ID] {
		return false, nil
	}
	seen[e.ID] = true
	m.envSeq++
	cp := *e
	cp.Mentions = append([]string(nil), e.Mentions...)
	m.envs[e.ChannelID] = append(m.envs[e.ChannelID], cp)
	return true, nil
}

// Envelopes implements Envelopes (ascending order, cursor = envelope seq).
func (m *MemStore) Envelopes(_ context.Context, channelID, before string, limit int) (*model.Page[model.Envelope], error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := m.envs[channelID]
	if limit <= 0 {
		limit = 50
	}
	// Chat order: no cursor = latest page; a cursor is the 1-based seq of
	// the oldest item of the previous page — return the page strictly
	// older than it.
	end := len(all)
	if before != "" {
		n, err := strconv.Atoi(before)
		if err != nil || n < 1 || n > len(all) {
			return nil, notFound("cursor", before)
		}
		end = n - 1
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	page := model.Page[model.Envelope]{Items: []model.Envelope{}}
	for _, e := range all[start:end] {
		cp := e
		cp.Mentions = append([]string(nil), e.Mentions...)
		page.Items = append(page.Items, cp)
	}
	if start > 0 {
		page.NextCursor = strconv.Itoa(start + 1)
	}
	return &page, nil
}

// DeleteEnvelopesBefore implements Envelopes.
func (m *MemStore) DeleteEnvelopesBefore(_ context.Context, channelID string, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.envs[channelID]
	kept := all[:0]
	var dropped int64
	for _, e := range all {
		if e.CreatedAt.Before(cutoff) {
			dropped++
			delete(m.envIDs[channelID], e.ID)
			continue
		}
		kept = append(kept, e)
	}
	m.envs[channelID] = kept
	return dropped, nil
}

// DeleteEnvelopes implements Envelopes.
func (m *MemStore) DeleteEnvelopes(_ context.Context, channelID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.envs, channelID)
	delete(m.envIDs, channelID)
	return nil
}

// ChannelBytes implements Envelopes (abuse guard input).
func (m *MemStore) ChannelBytes(_ context.Context, channelID string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var total int64
	for _, e := range m.envs[channelID] {
		total += int64(len(e.Payload))
	}
	return total, nil
}

// CreateSession implements Sessions.
func (m *MemStore) CreateSession(_ context.Context, s *model.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *s
	m.sessions[s.Token] = &cp
	return nil
}

// Session implements Sessions.
func (m *MemStore) Session(_ context.Context, token string) (*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[token]
	if !ok {
		return nil, notFound("session", token)
	}
	cp := *s
	return &cp, nil
}

// TouchSession implements Sessions.
func (m *MemStore) TouchSession(_ context.Context, token string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[token]
	if !ok {
		return notFound("session", token)
	}
	s.LastSeen = at
	return nil
}

// DeleteSession implements Sessions.
func (m *MemStore) DeleteSession(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
	return nil
}

// DeleteSessionsOfMember implements Sessions.
func (m *MemStore) DeleteSessionsOfMember(_ context.Context, networkID, memberID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	deleteMatching(m.sessions, func(s *model.Session) bool {
		return s.NetworkID == networkID && s.MemberID == memberID
	})
	return nil
}

func deleteMatching[V any](m map[string]V, match func(V) bool) {
	for key, v := range m {
		if match(v) {
			delete(m, key)
		}
	}
}

// SessionsOfNetwork implements Sessions.
func (m *MemStore) SessionsOfNetwork(_ context.Context, networkID string) ([]*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*model.Session
	for _, s := range m.sessions {
		if s.NetworkID == networkID {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

// DeleteSessionsOfNetwork implements Sessions.
func (m *MemStore) DeleteSessionsOfNetwork(_ context.Context, networkID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tok, s := range m.sessions {
		if s.NetworkID == networkID {
			delete(m.sessions, tok)
		}
	}
	return nil
}

// UpsertWakeup implements Wakeups.
func (m *MemStore) UpsertWakeup(_ context.Context, w *model.WakeupRegistration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *w
	cp.SecretHash = append([]byte(nil), w.SecretHash...)
	m.wakeups[wakeupKey(w.NetworkID, w.AgentID)] = &cp
	return nil
}

// Wakeup implements Wakeups.
func (m *MemStore) Wakeup(_ context.Context, networkID, agentID string) (*model.WakeupRegistration, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	w, ok := m.wakeups[wakeupKey(networkID, agentID)]
	if !ok {
		return nil, notFound("wakeup", agentID)
	}
	cp := *w
	return &cp, nil
}

// DeleteWakeup implements Wakeups.
func (m *MemStore) DeleteWakeup(_ context.Context, networkID, agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.wakeups, wakeupKey(networkID, agentID))
	return nil
}

// LogDispatch implements Wakeups.
func (m *MemStore) LogDispatch(_ context.Context, networkID string, d *model.WakeupDispatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dispatches[networkID] = append(m.dispatches[networkID], *d)
	return nil
}

// Dispatches implements Wakeups.
func (m *MemStore) Dispatches(_ context.Context, networkID, cursor string, limit int) (*model.Page[model.WakeupDispatch], error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := m.dispatches[networkID]
	start := 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil || n < 0 || n > len(all) {
			return nil, notFound("cursor", cursor)
		}
		start = n
	}
	if limit <= 0 {
		limit = 50
	}
	page := model.Page[model.WakeupDispatch]{Items: []model.WakeupDispatch{}}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	page.Items = append(page.Items, all[start:end]...)
	if end < len(all) {
		page.NextCursor = strconv.Itoa(end)
	}
	return &page, nil
}
