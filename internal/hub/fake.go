package hub

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// FakeClient is the offline test double for the hub connection. It models
// online/offline transitions, per-channel ordered delivery, and a preset
// presence roster. Not for production.
type FakeClient struct {
	mu       sync.Mutex
	agentID  string
	online   bool
	sent     map[string][]Envelope
	events   chan Event
	presence []PresenceInfo
	joined   map[string]bool
	closed   bool
}

// NewFakeClient returns an online fake with the given relay identity.
func NewFakeClient(agentID string) *FakeClient {
	return &FakeClient{
		agentID: agentID,
		online:  true,
		sent:    map[string][]Envelope{},
		events:  make(chan Event, 64),
		joined:  map[string]bool{},
	}
}

// AgentID implements Client.
func (f *FakeClient) AgentID() string { return f.agentID }

// EnrollAgent implements Client: deterministic fake secret per name.
func (f *FakeClient) EnrollAgent(_ context.Context, name string) (string, error) {
	if !f.Online() {
		return "", fmt.Errorf("hub offline")
	}
	return "fake-secret-" + name, nil
}

// HubURL implements Client.
func (f *FakeClient) HubURL() string { return "ws://fake-hub/ws" }

// Online implements Client.
func (f *FakeClient) Online() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.online
}

// SetOnline flips connectivity, emitting the corresponding transition
// event (AC-B7 test hook).
func (f *FakeClient) SetOnline(v bool) {
	f.mu.Lock()
	was := f.online
	f.online = v
	f.mu.Unlock()
	if was != v {
		kind := EventOffline
		if v {
			kind = EventOnline
		}
		f.emit(Event{Kind: kind, At: time.Now()})
	}
}

// Send implements Client (fails while offline, like the real client).
func (f *FakeClient) Send(_ context.Context, env Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.online {
		return errOffline
	}
	f.sent[env.ChannelID] = append(f.sent[env.ChannelID], env)
	return nil
}

// Sent returns the envelopes delivered for one channel, in order.
func (f *FakeClient) Sent(channelID string) []Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Envelope(nil), f.sent[channelID]...)
}

// Events implements Client.
func (f *FakeClient) Events() <-chan Event { return f.events }

// Join implements Client (records the subscription for assertions).
func (f *FakeClient) Join(_ context.Context, channel string) error {
	f.mu.Lock()
	f.joined[channel] = true
	f.mu.Unlock()
	return nil
}

// Joined returns the channels joined so far (test hook).
func (f *FakeClient) Joined() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.joined))
	for c := range f.joined {
		out = append(out, c)
	}
	return out
}

// EmitPresence emits a presence transition event (test hook for the
// relay's hub-agent name cache).
func (f *FakeClient) EmitPresence(info PresenceInfo) {
	f.emit(Event{Kind: EventPresence, At: time.Now(), AgentID: info.AgentID, Name: info.Name, Online: info.Online})
}

// EmitMsg injects an inbound hub envelope (test hook).
func (f *FakeClient) EmitMsg(env Envelope) {
	f.emit(Event{Kind: EventMsg, At: time.Now(), Msg: &env})
}

// SetPresence replaces the presence roster (test hook).
func (f *FakeClient) SetPresence(p []PresenceInfo) {
	f.mu.Lock()
	f.presence = p
	f.mu.Unlock()
}

// Presence implements Client.
func (f *FakeClient) Presence(context.Context) ([]PresenceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]PresenceInfo(nil), f.presence...), nil
}

// Run implements Client: the fake has no loop, it just idles.
func (f *FakeClient) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Close implements Client.
func (f *FakeClient) Close(context.Context) error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *FakeClient) emit(e Event) {
	f.events <- e
}
