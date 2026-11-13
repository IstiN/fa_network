package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

func TestMemStoreContract(t *testing.T) {
	ContractTest(t, func(t *testing.T) Store {
		t.Helper()
		return NewMemStore()
	})
}

// TestMemStoreInboxContract exercises the aggregate-inbox seam directly
// against the store (server behavior lives in internal/server): scope,
// first-touch baseline, monotonic clamped cursors, EnvelopeByID.
func TestMemStoreInboxContract(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	defer s.Close(ctx)

	// u1 owns a-net (channel ch1), u2 owns b-net (channel ch2) — no leaks.
	n := func(id, owner string) {
		if err := s.CreateNetwork(ctx, &model.Network{
			ID: id, Name: id, OwnerID: owner, CreatedAt: time.Now(),
			PasswordHash: []byte("h"), PasswordSalt: []byte("s"),
		}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	n("a-net", "u1")
	n("b-net", "u2")
	m := func(net, id string) {
		if err := s.UpsertMember(ctx, &model.Member{ID: id, NetworkID: net, Class: model.ClassOwner, DisplayName: id}); err != nil {
			t.Fatalf("member %s/%s: %v", net, id, err)
		}
	}
	m("a-net", "u1")
	m("b-net", "u2")
	ch := func(net, id string) {
		if err := s.CreateChannel(ctx, &model.Channel{ID: id, NetworkID: net}); err != nil {
			t.Fatalf("channel %s: %v", id, err)
		}
	}
	ch("a-net", "ch1")
	ch("b-net", "ch2")

	env := func(channel, id string) {
		if _, err := s.AppendEnvelope(ctx, &model.Envelope{
			ID: id, ChannelID: channel, SenderID: "u1", Payload: "cGF5bG9hZA==", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	env("ch1", "e1")
	env("ch1", "e2")
	env("ch2", "x1")

	// Scope: u1 sees only ch1, u2 only ch2.
	entries, err := s.InboxEntries(ctx, "u1")
	if err != nil || len(entries) != 1 || entries[0].Channel.ID != "ch1" {
		t.Fatalf("u1 entries = %v (%v), want exactly ch1", entries, err)
	}
	first := entries[0]
	// First aggregate fetch anchors unread at the current max: no flood.
	if first.UnreadCount != 0 {
		t.Fatalf("baseline unread = %d, want 0", first.UnreadCount)
	}
	if first.LastEnvelope == nil || first.LastEnvelope.ID != "e2" {
		t.Fatalf("last envelope = %+v, want e2 (opaque payload passthrough)", first.LastEnvelope)
	}
	if first.LastEnvelope.Payload != "cGF5bG9hZA==" {
		t.Fatalf("payload mutated: %q", first.LastEnvelope.Payload)
	}

	// New mail counts; monotonic + clamped cursors.
	env("ch1", "e3")
	if entries, _ = s.InboxEntries(ctx, "u1"); entries[0].UnreadCount != 1 {
		t.Fatalf("unread after e3 = %d, want 1", entries[0].UnreadCount)
	}
	if err := s.MarkRead(ctx, "u1", "ch1", 1); err != nil {
		t.Fatalf("mark read: %v", err)
	}
	if entries, _ = s.InboxEntries(ctx, "u1"); entries[0].UnreadCount != 1 {
		t.Fatalf("older mark-read rewound unread: %d, want 1 (monotonic)", entries[0].UnreadCount)
	}
	// A seq beyond the max is clamped: mail after it still counts.
	if err := s.MarkRead(ctx, "u1", "ch1", 1<<40); err != nil {
		t.Fatalf("mark read clamp: %v", err)
	}
	env("ch1", "e4")
	if entries, _ = s.InboxEntries(ctx, "u1"); entries[0].UnreadCount != 1 {
		t.Fatalf("unread after clamped read + e4 = %d, want 1", entries[0].UnreadCount)
	}

	// Per-user isolation: u1's cursor never touches u2's counts (u2's own
	// baseline applies on their first fetch).
	if entries, _ = s.InboxEntries(ctx, "u2"); len(entries) != 1 || entries[0].Channel.ID != "ch2" {
		t.Fatalf("u2 entries = %v, want exactly ch2", entries)
	}

	// EnvelopeByID: known id in-channel, ErrNotFound for foreign/unknown.
	got, err := s.EnvelopeByID(ctx, "ch1", "e1")
	if err != nil || got.ID != "e1" || got.Seq == 0 {
		t.Fatalf("EnvelopeByID ch1/e1 = %+v (%v), want seq-stamped e1", got, err)
	}
	if _, err = s.EnvelopeByID(ctx, "ch1", "x1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign id (x1 lives in ch2) err = %v, want ErrNotFound", err)
	}
	if _, err = s.EnvelopeByID(ctx, "ch1", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id err = %v, want ErrNotFound", err)
	}
}
