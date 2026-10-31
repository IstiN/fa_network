package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// ContractTest runs the Store contract against any implementation.
// The relay-only property (opaque payloads survive untouched) is part of
// the contract: payloads must round-trip byte-identical.
func ContractTest(t *testing.T, newStore func(t *testing.T) Store) {
	t.Helper()
	ctx := context.Background()

	t.Run("network CRUD and name uniqueness", func(t *testing.T) {
		s := newStore(t)
		defer s.Close(ctx)
		n := &model.Network{ID: "n1", Name: "fa-team", OwnerID: "u1", CreatedAt: time.Now()}
		if err := s.CreateNetwork(ctx, n); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := s.Network(ctx, "n1")
		if err != nil || got.Name != "fa-team" {
			t.Fatalf("get: %v %+v", err, got)
		}
		byName, err := s.NetworkByName(ctx, "fa-team")
		if err != nil || byName.ID != "n1" {
			t.Fatalf("byName: %v %+v", err, byName)
		}
		dup := &model.Network{ID: "n2", Name: "fa-team", OwnerID: "u2", CreatedAt: time.Now()}
		if err := s.CreateNetwork(ctx, dup); !IsConflict(err) {
			t.Fatalf("dup name err = %v, want conflict", err)
		}
		if err := s.DeleteNetwork(ctx, "n1"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := s.Network(ctx, "n1"); !IsNotFound(err) {
			t.Fatalf("get after delete err = %v, want not found", err)
		}
	})

	t.Run("members and presence", func(t *testing.T) {
		s := newStore(t)
		defer s.Close(ctx)
		m := &model.Member{ID: "m1", NetworkID: "n1", Class: model.ClassGuest, DisplayName: "bot", Presence: model.PresenceOffline}
		if err := s.UpsertMember(ctx, m); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := s.UpdateMemberPresence(ctx, "n1", "m1", model.PresenceLive); err != nil {
			t.Fatalf("presence: %v", err)
		}
		got, err := s.Member(ctx, "n1", "m1")
		if err != nil || got.Presence != model.PresenceLive {
			t.Fatalf("get: %v %+v", err, got)
		}
		byName, err := s.MemberByName(ctx, "n1", "bot")
		if err != nil || byName.ID != "m1" {
			t.Fatalf("byName: %v %+v", err, byName)
		}
		list, err := s.Members(ctx, "n1")
		if err != nil || len(list) != 1 {
			t.Fatalf("list: %v %d", err, len(list))
		}
	})

	t.Run("channels", func(t *testing.T) {
		s := newStore(t)
		defer s.Close(ctx)
		days := 7
		c := &model.Channel{NetworkID: "n1", Name: "general", RetentionDays: &days}
		if err := s.CreateChannel(ctx, c); err != nil {
			t.Fatalf("create: %v", err)
		}
		if c.ID == "" {
			t.Fatal("id not assigned")
		}
		got, err := s.Channel(ctx, c.ID)
		if err != nil || got.Name != "general" || *got.RetentionDays != 7 {
			t.Fatalf("get: %v %+v", err, got)
		}
		withRet, err := s.ChannelsWithRetention(ctx)
		if err != nil || len(withRet) != 1 {
			t.Fatalf("withRetention: %v %d", err, len(withRet))
		}
		list, err := s.Channels(ctx, "n1")
		if err != nil || len(list) != 1 {
			t.Fatalf("list: %v %d", err, len(list))
		}
	})

	t.Run("envelopes dedup order pagination and retention", func(t *testing.T) {
		s := newStore(t)
		defer s.Close(ctx)
		base := time.Now().Add(-time.Hour)
		mk := func(i int, at time.Time) *model.Envelope {
			return &model.Envelope{
				ID:        "e" + string(rune('0'+i)),
				ChannelID: "c1",
				SenderID:  "m1",
				Payload:   "Y2lwaGVydGV4dA==", // base64 ciphertext, relay-only
				CreatedAt: at,
			}
		}
		for i := 0; i < 5; i++ {
			stored, err := s.AppendEnvelope(ctx, mk(i, base.Add(time.Duration(i)*time.Minute)))
			if err != nil || !stored {
				t.Fatalf("append %d: %v stored=%v", i, err, stored)
			}
		}
		dup := mk(2, base)
		dup.Payload = "REDACTED" // same id → dedup must win, payload ignored
		stored, err := s.AppendEnvelope(ctx, dup)
		if err != nil || stored {
			t.Fatalf("dup append: %v stored=%v", err, stored)
		}
		// Chat order: no cursor = LATEST page; the cursor walks to older
		// pages; items are ascending within each page.
		page, err := s.Envelopes(ctx, "c1", "", 3)
		if err != nil || len(page.Items) != 3 || page.NextCursor == "" {
			t.Fatalf("page1: %v %+v", err, page)
		}
		page2, err := s.Envelopes(ctx, "c1", page.NextCursor, 10)
		if err != nil || len(page2.Items) != 2 || page2.NextCursor != "" {
			t.Fatalf("page2: %v %+v", err, page2)
		}
		ids := func(page *model.Page[model.Envelope]) []string {
			out := make([]string, 0, len(page.Items))
			for _, e := range page.Items {
				out = append(out, e.ID)
			}
			return out
		}
		if got := ids(page); fmt.Sprint(got) != "[e2 e3 e4]" {
			t.Fatalf("latest page = %v, want [e2 e3 e4]", got)
		}
		if got := ids(page2); fmt.Sprint(got) != "[e0 e1]" {
			t.Fatalf("cursor page = %v, want [e0 e1]", got)
		}
		// Relay-only: payloads round-trip untouched.
		if page.Items[0].Payload != "Y2lwaGVydGV4dA==" {
			t.Fatalf("payload mutated: %q", page.Items[0].Payload)
		}
		n, err := s.DeleteEnvelopesBefore(ctx, "c1", base.Add(2*time.Minute))
		if err != nil || n != 2 {
			t.Fatalf("deleteBefore: %v n=%d", err, n)
		}
		left, err := s.Envelopes(ctx, "c1", "", 10)
		if err != nil || len(left.Items) != 3 {
			t.Fatalf("left: %v %d", err, len(left.Items))
		}
	})

	t.Run("sessions", func(t *testing.T) {
		s := newStore(t)
		defer s.Close(ctx)
		sess := &model.Session{Token: "tok", NetworkID: "n1", MemberID: "m1", CreatedAt: time.Now(), LastSeen: time.Now()}
		if err := s.CreateSession(ctx, sess); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := s.Session(ctx, "tok")
		if err != nil || got.MemberID != "m1" {
			t.Fatalf("get: %v %+v", err, got)
		}
		later := time.Now()
		if err := s.TouchSession(ctx, "tok", later); err != nil {
			t.Fatalf("touch: %v", err)
		}
		got, _ = s.Session(ctx, "tok")
		if !got.LastSeen.Equal(later) {
			t.Fatalf("touch not persisted: %v", got.LastSeen)
		}
		list, err := s.SessionsOfNetwork(ctx, "n1")
		if err != nil || len(list) != 1 {
			t.Fatalf("list: %v %d", err, len(list))
		}
	})

	t.Run("wakeups and dispatch log", func(t *testing.T) {
		s := newStore(t)
		defer s.Close(ctx)
		w := &model.WakeupRegistration{NetworkID: "n1", AgentID: "a1", URL: "https://hook", DebounceSeconds: 60, CreatedAt: time.Now(), SecretHash: []byte("h")}
		if err := s.UpsertWakeup(ctx, w); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		got, err := s.Wakeup(ctx, "n1", "a1")
		if err != nil || got.URL != "https://hook" {
			t.Fatalf("get: %v %+v", err, got)
		}
		if err := s.LogDispatch(ctx, "n1", &model.WakeupDispatch{AgentID: "a1", At: time.Now(), Outcome: model.OutcomeDelivered}); err != nil {
			t.Fatalf("log: %v", err)
		}
		log, err := s.Dispatches(ctx, "n1", "", 10)
		if err != nil || len(log.Items) != 1 || log.Items[0].Outcome != model.OutcomeDelivered {
			t.Fatalf("log page: %v %+v", err, log)
		}
		if _, err := s.Wakeup(ctx, "n1", "nope"); !IsNotFound(err) {
			t.Fatalf("missing wakeup err = %v, want not found", err)
		}
	})

	t.Run("activity and network wipe", func(t *testing.T) {
		s := newStore(t)
		defer s.Close(ctx)
		n := &model.Network{ID: "n1", Name: "old-net", CreatedAt: time.Now().Add(-40 * 24 * time.Hour)}
		if err := s.CreateNetwork(ctx, n); err != nil {
			t.Fatalf("create: %v", err)
		}
		stale := time.Now().Add(-40 * 24 * time.Hour)
		if err := s.TouchActivity(ctx, "n1", stale); err != nil {
			t.Fatalf("touch: %v", err)
		}
		cutoff := time.Now().Add(-30 * 24 * time.Hour)
		inactive, err := s.InactiveNetworks(ctx, cutoff)
		if err != nil || len(inactive) != 1 {
			t.Fatalf("inactive: %v %v", err, inactive)
		}
		_ = s.UpsertMember(ctx, &model.Member{ID: "m1", NetworkID: "n1", DisplayName: "x"})
		if err := s.DeleteNetworkData(ctx, "n1"); err != nil {
			t.Fatalf("wipe: %v", err)
		}
		if _, err := s.Member(ctx, "n1", "m1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("member after wipe err = %v", err)
		}
		inactive, _ = s.InactiveNetworks(ctx, cutoff)
		if len(inactive) != 0 {
			t.Fatalf("activity not cleared: %v", inactive)
		}
	})

	t.Run("public catalog pagination and member count", func(t *testing.T) {
		s := newStore(t)
		defer s.Close(ctx)
		base := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
		mk := func(id, name string, at time.Time, public bool) {
			n := &model.Network{ID: id, Name: name, OwnerID: "u1", Public: public, CreatedAt: at}
			if err := s.CreateNetwork(ctx, n); err != nil {
				t.Fatalf("create %s: %v", id, err)
			}
		}
		mk("c1", "pub-one", base, true)
		mk("c2", "priv-two", base.Add(time.Second), false)
		mk("c3", "pub-three", base.Add(2*time.Second), true)

		// Only opted-in networks, chronological order.
		page, err := s.PublicNetworks(ctx, time.Time{}, "", 10)
		if err != nil {
			t.Fatalf("catalog: %v", err)
		}
		if len(page) != 2 || page[0].ID != "c1" || page[1].ID != "c3" {
			t.Fatalf("catalog = %v, want [c1 c3]", idsOf(page))
		}

		// Keyset: continue strictly after the first entry.
		rest, err := s.PublicNetworks(ctx, page[0].CreatedAt, page[0].ID, 10)
		if err != nil {
			t.Fatalf("catalog cursor: %v", err)
		}
		if len(rest) != 1 || rest[0].ID != "c3" {
			t.Fatalf("cursor page = %v, want [c3]", idsOf(rest))
		}

		// Public flag round-trips through UpdateNetwork.
		n, err := s.Network(ctx, "c2")
		if err != nil {
			t.Fatalf("get c2: %v", err)
		}
		n.Public = true
		if err := s.UpdateNetwork(ctx, n); err != nil {
			t.Fatalf("update c2: %v", err)
		}
		afterToggle, _ := s.PublicNetworks(ctx, time.Time{}, "", 10)
		if len(afterToggle) != 3 {
			t.Fatalf("catalog after toggle = %v, want 3 entries", idsOf(afterToggle))
		}

		// MemberCount reflects the roster.
		for _, m := range []*model.Member{
			{ID: "m1", NetworkID: "c1", Class: model.ClassOwner, DisplayName: "o"},
			{ID: "m2", NetworkID: "c1", Class: model.ClassGuest, DisplayName: "g"},
		} {
			if err := s.UpsertMember(ctx, m); err != nil {
				t.Fatalf("upsert member: %v", err)
			}
		}
		count, err := s.MemberCount(ctx, "c1")
		if err != nil || count != 2 {
			t.Fatalf("memberCount = %d, %v; want 2", count, err)
		}
		empty, err := s.MemberCount(ctx, "c3")
		if err != nil || empty != 0 {
			t.Fatalf("empty memberCount = %d, %v; want 0", empty, err)
		}
	})

	t.Run("account networks discovery", func(t *testing.T) {
		s := newStore(t)
		defer s.Close(ctx)
		base := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
		mk := func(id, name string, at time.Time, public bool, owner string) {
			n := &model.Network{
				ID: id, Name: name, OwnerID: owner, Public: public, CreatedAt: at,
				PasswordHash: []byte("h"), PasswordSalt: []byte("s"),
			}
			if err := s.CreateNetwork(ctx, n); err != nil {
				t.Fatalf("create %s: %v", id, err)
			}
		}
		// b-net and c-net share a createdAt: id DESC is the tie-break.
		mk("b-net", "beta", base, false, "u1")
		mk("a-net", "alpha", base.Add(time.Second), true, "u1")
		mk("c-net", "gamma", base, false, "u2")
		join := func(networkID, userID, class string) {
			m := &model.Member{ID: userID, NetworkID: networkID, Class: class, DisplayName: userID}
			if err := s.UpsertMember(ctx, m); err != nil {
				t.Fatalf("upsert %s/%s: %v", networkID, userID, err)
			}
		}
		join("b-net", "u1", model.ClassOwner)
		join("a-net", "u1", model.ClassAdmin)
		join("b-net", "guest-x", model.ClassGuest)

		// Every membership row of u1, newest network first, id DESC tie.
		got, err := s.AccountNetworks(ctx, "u1")
		if err != nil {
			t.Fatalf("account networks: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("rows = %v, want 2 (private + public alike)", accountIDs(got))
		}
		if got[0].Network.ID != "a-net" || got[1].Network.ID != "b-net" {
			t.Fatalf("order = %v, want [a-net b-net] (createdAt DESC, id DESC)", accountIDs(got))
		}
		if got[0].MemberClass != model.ClassAdmin || !got[0].Network.Public {
			t.Fatalf("a-net row = %+v, want admin/public", got[0])
		}
		if got[1].MemberClass != model.ClassOwner || got[1].Network.Public {
			t.Fatalf("b-net row = %+v, want owner/private", got[1])
		}

		// A guest-class row is listed too when it carries the user id.
		guestRows, err := s.AccountNetworks(ctx, "guest-x")
		if err != nil || len(guestRows) != 1 || guestRows[0].Network.ID != "b-net" ||
			guestRows[0].MemberClass != model.ClassGuest {
			t.Fatalf("guest rows: %v %v", guestRows, err)
		}

		// Ownership alone (no membership row, e.g. row deleted) lists
		// nothing — the API seeds an owner row on create, so owners do
		// not rely on this fallback.
		foreign, err := s.AccountNetworks(ctx, "u2")
		if err != nil || len(foreign) != 0 {
			t.Fatalf("u2 rows = %v %v, want none (no membership row)", accountIDs(foreign), err)
		}

		// Deleting the membership drops the network from the listing.
		if err := s.DeleteMember(ctx, "b-net", "u1"); err != nil {
			t.Fatalf("delete member: %v", err)
		}
		after, err := s.AccountNetworks(ctx, "u1")
		if err != nil || len(after) != 1 || after[0].Network.ID != "a-net" {
			t.Fatalf("after delete = %v %v, want [a-net]", accountIDs(after), err)
		}
	})
}

// idsOf projects network ids for test diagnostics.
func idsOf(networks []*model.Network) []string {
	out := make([]string, 0, len(networks))
	for _, n := range networks {
		out = append(out, n.ID)
	}
	return out
}

// accountIDs projects account-network ids for test diagnostics.
func accountIDs(rows []*model.AccountNetwork) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Network.ID)
	}
	return out
}

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
