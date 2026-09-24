package store

import (
	"context"
	"errors"
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
		page, err := s.Envelopes(ctx, "c1", "", 3)
		if err != nil || len(page.Items) != 3 || page.NextCursor == "" {
			t.Fatalf("page1: %v %+v", err, page)
		}
		page2, err := s.Envelopes(ctx, "c1", page.NextCursor, 10)
		if err != nil || len(page2.Items) != 2 || page2.NextCursor != "" {
			t.Fatalf("page2: %v %+v", err, page2)
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
}

func TestMemStoreContract(t *testing.T) {
	ContractTest(t, func(t *testing.T) Store {
		t.Helper()
		return NewMemStore()
	})
}
