package store

import (
	"context"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// TestMemStoreDevices covers the Devices contract branches: create,
// lookup by id and by token hash, revocation semantics (revocation ==
// deletion for the auth index; the audit row stays addressable).
func TestMemStoreDevices(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()

	dev := &model.Device{ID: "d1", UserID: "u1", Name: "macbook",
		TokenHash: []byte("hash-1"), CreatedAt: time.Now()}
	if err := s.CreateDevice(ctx, dev); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Duplicate id conflicts.
	if err := s.CreateDevice(ctx, dev); !IsConflict(err) {
		t.Fatalf("dup id = %v, want conflict", err)
	}
	// Token-less devices cannot authenticate: conflict.
	if err := s.CreateDevice(ctx, &model.Device{ID: "d2", UserID: "u1",
		CreatedAt: time.Now()}); !IsConflict(err) {
		t.Fatalf("token-less = %v, want conflict", err)
	}

	got, err := s.Device(ctx, "d1")
	if err != nil || got.UserID != "u1" || string(got.TokenHash) != "hash-1" {
		t.Fatalf("by id: %v %+v", err, got)
	}
	if _, err := s.Device(ctx, "missing"); !IsNotFound(err) {
		t.Fatalf("missing by id = %v, want not found", err)
	}

	byToken, err := s.DeviceByTokenHash(ctx, []byte("hash-1"))
	if err != nil || byToken.ID != "d1" {
		t.Fatalf("by hash: %v %+v", err, byToken)
	}
	if _, err := s.DeviceByTokenHash(ctx, []byte("nope")); !IsNotFound(err) {
		t.Fatalf("unknown hash = %v, want not found", err)
	}

	if _, err := s.DeviceByTokenHash(ctx, []byte("hash-u2")); !IsNotFound(err) {
		t.Fatal("setup: want unknown")
	}
	u2 := &model.Device{ID: "d3", UserID: "u2", TokenHash: []byte("hash-u2"), CreatedAt: time.Now()}
	if err := s.CreateDevice(ctx, u2); err != nil {
		t.Fatalf("create u2: %v", err)
	}
	rows, err := s.DevicesOfUser(ctx, "u1")
	if err != nil || len(rows) != 1 || rows[0].ID != "d1" {
		t.Fatalf("of user: %v %+v", err, rows)
	}

	// Revoke d1: auth index loses it; the row itself reads as revoked.
	if err := s.RevokeDevice(ctx, "d1", time.Now()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.DeviceByTokenHash(ctx, []byte("hash-1")); !IsNotFound(err) {
		t.Fatalf("revoked by hash = %v, want not found", err)
	}
	got, err = s.Device(ctx, "d1")
	if err != nil || got.RevokedAt == nil {
		t.Fatalf("revoked row: %v %+v", err, got)
	}
	if err := s.RevokeDevice(ctx, "missing", time.Now()); !IsNotFound(err) {
		t.Fatalf("revoke missing = %v, want not found", err)
	}
}

// TestMemStorePersonalNetwork covers every PersonalNetwork branch:
// no network at all, shared networks only, foreign personal network,
// and the owned personal network match.
func TestMemStorePersonalNetwork(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()

	// None yet.
	if _, err := s.PersonalNetwork(ctx, "u1"); !IsNotFound(err) {
		t.Fatalf("empty store = %v, want not found", err)
	}
	// A shared network must not match.
	if err := s.CreateNetwork(ctx, &model.Network{ID: "n1", Name: "shared-1",
		OwnerID: "u1", Kind: model.NetworkShared, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create shared: %v", err)
	}
	if _, err := s.PersonalNetwork(ctx, "u1"); !IsNotFound(err) {
		t.Fatalf("shared-only = %v, want not found", err)
	}
	// Another user's personal network must not match.
	if err := s.CreateNetwork(ctx, &model.Network{ID: "n2", Name: "personal-u2",
		OwnerID: "u2", Kind: model.NetworkPersonal, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create foreign personal: %v", err)
	}
	if _, err := s.PersonalNetwork(ctx, "u1"); !IsNotFound(err) {
		t.Fatalf("foreign personal = %v, want not found", err)
	}
	// The match.
	if err := s.CreateNetwork(ctx, &model.Network{ID: "n3", Name: "personal-u1",
		OwnerID: "u1", Kind: model.NetworkPersonal, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create personal: %v", err)
	}
	got, err := s.PersonalNetwork(ctx, "u1")
	if err != nil || got.ID != "n3" || got.Kind != model.NetworkPersonal {
		t.Fatalf("match: %v %+v", err, got)
	}
	// The returned network is a clone: mutating it must not corrupt the
	// store (the server mutates wire copies).
	got.Name = "hacked"
	again, _ := s.PersonalNetwork(ctx, "u1")
	if again.Name == "hacked" {
		t.Fatal("PersonalNetwork leaked store state")
	}
}
