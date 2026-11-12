package server

import (
	"testing"
	"time"
)

// TestDeviceGraceSweeper covers the degraded → offline inference: the
// grace window holds, expiry flips, online devices never flip.
func TestDeviceGraceSweeper(t *testing.T) {
	e := newDeviceExposure()
	now := time.Now()

	e.SetMachine("d-live", MachineOnline, now)
	e.SetMachine("d-deg", MachineDegraded, now)

	// Within the grace window: nothing flips.
	flipped := e.SweeperTick(now.Add(44 * time.Second))
	if len(flipped) != 0 {
		t.Fatalf("early tick flipped %v", flipped)
	}
	if m, _, _ := e.Roster("d-deg", ""); m != MachineDegraded {
		t.Fatalf("degraded lost early: %q", m)
	}

	// Past the grace window: only the degraded device flips.
	flipped = e.SweeperTick(now.Add(46 * time.Second))
	if len(flipped) != 1 || flipped[0] != "d-deg" {
		t.Fatalf("flipped = %v, want d-deg", flipped)
	}
	if m, _, _ := e.Roster("d-deg", ""); m != MachineOffline {
		t.Fatalf("degraded did not expire: %q", m)
	}
	if m, _, _ := e.Roster("d-live", ""); m != MachineOnline {
		t.Fatalf("online device flipped: %q", m)
	}

	// An offline device stays offline (no double flips).
	if flipped = e.SweeperTick(now.Add(90 * time.Second)); len(flipped) != 0 {
		t.Fatalf("re-flip = %v", flipped)
	}
}
