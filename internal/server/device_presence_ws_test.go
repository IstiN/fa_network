package server

import (
	"testing"

	"github.com/IstiN/fa_network/internal/model"
	"github.com/coder/websocket"
)

// TestDeviceWSRosterSnapshotCarriesMachines: the device-WS roster
// snapshot must include the machines of the device's networks with
// server-inferred presence (contract §4/§5) — REST parity, self
// included (the client filters).
func TestDeviceWSRosterSnapshotCarriesMachines(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	devA := enrollDevice(t, env, jwt, "macbook")
	devB := enrollDevice(t, env, jwt, "cli-box")

	if rec := env.do("PATCH", "/api/devices/"+devB.DeviceID+"/name",
		map[string]any{"name": "MacBook Pro"}, jwt); rec.Code != 200 {
		t.Fatalf("rename status = %d", rec.Code)
	}

	dcA := dialDeviceWS(t, env, devA.DeviceToken)
	roster := dcA.hello(devA.DeviceID, 1)
	if len(roster) == 0 || roster[0].Network == "" {
		t.Fatal("hello must produce a roster snapshot")
	}
	if len(roster[0].Devices) != 2 {
		t.Fatalf("snapshot machines = %+v, want both devices", roster[0].Devices)
	}
	byID := map[string]networkDeviceRosterWire{}
	for _, d := range roster[0].Devices {
		byID[d.DeviceID] = d
	}
	a, okA := byID[devA.DeviceID]
	b, okB := byID[devB.DeviceID]
	if !okA || !okB {
		t.Fatalf("snapshot missing machines: %+v", roster[0].Devices)
	}
	if a.Presence != MachineOnline {
		t.Fatalf("self machine = %q, want online", a.Presence)
	}
	if b.Presence != MachineOffline {
		t.Fatalf("idle machine = %q, want offline", b.Presence)
	}
	if b.FriendlyName != "MacBook Pro" {
		t.Fatalf("machine friendlyName = %q", b.FriendlyName)
	}
}

// TestDeviceWSPresenceFrameUpdatesProjection: a kind=presence frame
// from the connector updates the same server-side projection as the
// REST roster patch (merge semantics).
func TestDeviceWSPresenceFrameUpdatesProjection(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	var mine struct {
		Items []model.AccountNetworkWire `json:"items"`
	}
	decodeBody(t, env.do("GET", "/api/networks/mine", nil, jwt), &mine)

	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)
	dc.send(deviceFrame{
		V: 1, Kind: kindPresence, MsgID: "pr-1",
		Agents:   []deviceAgentWire{{Name: "alf", State: "live", Exposed: true}},
		Sessions: []deviceSessionWire{{ID: "s1", State: SessionLive, Networks: []string{mine.Items[0].ID}}},
	})
	// The server reads frames sequentially on this socket: waiting for
	// the pong of a follow-up ping proves the presence frame has been
	// applied before the REST read (no sleeps).
	dc.send(deviceFrame{V: 1, Kind: "ping", MsgID: "barrier-1"})
	if f := dc.next("pong"); f.RefID != "barrier-1" {
		t.Fatalf("barrier pong refId = %q", f.RefID)
	}

	rec := env.do("GET", "/api/networks/"+mine.Items[0].ID+"/devices", nil, jwt)
	var roster struct {
		Devices []networkDeviceRosterWire `json:"devices"`
	}
	decodeBody(t, rec, &roster)
	if len(roster.Devices) != 1 {
		t.Fatalf("roster = %+v", roster.Devices)
	}
	d := roster.Devices[0]
	if len(d.Agents) != 1 || d.Agents[0].Name != "alf" || !d.Agents[0].Exposed {
		t.Fatalf("agents = %+v", d.Agents)
	}
	if len(d.Sessions) != 1 || d.Sessions[0].ID != "s1" {
		t.Fatalf("sessions = %+v", d.Sessions)
	}
}

// TestDeviceWSMachineFlipFanout: when a device's machine state flips,
// live sibling sockets sharing a network receive the presence frame
// (dial → online reaches later dials via the snapshot; clean close →
// offline is pushed).
// closeWS closes the socket cleanly (close frame) — the server infers
// offline immediately.
func (c *deviceWSClient) closeWS() {
	_ = c.conn.Close(websocket.StatusNormalClosure, "test done")
}

func TestDeviceWSMachineFlipFanout(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	devA := enrollDevice(t, env, jwt, "macbook")
	devB := enrollDevice(t, env, jwt, "cli-box")

	dcB := dialDeviceWS(t, env, devB.DeviceToken)
	dcB.hello(devB.DeviceID, 1)

	// A dials: B must receive the online flip.
	dcA := dialDeviceWS(t, env, devA.DeviceToken)
	flip := dcB.next("presence")
	if len(flip.Devices) != 1 || flip.Devices[0].DeviceID != devA.DeviceID ||
		flip.Devices[0].Presence != MachineOnline {
		t.Fatalf("online flip = %+v", flip.Devices)
	}
	if flip.Network == "" {
		t.Fatal("flip frame must carry its network id")
	}

	// A closes cleanly: B must receive the offline flip.
	dcA.closeWS()
	flip = dcB.next("presence")
	if len(flip.Devices) != 1 || flip.Devices[0].DeviceID != devA.DeviceID ||
		flip.Devices[0].Presence != MachineOffline {
		t.Fatalf("offline flip = %+v", flip.Devices)
	}
}

// TestDisplayStringSanitization: client-declared display strings
// (enroll name/platform, friendlyName, roster session title/path)
// reject control characters and bidi overrides — the UI renders them
// verbatim. WS presence frames skip invalid entries (no 400 channel).
func TestDisplayStringSanitization(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")

	// Enroll: RTL override in name → 400; control char in platform → 400.
	if rec := env.do("POST", "/api/devices/enroll",
		map[string]any{"name": "box\u202Eevil"}, jwt); rec.Code != 400 {
		t.Fatalf("bidi name status = %d, want 400", rec.Code)
	}
	if rec := env.do("POST", "/api/devices/enroll",
		map[string]any{"name": "ok", "platform": "da\x00rwin"}, jwt); rec.Code != 400 {
		t.Fatalf("control platform status = %d, want 400", rec.Code)
	}

	dev := enrollDevice(t, env, jwt, "macbook")

	// Rename with control char → 400.
	if rec := env.do("PATCH", "/api/devices/"+dev.DeviceID+"/name",
		map[string]any{"name": "x\x1b[31m"}, jwt); rec.Code != 400 {
		t.Fatalf("control friendlyName status = %d, want 400", rec.Code)
	}

	// Roster PATCH with bidi title → 400.
	var mine struct {
		Items []model.AccountNetworkWire `json:"items"`
	}
	decodeBody(t, env.do("GET", "/api/networks/mine", nil, jwt), &mine)
	if rec := env.do("PATCH", "/api/devices/"+dev.DeviceID+"/roster",
		map[string]any{"sessions": []map[string]any{
			{"id": "s", "state": "live", "networks": []string{mine.Items[0].ID}, "title": "t\u202D"},
		}}, jwt); rec.Code != 400 {
		t.Fatalf("bidi title status = %d, want 400", rec.Code)
	}

	// WS presence frame with an invalid agent name: the valid sibling
	// entry applies, the invalid one is skipped.
	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)
	dc.send(deviceFrame{V: 1, Kind: kindPresence, MsgID: "pr-2",
		Agents: []deviceAgentWire{
			{Name: "good", State: "live", Exposed: true},
			{Name: "ba\x00d", State: "live", Exposed: true},
		}})
	dc.send(deviceFrame{V: 1, Kind: "ping", MsgID: "barrier-2"})
	if f := dc.next("pong"); f.RefID != "barrier-2" {
		t.Fatalf("barrier pong refId = %q", f.RefID)
	}
	rec := env.do("GET", "/api/networks/"+mine.Items[0].ID+"/devices", nil, jwt)
	var roster struct {
		Devices []networkDeviceRosterWire `json:"devices"`
	}
	decodeBody(t, rec, &roster)
	if len(roster.Devices[0].Agents) != 1 || roster.Devices[0].Agents[0].Name != "good" {
		t.Fatalf("agents = %+v, want only the valid entry", roster.Devices[0].Agents)
	}
}

// TestRenameFanout: renaming a device pushes a presence frame to live
// sibling sockets — open UIs update without a roster re-GET.
func TestRenameFanout(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	devA := enrollDevice(t, env, jwt, "macbook")
	devB := enrollDevice(t, env, jwt, "cli-box")

	dcB := dialDeviceWS(t, env, devB.DeviceToken)
	dcB.hello(devB.DeviceID, 1)

	if rec := env.do("PATCH", "/api/devices/"+devA.DeviceID+"/name",
		map[string]any{"name": "Renamed Box"}, jwt); rec.Code != 200 {
		t.Fatalf("rename status = %d", rec.Code)
	}
	flip := dcB.next("presence")
	if len(flip.Devices) != 1 || flip.Devices[0].DeviceID != devA.DeviceID ||
		flip.Devices[0].FriendlyName != "Renamed Box" || flip.Devices[0].Presence != MachineOffline {
		t.Fatalf("rename fanout = %+v", flip.Devices)
	}
}
