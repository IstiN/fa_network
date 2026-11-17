package server

// Contract §8.2 (flutter_agent/docs/fa_network_connector.md, #2212):
// tombstone retraction, 30-day offline reap, roster-hygiene agent
// shapes, revocation roster removal — and §8.1 (#2213) additive
// session metadata passthrough.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// TestSessionAdditiveKeysRoundtrip: unknown/additive session metadata
// keys (snippet, cwd) survive patch → projection → roster snapshot
// verbatim (contract §8.1 MUST).
func TestSessionAdditiveKeysRoundtrip(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	var mine struct {
		Items []model.AccountNetworkWire `json:"items"`
	}
	decodeBody(t, env.do("GET", "/api/networks/mine", nil, jwt), &mine)
	netID := mine.Items[0].ID

	rec := env.do("PATCH", "/api/devices/"+dev.DeviceID+"/roster",
		map[string]any{"sessions": []map[string]any{
			{"id": "s1", "state": "live", "networks": []string{netID},
				"title": "Fix bug", "path": "/repo", "lastActivity": "2026-11-17T10:00:00Z",
				"snippet": "fix the flaky test", "cwd": "/repo/sub", "customScore": 42},
		}}, jwt)
	if rec.Code != 200 {
		t.Fatalf("patch status = %d body %s", rec.Code, rec.Body.String())
	}

	var roster struct {
		Devices []networkDeviceRosterWire `json:"devices"`
	}
	decodeBody(t, env.do("GET", "/api/networks/"+netID+"/devices", nil, jwt), &roster)
	ses := roster.Devices[0].Sessions
	if len(ses) != 1 {
		t.Fatalf("sessions = %d", len(ses))
	}
	if ses[0].Extra["snippet"] != "fix the flaky test" || ses[0].Extra["cwd"] != "/repo/sub" {
		t.Fatalf("additive keys lost: %+v", ses[0].Extra)
	}
	if ses[0].Extra["customScore"] != float64(42) {
		t.Fatalf("typed additive key mangled: %+v", ses[0].Extra)
	}
	if ses[0].Title != "Fix bug" || ses[0].Path != "/repo" {
		t.Fatalf("baseline keys lost: %+v", ses[0])
	}
}

// TestSessionTombstoneRetraction: offline + empty networks is an
// authoritative retraction — the row disappears from later snapshots;
// a fresh live patch re-adds it (connector authority).
func TestSessionTombstoneRetraction(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	var mine struct {
		Items []model.AccountNetworkWire `json:"items"`
	}
	decodeBody(t, env.do("GET", "/api/networks/mine", nil, jwt), &mine)
	netID := mine.Items[0].ID
	rosterURL := "/api/networks/" + netID + "/devices"

	push := func(state string, nets []string) *httptest.ResponseRecorder {
		ses := map[string]any{"id": "s1", "state": state, "networks": nets, "title": "T"}
		return env.do("PATCH", "/api/devices/"+dev.DeviceID+"/roster",
			map[string]any{"sessions": []map[string]any{ses}}, jwt)
	}
	count := func() int {
		var roster struct {
			Devices []networkDeviceRosterWire `json:"devices"`
		}
		decodeBody(t, env.do("GET", rosterURL, nil, jwt), &roster)
		return len(roster.Devices[0].Sessions)
	}

	if rec := push("live", []string{netID}); rec.Code != 200 {
		t.Fatalf("live patch = %d", rec.Code)
	}
	if count() != 1 {
		t.Fatal("live row missing")
	}
	if rec := push("offline", []string{}); rec.Code != 200 {
		t.Fatalf("tombstone = %d", rec.Code)
	}
	if count() != 0 {
		t.Fatal("tombstoned row still in snapshot")
	}
	// Offline with networks kept is a rendered catalog row, not a tombstone.
	if rec := push("offline", []string{netID}); rec.Code != 200 || count() != 1 {
		t.Fatal("offline catalog row must persist")
	}
	if rec := push("offline", []string{}); rec.Code != 200 || count() != 0 {
		t.Fatal("explicit retraction must still win")
	}
}

// TestOfflineEntryReap: entries of an offline device not refreshed
// within 30 days (server receive time) are reaped from the projection.
func TestOfflineEntryReap(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	var mine struct {
		Items []model.AccountNetworkWire `json:"items"`
	}
	decodeBody(t, env.do("GET", "/api/networks/mine", nil, jwt), &mine)
	netID := mine.Items[0].ID

	rec := env.do("PATCH", "/api/devices/"+dev.DeviceID+"/roster",
		map[string]any{"sessions": []map[string]any{
			{"id": "old", "state": "live", "networks": []string{netID}},
			{"id": "fresh", "state": "live", "networks": []string{netID}},
		}}, jwt)
	if rec.Code != 200 {
		t.Fatalf("patch = %d", rec.Code)
	}
	// Simulate: device went offline long ago; the old entry was last
	// touched 31 days ago, the fresh one today.
	exp := env.srv.deviceExposure
	exp.mu.Lock()
	st := exp.byDevice[dev.DeviceID]
	st.machine = MachineOffline
	st.sessionSeen["old"] = env.srv.cfg.Now().Add(-31 * 24 * time.Hour)
	st.sessionSeen["fresh"] = env.srv.cfg.Now()
	exp.mu.Unlock()

	var roster struct {
		Devices []networkDeviceRosterWire `json:"devices"`
	}
	decodeBody(t, env.do("GET", "/api/networks/"+netID+"/devices", nil, jwt), &roster)
	ses := roster.Devices[0].Sessions
	if len(ses) != 1 || ses[0].ID != "fresh" {
		t.Fatalf("reaped roster sessions = %+v", ses)
	}
}

// TestRevokedDeviceAbsentFromNetworkRoster: revocation removes the
// device from network rosters (account list keeps the row, revoked).
func TestRevokedDeviceAbsentFromNetworkRoster(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	var mine struct {
		Items []model.AccountNetworkWire `json:"items"`
	}
	decodeBody(t, env.do("GET", "/api/networks/mine", nil, jwt), &mine)
	netID := mine.Items[0].ID

	if rec := env.do("DELETE", "/api/devices/"+dev.DeviceID, nil, jwt); rec.Code != 200 {
		t.Fatalf("revoke = %d", rec.Code)
	}
	var roster struct {
		Devices []networkDeviceRosterWire `json:"devices"`
	}
	decodeBody(t, env.do("GET", "/api/networks/"+netID+"/devices", nil, jwt), &roster)
	for _, d := range roster.Devices {
		if d.DeviceID == dev.DeviceID {
			t.Fatal("revoked device still in network roster")
		}
	}
	var list struct {
		Devices []deviceWire `json:"devices"`
	}
	decodeBody(t, env.do("GET", "/api/devices", nil, jwt), &list)
	found := false
	for _, d := range list.Devices {
		if d.DeviceID == dev.DeviceID && d.RevokedAt != nil {
			found = true
		}
	}
	if !found {
		t.Fatal("account device list lost the revoked row")
	}
}

// TestAgentExposedOmittedIsExposed: address+state without `exposed`
// lists the agent (catalog default); explicit exposed:false hides it.
func TestAgentExposedOmittedIsExposed(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	var mine struct {
		Items []model.AccountNetworkWire `json:"items"`
	}
	decodeBody(t, env.do("GET", "/api/networks/mine", nil, jwt), &mine)
	netID := mine.Items[0].ID

	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)
	dc.send(deviceFrame{V: 1, Kind: kindPresence, MsgID: "pr-3",
		Agents: []deviceAgentWire{
			{Name: "catalog-agent", State: "live"},
			{Name: "hidden-agent", State: "live", Exposed: new(bool)},
			{Name: "explicit-agent", State: "live", Exposed: exposedTrue()},
		}})
	dc.send(deviceFrame{V: 1, Kind: "ping", MsgID: "barrier-3"})
	if f := dc.next("pong"); f.RefID != "barrier-3" {
		t.Fatalf("barrier refId = %q", f.RefID)
	}

	var roster struct {
		Devices []networkDeviceRosterWire `json:"devices"`
	}
	decodeBody(t, env.do("GET", "/api/networks/"+netID+"/devices", nil, jwt), &roster)
	names := map[string]bool{}
	for _, a := range roster.Devices[0].Agents {
		names[a.Name] = true
	}
	if !names["catalog-agent"] || !names["explicit-agent"] || names["hidden-agent"] {
		t.Fatalf("agent exposure shapes wrong: %v", names)
	}
}

// TestWakeupTypeHint: registrations carry the wake-path hint; the
// enum is enforced; the value rides the wire round-trip (§9 delta).
func TestWakeupTypeHint(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	enrollDevice(t, env, jwt, "macbook") // provisions the personal network

	var mine struct {
		Items []model.AccountNetworkWire `json:"items"`
	}
	decodeBody(t, env.do("GET", "/api/networks/mine", nil, jwt), &mine)
	netID := mine.Items[0].ID
	base := "/api/networks/" + netID + "/agents/alf/wakeups"

	if rec := env.do("POST", base,
		map[string]any{"url": "https://hooks.example/wake", "secret": "s3cret",
			"wakeType": "desktop"}, jwt); rec.Code != http.StatusCreated {
		t.Fatalf("register = %d body %s", rec.Code, rec.Body.String())
	}
	var reg model.WakeupRegistrationWire
	decodeBody(t, env.do("GET", base, nil, jwt), &reg)
	if reg.WakeType != "desktop" {
		t.Fatalf("wakeType = %q", reg.WakeType)
	}
	if rec := env.do("POST", base,
		map[string]any{"url": "https://hooks.example/wake", "secret": "s3cret",
			"wakeType": "carrier-pigeon"}, jwt); rec.Code != 400 {
		t.Fatalf("bad wakeType = %d, want 400", rec.Code)
	}
}
