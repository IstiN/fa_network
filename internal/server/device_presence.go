package server

import (
	"context"
	"encoding/json"
	"sync"
	"time"
	"unicode"
)

// Device presence + exposure (machine-connector contract §5/§6).
//
// Three machine states with independent inference: online (live socket +
// heartbeats), degraded (socket lost — local agents keep working; the
// server runs the ~45s grace window), offline (grace expired, or a CLEAN
// shutdown deregisters immediately). Agent (live|busy|offline) and
// session (live|wake-on-DM|offline) states ride inside the machine
// presence frame from the connector. Presence truth = SERVER receive
// time — client wall-clock claims are never stored (lease-mtime lesson).
//
// Exposure flags live locally on the connector (device registry); this
// store is the server-side projection they propagate into (presence
// frames and the roster patch endpoint). In-memory by contract — flags
// re-propagate within one heartbeat after a server restart.
type DeviceExposure struct {
	mu       sync.RWMutex
	byDevice map[string]*deviceState
}

// deviceGrace is the degraded → offline window (§5, ~45s).
const deviceGrace = 45 * time.Second

// Presence state constants (machine level).
const (
	MachineOnline   = "online"
	MachineDegraded = "degraded"
	MachineOffline  = "offline"
)

// Session lease states (§5).
const (
	SessionLive      = "live"
	SessionWakeOnDM  = "wake-on-DM"
	SessionOfflineSt = "offline"
)

// validDisplay rejects control characters (Cc — C0/C1) and bidi
// overrides in client-declared display strings: the UI renders these
// verbatim, so splicing/RTL-spoofing payloads are refused at ingest
// (400 on REST; WS presence frames drop the invalid entries).
func validDisplay(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return false
		}
	}
	return true
}

// deviceAgentWire is one agent entry of a presence frame / roster.
type deviceAgentWire struct {
	Name  string `json:"name"` // agentName; address = name@deviceId
	State string `json:"state"`
	// Exposed nil = exposed (contract §8.2: address + state suffices —
	// the roster is the exposed catalog, not the live registry);
	// explicit false hides the agent.
	Exposed *bool  `json:"exposed,omitempty"`
	DMPub   string `json:"dmPub,omitempty"`
}

// exposedTrue is the explicit-opt-in literal for tests/connector code.
func exposedTrue() *bool {
	b := true
	return &b
}

// deviceSessionWire is one session entry. Exposure is per NETWORK
// (contract §6: personal default ON, shared default OFF for sessions);
// the connector lists the networks it exposes the session to. Title/
// path/lastActivity are connector-declared display metadata — passed
// through into the in-memory projection (lost on restart until the
// connector re-pushes, like all exposure flags).
type deviceSessionWire struct {
	ID           string   `json:"id"`
	State        string   `json:"state"` // live | wake-on-DM | offline
	Networks     []string `json:"networks,omitempty"`
	Title        string   `json:"title,omitempty"`
	Path         string   `json:"path,omitempty"`
	LastActivity string   `json:"lastActivity,omitempty"` // RFC3339, connector clock
	// Extra carries unknown/additive session metadata keys (snippet,
	// cwd, ...) verbatim through the projection — contract §8.1: the
	// server MUST preserve them when merging patches.
	Extra map[string]any `json:"-"`
}

// sessionKnownKeys are the fields decoded into the struct; every other
// key lands in Extra unchanged.
var sessionKnownKeys = map[string]bool{
	"id": true, "state": true, "networks": true,
	"title": true, "path": true, "lastActivity": true,
}

// UnmarshalJSON splits known fields from additive metadata.
func (w *deviceSessionWire) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	type known struct {
		ID           string   `json:"id"`
		State        string   `json:"state"`
		Networks     []string `json:"networks"`
		Title        string   `json:"title"`
		Path         string   `json:"path"`
		LastActivity string   `json:"lastActivity"`
	}
	var k known
	if err := json.Unmarshal(data, &k); err != nil {
		return err
	}
	w.ID, w.State, w.Networks, w.Title, w.Path, w.LastActivity =
		k.ID, k.State, k.Networks, k.Title, k.Path, k.LastActivity
	w.Extra = nil
	for key, v := range raw {
		if sessionKnownKeys[key] {
			continue
		}
		var val any
		if err := json.Unmarshal(v, &val); err != nil {
			return err
		}
		if w.Extra == nil {
			w.Extra = map[string]any{}
		}
		w.Extra[key] = val
	}
	return nil
}

// MarshalJSON re-emits known fields plus the preserved additive keys.
func (w deviceSessionWire) MarshalJSON() ([]byte, error) {
	type known struct {
		ID           string   `json:"id"`
		State        string   `json:"state"`
		Networks     []string `json:"networks,omitempty"`
		Title        string   `json:"title,omitempty"`
		Path         string   `json:"path,omitempty"`
		LastActivity string   `json:"lastActivity,omitempty"`
	}
	base, err := json.Marshal(known{
		ID: w.ID, State: w.State, Networks: w.Networks,
		Title: w.Title, Path: w.Path, LastActivity: w.LastActivity,
	})
	if err != nil {
		return nil, err
	}
	if len(w.Extra) == 0 {
		return base, nil
	}
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	for key, v := range w.Extra {
		m[key] = v
	}
	return json.Marshal(m)
}

// deviceState is one device's projection.
type deviceState struct {
	machine     string
	agents      map[string]deviceAgentWire
	sessions    map[string]deviceSessionWire
	agentSeen   map[string]time.Time // server receive time per entry
	sessionSeen map[string]time.Time
	lastReceive time.Time
	graceUntil  time.Time
}

func newDeviceExposure() *DeviceExposure {
	return &DeviceExposure{byDevice: map[string]*deviceState{}}
}

// state returns (creating on demand) the device's projection.
func (e *DeviceExposure) state(deviceID string, now time.Time) *deviceState {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.byDevice[deviceID]
	if !ok {
		st = &deviceState{
			machine:     MachineOffline,
			agents:      map[string]deviceAgentWire{},
			sessions:    map[string]deviceSessionWire{},
			agentSeen:   map[string]time.Time{},
			sessionSeen: map[string]time.Time{},
			lastReceive: now,
		}
		e.byDevice[deviceID] = st
	}
	return st
}

// Touch records inbound activity (server receive time = presence truth).
func (e *DeviceExposure) Touch(deviceID string, now time.Time) {
	st := e.state(deviceID, now)
	e.mu.Lock()
	st.lastReceive = now
	e.mu.Unlock()
}

// SetMachine records a server-inferred machine state (socket events).
func (e *DeviceExposure) SetMachine(deviceID, machine string, now time.Time) {
	st := e.state(deviceID, now)
	e.mu.Lock()
	st.machine = machine
	if machine == MachineDegraded {
		st.graceUntil = now.Add(deviceGrace)
	}
	e.mu.Unlock()
}

// ApplyPresence merges one connector presence frame (agents + sessions;
// exposure flags included). The machine state itself stays
// server-inferred — the frame only refreshes the receive clock.
// Entries carrying control/bidi characters in display fields are
// skipped (same posture as the REST patch's 400).
func (e *DeviceExposure) ApplyPresence(deviceID string, agents []deviceAgentWire, sessions []deviceSessionWire, now time.Time) {
	st := e.state(deviceID, now)
	e.mu.Lock()
	defer e.mu.Unlock()
	st.lastReceive = now
	for _, a := range agents {
		if a.Name == "" || !validDisplay(a.Name) || (a.DMPub != "" && !validDisplay(a.DMPub)) {
			continue
		}
		st.agents[a.Name] = a
		st.agentSeen[a.Name] = now
	}
	for _, ses := range sessions {
		applySessionEntry(st, ses, now)
	}
	e.reapLocked(now)
}

// applySessionEntry merges one session row: invalid display strings are
// skipped; an offline entry with empty networks is an authoritative
// retraction (contract §8.2 — deleted, not stored; only a fresh
// connector patch resurrects it).
func applySessionEntry(st *deviceState, ses deviceSessionWire, now time.Time) {
	if ses.ID == "" || !validDisplay(ses.Title) || !validDisplay(ses.Path) {
		return
	}
	if ses.State == "offline" && len(ses.Networks) == 0 {
		delete(st.sessions, ses.ID)
		delete(st.sessionSeen, ses.ID)
		return
	}
	st.sessions[ses.ID] = ses
	st.sessionSeen[ses.ID] = now
}

// offlineEntryTL bounds how long an offline device's projected entries
// survive without a refresh (contract §8.2: 30-day reap on server
// receive time — client timestamps are never trusted).
const offlineEntryTL = 30 * 24 * time.Hour

// reapLocked drops entries of offline devices that have not been
// refreshed within offlineEntryTL. Runs under e.mu.
func (e *DeviceExposure) reapLocked(now time.Time) {
	for _, st := range e.byDevice {
		if st.machine != MachineOffline {
			continue
		}
		for sid, seen := range st.sessionSeen {
			if now.Sub(seen) > offlineEntryTL {
				delete(st.sessions, sid)
				delete(st.sessionSeen, sid)
			}
		}
		for aid, seen := range st.agentSeen {
			if now.Sub(seen) > offlineEntryTL {
				delete(st.agents, aid)
				delete(st.agentSeen, aid)
			}
		}
	}
}

// DropDevice forgets a device's whole projection (revocation).
func (e *DeviceExposure) DropDevice(deviceID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.byDevice, deviceID)
}

// StateOf reports the current machine state without mutating anything
// (rename fanout reuses the live state).
func (e *DeviceExposure) StateOf(deviceID string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if st, ok := e.byDevice[deviceID]; ok {
		return st.machine
	}
	return MachineOffline
}

// ExposedAgent reports whether the address's agent is currently exposed
// by the device (upstream sender ACL, contract §6).
func (e *DeviceExposure) ExposedAgent(deviceID, agentName string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	st, ok := e.byDevice[deviceID]
	if !ok {
		return false
	}
	a, ok := st.agents[agentName]
	return ok && (a.Exposed == nil || *a.Exposed)
}

// SweeperTicks walks every device, applying the degraded → offline
// grace expiry. Called from the relay loop (server clock only).
func (e *DeviceExposure) SweeperTick(now time.Time) []string {
	e.mu.Lock()
	var flipped []string
	for id, st := range e.byDevice {
		if st.machine == MachineDegraded && now.After(st.graceUntil) {
			st.machine = MachineOffline
			flipped = append(flipped, id)
		}
	}
	e.mu.Unlock()
	return flipped
}

// Roster returns the exposed-only projection for one device within one
// network (machine presence + exposed agents with dmPub + sessions
// exposed to THAT network).
func (e *DeviceExposure) Roster(deviceID, networkID string, now time.Time) (machine string, agents []deviceAgentWire, sessions []deviceSessionWire) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reapLocked(now)
	st, ok := e.byDevice[deviceID]
	if !ok {
		return MachineOffline, nil, nil
	}
	machine = st.machine
	for _, a := range st.agents {
		if a.Exposed == nil || *a.Exposed {
			agents = append(agents, a)
		}
	}
	for _, ses := range st.sessions {
		if containsNet(ses.Networks, networkID) {
			sessions = append(sessions, ses)
		}
	}
	return machine, agents, sessions
}

func containsNet(nets []string, id string) bool {
	for _, n := range nets {
		if n == id {
			return true
		}
	}
	return false
}

// devicePresenceLoop drives the machine-state sweeper: degraded devices
// whose grace window expired flip to offline (server clock only). The
// tick matches the heartbeat cadence; flips propagate on the next
// roster read and the next snapshot.
func (s *Server) devicePresenceLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweeperOfflineFanout(s.deviceExposure.SweeperTick(s.cfg.Now()))
		}
	}
}
