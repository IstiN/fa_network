package server

import (
	"context"
	"sync"
	"time"
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

// deviceAgentWire is one agent entry of a presence frame / roster.
type deviceAgentWire struct {
	Name    string `json:"name"` // agentName; address = name@deviceId
	State   string `json:"state"`
	Exposed bool   `json:"exposed"`
	DMPub   string `json:"dmPub,omitempty"`
}

// deviceSessionWire is one session entry. Exposure is per NETWORK
// (contract §6: personal default ON, shared default OFF for sessions);
// the connector lists the networks it exposes the session to.
type deviceSessionWire struct {
	ID       string   `json:"id"`
	State    string   `json:"state"` // live | wake-on-DM | offline
	Networks []string `json:"networks,omitempty"`
}

// deviceState is one device's projection.
type deviceState struct {
	machine     string
	agents      map[string]deviceAgentWire
	sessions    map[string]deviceSessionWire
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
func (e *DeviceExposure) ApplyPresence(deviceID string, agents []deviceAgentWire, sessions []deviceSessionWire, now time.Time) {
	st := e.state(deviceID, now)
	e.mu.Lock()
	defer e.mu.Unlock()
	st.lastReceive = now
	for _, a := range agents {
		st.agents[a.Name] = a
	}
	for _, ses := range sessions {
		st.sessions[ses.ID] = ses
	}
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
	return ok && a.Exposed
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
func (e *DeviceExposure) Roster(deviceID, networkID string) (machine string, agents []deviceAgentWire, sessions []deviceSessionWire) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	st, ok := e.byDevice[deviceID]
	if !ok {
		return MachineOffline, nil, nil
	}
	machine = st.machine
	for _, a := range st.agents {
		if a.Exposed {
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
			s.deviceExposure.SweeperTick(s.cfg.Now())
		}
	}
}
