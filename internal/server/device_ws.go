package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/IstiN/fa_network/internal/model"
)

// Device WS protocol (machine-connector contract §3/§4): one upstream
// socket per device speaking envelope v1 frames. The server never
// inspects ciphertext — routing, dedup and delivery bookkeeping only
// (relay-only law).
const (
	// deviceHeartbeat bounds idle sockets; ~20s per contract §4.
	deviceHeartbeat = 20 * time.Second
	// deviceGhostAfter drops half-open sockets (two missed beats).
	deviceGhostAfter = 45 * time.Second
	// deviceHelloTimeout bounds how long a socket may sit before hello.
	deviceHelloTimeout = 10 * time.Second
	// deviceMailboxCap bounds unacked mail held per device.
	deviceMailboxCap = 512
)

// deviceFrame is one envelope v1 wire frame (contract §3). msgId doubles
// as the fanet1 frameId inside ciphertext (contract v1.1 §3): the server
// redelivers frames byte-for-byte and never mints or rewrites msgIds.
type deviceFrame struct {
	V          int    `json:"v"`
	Kind       string `json:"kind"`
	MsgID      string `json:"msgId,omitempty"`
	RefID      string `json:"refId,omitempty"`
	Network    string `json:"network,omitempty"`
	Channel    string `json:"channel,omitempty"`
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	TS         string `json:"ts,omitempty"`
	Seq        int64  `json:"seq,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	// roster-only: public directory entries (names/presence/classes —
	// never message content), plaintext like the member-WS roster.
	Entries []model.MemberWire `json:"entries,omitempty"`
	// presence-only (§5): agent states + exposed session leases riding
	// inside the machine presence frame.
	Agents   []deviceAgentWire   `json:"agents,omitempty"`
	Sessions []deviceSessionWire `json:"sessions,omitempty"`
	// hello-only fields
	DeviceID     string `json:"deviceId,omitempty"`
	RosterDigest string `json:"rosterDigest,omitempty"`
}

// device frame kinds (contract §3).
const (
	kindHello    = "hello"
	kindHelloOK  = "hello_ok"
	kindMail     = "mail"
	kindRoster   = "roster"
	kindAck      = "ack"
	kindWake     = "wake_hint"
	kindPing     = "ping"
	kindPong     = "pong"
	kindError    = "error"
	kindPresence = "presence"
)

// deviceConn is one live device socket.
type deviceConn struct {
	device    *model.Device
	send      chan deviceFrame
	done      chan struct{}
	closeConn func()
	mu        sync.Mutex
	lastPong  time.Time
}

// markPong records inbound activity (any frame counts).
func (c *deviceConn) markPong(at time.Time) {
	c.mu.Lock()
	c.lastPong = at
	c.mu.Unlock()
}

// silentFor reports whether the socket missed its heartbeat window.
func (c *deviceConn) silentFor(at, after time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPong.Before(after)
}

// DeviceRegistry tracks live device sockets — one upstream per device
// (contract AC1). A second dial for the same device wins; the older
// socket is closed (connector reconnect storms stay safe).
type DeviceRegistry struct {
	mu   sync.Mutex
	cons map[string]*deviceConn
}

// NewDeviceRegistry returns an empty registry.
func NewDeviceRegistry() *DeviceRegistry {
	return &DeviceRegistry{cons: map[string]*deviceConn{}}
}

// Add registers conn for its device, closing and evicting any older
// socket. The evicted socket's mail frame stays in its mailbox.
func (r *DeviceRegistry) Add(conn *deviceConn) (evicted bool) {
	r.mu.Lock()
	old, ok := r.cons[conn.device.ID]
	r.cons[conn.device.ID] = conn
	r.mu.Unlock()
	if ok && old != conn {
		old.closeConn()
		return true
	}
	return false
}

// Remove deregisters conn when it is still the live one.
func (r *DeviceRegistry) Remove(conn *deviceConn) {
	r.mu.Lock()
	if cur, ok := r.cons[conn.device.ID]; ok && cur == conn {
		delete(r.cons, conn.device.ID)
	}
	r.mu.Unlock()
}

// Online reports whether the device has a live socket.
func (r *DeviceRegistry) Online(deviceID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.cons[deviceID]
	return ok
}

// OfUsers returns the live sockets of the given users (device mail
// fanout: one frame per member device per envelope).
func (r *DeviceRegistry) OfUsers(userIDs []string) []*deviceConn {
	want := make(map[string]bool, len(userIDs))
	for _, id := range userIDs {
		want[id] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*deviceConn
	for _, conn := range r.cons {
		if want[conn.device.UserID] {
			out = append(out, conn)
		}
	}
	return out
}

// All returns every live device socket (sweeper broadcasts).
func (r *DeviceRegistry) All() []*deviceConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*deviceConn, 0, len(r.cons))
	for _, conn := range r.cons {
		out = append(out, conn)
	}
	return out
}

// Kick force-closes a device's socket (revocation path).
func (r *DeviceRegistry) Kick(deviceID string) {
	r.mu.Lock()
	conn, ok := r.cons[deviceID]
	delete(r.cons, deviceID)
	r.mu.Unlock()
	if ok {
		conn.closeConn()
	}
}

// deviceMailbox holds a device's unacked mail for redelivery in seq
// order (contract AC5: kill upstream, send, restore — nothing lost).
// In-memory by design for now: durable mail already lives in the
// per-channel envelope store; this buffer only covers the redelivery
// window of a reconnecting connector on the same process.
type deviceMailbox struct {
	mu      sync.Mutex
	pending []deviceFrame
}

// Enqueue holds one mail frame for (re)delivery.
func (m *deviceMailbox) Enqueue(f deviceFrame) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pending) >= deviceMailboxCap {
		m.pending = m.pending[1:] // shed oldest under abuse
	}
	m.pending = append(m.pending, f)
}

// Ack drops the frame whose msgId == refID (acked after local write).
func (m *deviceMailbox) Ack(refID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, f := range m.pending {
		if f.MsgID == refID {
			m.pending = append(m.pending[:i], m.pending[i+1:]...)
			return
		}
	}
}

// Redeliver returns unacked mail in seq order (older first).
func (m *deviceMailbox) Redeliver() []deviceFrame {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]deviceFrame, len(m.pending))
	copy(out, m.pending)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Seq < out[j-1].Seq; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// deviceMailboxes is the per-device mailbox set.
type deviceMailboxes struct {
	mu   sync.Mutex
	byID map[string]*deviceMailbox
}

func newDeviceMailboxes() *deviceMailboxes {
	return &deviceMailboxes{byID: map[string]*deviceMailbox{}}
}

func (m *deviceMailboxes) of(deviceID string) *deviceMailbox {
	m.mu.Lock()
	defer m.mu.Unlock()
	box, ok := m.byID[deviceID]
	if !ok {
		box = &deviceMailbox{}
		m.byID[deviceID] = box
	}
	return box
}

// serveDeviceWS runs the device protocol path of GET /ws after a
// device-scope ticket redeemed deviceToken. The token is re-resolved:
// a revocation between ticket mint and upgrade must fail closed.
func (s *Server) serveDeviceWS(w http.ResponseWriter, r *http.Request, deviceToken string) {
	device := s.deviceByToken(r.Context(), deviceToken)
	if device == nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid device token")
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: s.corsOrigins})
	if err != nil {
		return
	}
	dc := &deviceConn{
		device:    device,
		send:      make(chan deviceFrame, 64),
		done:      make(chan struct{}),
		closeConn: func() { _ = conn.CloseNow() },
		lastPong:  time.Now(),
	}
	s.deviceConns.Add(dc)
	box := s.deviceMail.of(device.ID)
	s.deviceExposure.SetMachine(device.ID, MachineOnline, s.cfg.Now())

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	writeDone := make(chan struct{})
	go s.deviceWriteLoop(ctx, conn, dc, box)

	if !s.deviceHandshake(ctx, conn, dc, box) {
		s.deviceExposure.SetMachine(device.ID, MachineOffline, s.cfg.Now())
		dc.closeConn()
		<-writeDone
		return
	}
	readPumpErr := s.deviceReadPump(ctx, conn, dc, box)
	dc.closeConn()
	s.deviceConns.Remove(dc)
	// Machine-state inference on socket loss (§5): a clean close (the
	// connector sent a close frame) deregisters immediately; an abnormal
	// drop (network gone, process killed) opens the degraded grace
	// window — local agents keep working while it runs.
	if isCleanWSClose(readPumpErr) {
		s.deviceExposure.SetMachine(device.ID, MachineOffline, s.cfg.Now())
	} else {
		s.deviceExposure.SetMachine(device.ID, MachineDegraded, s.cfg.Now())
	}
	<-writeDone
}

// isCleanWSClose reports whether the socket ended with a close frame
// (intentional teardown) rather than a transport-level drop.
func isCleanWSClose(err error) bool {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		return ce.Code == websocket.StatusNormalClosure || ce.Code == websocket.StatusGoingAway
	}
	return false
}

// deviceHandshake waits for hello, replies hello_ok + roster snapshot
// and redelivers unacked mail in seq order (contract §4).
func (s *Server) deviceHandshake(ctx context.Context, conn *websocket.Conn, dc *deviceConn, box *deviceMailbox) bool {
	deadline, cancel := context.WithTimeout(ctx, deviceHelloTimeout)
	defer cancel()
	for {
		_, raw, err := conn.Read(deadline)
		if err != nil {
			return false
		}
		var f deviceFrame
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		dc.markPong(s.cfg.Now())
		switch f.Kind {
		case kindPing:
			s.deviceSend(dc, deviceFrame{V: 1, Kind: kindPong, MsgID: newToken(), RefID: f.MsgID, TS: s.cfg.Now().UTC().Format(time.RFC3339)})
		case kindHello:
			s.deviceSend(dc, deviceFrame{V: 1, Kind: kindHelloOK, MsgID: newToken(), RefID: f.MsgID, TS: s.cfg.Now().UTC().Format(time.RFC3339)})
			s.deviceRosterSnapshot(dc)
			for _, mail := range box.Redeliver() {
				s.deviceSend(dc, mail)
			}
			return true
		}
	}
}

// deviceRosterSnapshot pushes one roster frame per network of the
// device's user (personal networks first). Exposure filtering arrives
// with the roster-patch endpoint (contract §6, phase B).
func (s *Server) deviceRosterSnapshot(dc *deviceConn) {
	ctx := context.Background()
	networks, err := s.st.AccountNetworks(ctx, dc.device.UserID)
	if err != nil {
		return
	}
	for _, an := range networks {
		members, _ := s.st.Members(ctx, an.Network.ID)
		members = append(members, s.relay.hubAgentMembers(ctx, an.Network.ID, members)...)
		s.relay.decorateAccess(ctx, members)
		entries := make([]model.MemberWire, 0, len(members))
		for _, m := range members {
			entries = append(entries, model.MemberWireOf(m))
		}
		s.deviceSend(dc, deviceFrame{
			V: 1, Kind: kindRoster, MsgID: newToken(),
			Network: an.Network.ID, TS: s.cfg.Now().UTC().Format(time.RFC3339),
			Entries: entries,
		})
	}
}

// deviceWriteLoop pumps frames and the heartbeat; the ghost check drops
// half-open sockets (two missed beats).
func (s *Server) deviceWriteLoop(ctx context.Context, conn *websocket.Conn, dc *deviceConn, box *deviceMailbox) {
	defer close(dc.done)
	ticker := time.NewTicker(deviceHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case f := <-dc.send:
			if err := s.deviceWrite(conn, f); err != nil {
				return
			}
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.deviceSendPing(conn, dc) {
				return
			}
		}
	}
}

// deviceSendPing emits a ping; true = the socket is a ghost.
func (s *Server) deviceSendPing(conn *websocket.Conn, dc *deviceConn) bool {
	if err := s.deviceWrite(conn, deviceFrame{V: 1, Kind: kindPing, MsgID: newToken()}); err != nil {
		return true
	}
	return dc.silentFor(time.Now(), time.Now().Add(-deviceGhostAfter))
}

// deviceWrite serializes one frame to the socket.
func (s *Server) deviceWrite(conn *websocket.Conn, f deviceFrame) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, raw)
}

// deviceSend queues a frame; a full buffer or closed socket must never
// block the routing path.
func (s *Server) deviceSend(dc *deviceConn, f deviceFrame) {
	select {
	case dc.send <- f:
	default:
	}
}

// deviceReadPump routes inbound frames until disconnect, reporting the
// terminal read error (clean-close inference upstream).
func (s *Server) deviceReadPump(ctx context.Context, conn *websocket.Conn, dc *deviceConn, box *deviceMailbox) error {
	for {
		_, raw, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var f deviceFrame
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		dc.markPong(s.cfg.Now())
		switch f.Kind {
		case kindPing:
			s.deviceSend(dc, deviceFrame{V: 1, Kind: kindPong, MsgID: newToken(), RefID: f.MsgID, TS: s.cfg.Now().UTC().Format(time.RFC3339)})
		case kindAck:
			box.Ack(f.RefID)
		case kindMail:
			s.deviceMailRoute(ctx, dc, f)
		case kindPresence:
			s.deviceExposure.ApplyPresence(dc.device.ID, f.Agents, f.Sessions, s.cfg.Now())
		default:
			// hello outside handshake, unknown kinds: ignore (log-free
			// noise discipline; the connector retries with hello).
		}
	}
}
