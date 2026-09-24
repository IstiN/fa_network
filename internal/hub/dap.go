package hub

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// DapClient is the real dap/1 hub connection: one WS, Ed25519 hello,
// channel joins, signed sends, presence queries, reconnect with backoff.
type DapClient struct {
	url         string
	secret      string
	name        string
	agentID     string
	edPriv      ed25519.PrivateKey
	edPubB64    string
	xPubB64     string
	connMu      sync.Mutex
	conn        *websocket.Conn
	events      chan Event
	joined      map[string]bool
	joinedMu    sync.Mutex
	online      bool
	closed      chan struct{}
	closeOnce   sync.Once
	backoffInit time.Duration
	backoffMax  time.Duration
	now         func() time.Time
	logf        func(string, ...any)
	waitersMu   sync.Mutex
	waiters     map[string]chan frame
}

// DapConfig wires one relay identity against a dap hub.
type DapConfig struct {
	URL          string // ws(s)://hub/ws
	MasterSecret string
	Name         string
}

// NewDapClient builds (but does not yet connect) the relay client.
func NewDapClient(cfg DapConfig) (*DapClient, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(edPub)
	return &DapClient{
		url:         cfg.URL,
		secret:      cfg.MasterSecret,
		name:        cfg.Name,
		agentID:     "r_" + hex.EncodeToString(sum[:])[:12],
		edPriv:      edPriv,
		edPubB64:    base64.StdEncoding.EncodeToString(edPub),
		xPubB64:     base64.RawStdEncoding.EncodeToString(xPriv.PublicKey().Bytes()),
		events:      make(chan Event, 64),
		joined:      map[string]bool{},
		closed:      make(chan struct{}),
		backoffInit: time.Second,
		backoffMax:  30 * time.Second,
		now:         time.Now,
		logf:        log.Printf,
		waiters:     map[string]chan frame{},
	}, nil
}

// AgentID implements Client.
func (d *DapClient) AgentID() string { return d.agentID }

// Online implements Client.
func (d *DapClient) Online() bool {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	return d.online
}

// SetClock swaps the clock (tests).
func (d *DapClient) SetClock(now func() time.Time) { d.now = now }

// Run connects and serves until Close. Reconnects with exponential
// backoff; emits EventOffline/EventOnline around every transition.
func (d *DapClient) Run(ctx context.Context) error {
	backoff := d.backoffInit
	for {
		if d.isClosed() {
			return nil
		}
		err := d.connectOnce(ctx)
		if d.isClosed() {
			return nil
		}
		d.setOnline(false)
		d.emit(Event{Kind: EventOffline, At: d.now()})
		d.logf("dap: disconnected (%v); retrying in %s", err, backoff)
		select {
		case <-d.closed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > d.backoffMax {
			backoff = d.backoffMax
		}
	}
}

func (d *DapClient) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

func (d *DapClient) setOnline(v bool) {
	d.connMu.Lock()
	d.online = v
	d.connMu.Unlock()
}

func (d *DapClient) emit(e Event) {
	select {
	case d.events <- e:
	default:
		d.logf("dap: event dropped (slow consumer)")
	}
}

// connectOnce performs one full connect → hello → welcome → serve cycle.
func (d *DapClient) connectOnce(ctx context.Context) error {
	conn, _, err := websocket.Dial(ctx, d.url, &websocket.DialOptions{
		HTTPHeader: authHeader(d.secret),
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseNow()
	d.connMu.Lock()
	d.conn = conn
	d.connMu.Unlock()
	defer func() {
		d.connMu.Lock()
		d.conn = nil
		d.connMu.Unlock()
	}()

	if err := d.hello(ctx, conn); err != nil {
		return err
	}
	d.setOnline(true)
	d.emit(Event{Kind: EventOnline, At: d.now()})
	if err := d.writeFrame(ctx, conn, frame{"op": "flush"}); err != nil {
		return err
	}
	return d.serve(ctx, conn)
}

func authHeader(secret string) map[string][]string {
	return map[string][]string{
		"Authorization": {"Bearer " + secret},
	}
}

// hello sends the signed hello frame and expects welcome.
func (d *DapClient) hello(ctx context.Context, conn *websocket.Conn) error {
	ts := d.now().UnixMilli()
	hello := frame{
		"op": "hello", "v": 1,
		"pubkey": d.edPubB64, "x25519": d.xPubB64, "name": d.name,
		"nonce": nonce16(), "ts": ts,
	}
	sig, err := sign(d.edPriv, "hello", ts, hello)
	if err != nil {
		return err
	}
	hello["sig"] = sig
	if err := d.writeFrame(ctx, conn, hello); err != nil {
		return err
	}
	for {
		f, err := d.readFrame(ctx, conn)
		if err != nil {
			return err
		}
		switch f.str("op") {
		case "welcome":
			return nil
		case "error":
			return fmt.Errorf("hub rejected hello: %s %s", f.str("code"), f.str("msg"))
		}
	}
}

// registerWaiter reserves a reply channel for one request id.
func (d *DapClient) registerWaiter(id string) chan frame {
	d.waitersMu.Lock()
	defer d.waitersMu.Unlock()
	ch := make(chan frame, 1)
	d.waiters[id] = ch
	return ch
}

func (d *DapClient) unregisterWaiter(id string) {
	d.waitersMu.Lock()
	delete(d.waiters, id)
	d.waitersMu.Unlock()
}

// deliver hands one reply frame to its waiter (false = no waiter).
func (d *DapClient) deliver(id string, f frame) bool {
	d.waitersMu.Lock()
	ch, ok := d.waiters[id]
	if ok {
		delete(d.waiters, id)
	}
	d.waitersMu.Unlock()
	if !ok {
		return false
	}
	ch <- f
	return true
}

// serve reads frames until the connection dies. It is the ONLY reader on
// the socket: reply-matched frames go to waiters, the rest become Events.
func (d *DapClient) serve(ctx context.Context, conn *websocket.Conn) error {
	for {
		f, err := d.readFrame(ctx, conn)
		if err != nil {
			return err
		}
		if replyTo := f.str("replyTo"); replyTo != "" && d.deliver(replyTo, f) {
			continue
		}
		d.dispatch(f)
	}
}

// dispatch routes one inbound hub frame to an Event.
func (d *DapClient) dispatch(f frame) {
	ts := d.now()
	switch f.str("op") {
	case "msg":
		d.emit(Event{Kind: EventMsg, At: ts, Msg: &Envelope{
			ChannelID: f.str("channel"),
			ID:        f.str("id"),
			Payload:   f.str("ciphertext"),
			CreatedAt: ts,
		}})
	case "presence":
		d.emitPresenceFrame(f)
	case "flushed":
		// mailbox drained — nothing to surface.
	case "error":
		d.logf("dap: hub error frame %s %s", f.str("code"), f.str("msg"))
	}
}

func (d *DapClient) emitPresenceFrame(f frame) {
	raw, ok := f["agents"].([]any)
	if !ok {
		return
	}
	for _, item := range raw {
		d.emitPresenceItem(item)
	}
}

func (d *DapClient) emitPresenceItem(item any) {
	m, ok := item.(map[string]any)
	if !ok {
		return
	}
	online, _ := m["online"].(bool)
	d.emit(Event{
		Kind:    EventPresence,
		At:      d.now(),
		AgentID: strOf(m["agentId"]),
		Name:    strOf(m["name"]),
		Online:  online,
	})
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

// Send implements Client: join (once per channel) then signed send.
func (d *DapClient) Send(ctx context.Context, env Envelope) error {
	d.connMu.Lock()
	conn := d.conn
	online := d.online
	d.connMu.Unlock()
	if conn == nil || !online {
		return fmt.Errorf("dap: hub offline")
	}
	if err := d.ensureJoined(ctx, conn, env.ChannelID); err != nil {
		return err
	}
	ts := env.CreatedAt.UnixMilli()
	if ts == 0 {
		ts = d.now().UnixMilli()
	}
	send := frame{
		"op": "send", "channel": env.ChannelID, "id": env.ID,
		"ts": ts, "ciphertext": env.Payload,
	}
	sig, err := sign(d.edPriv, "send", ts, send)
	if err != nil {
		return err
	}
	send["sig"] = sig
	return d.writeFrame(ctx, conn, send)
}

// ensureJoined joins the channel exactly once per connection lifetime.
func (d *DapClient) ensureJoined(ctx context.Context, conn *websocket.Conn, channel string) error {
	d.joinedMu.Lock()
	if d.joined[channel] {
		d.joinedMu.Unlock()
		return nil
	}
	d.joinedMu.Unlock()
	if err := d.writeFrame(ctx, conn, frame{"op": "join", "channel": channel, "chanPubkey": ""}); err != nil {
		return err
	}
	d.joinedMu.Lock()
	d.joined[channel] = true
	d.joinedMu.Unlock()
	return nil
}

// Presence implements Client.
func (d *DapClient) Presence(ctx context.Context) ([]PresenceInfo, error) {
	d.connMu.Lock()
	conn := d.conn
	online := d.online
	d.connMu.Unlock()
	if conn == nil || !online {
		return nil, fmt.Errorf("dap: hub offline")
	}
	id := nonce16()
	ch := d.registerWaiter(id)
	defer d.unregisterWaiter(id)
	if err := d.writeFrame(ctx, conn, frame{"op": "presence_query", "id": id}); err != nil {
		return nil, err
	}
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case f := <-ch:
		return parsePresence(f), nil
	case <-deadline.Done():
		return nil, deadline.Err()
	}
}

func parsePresence(f frame) []PresenceInfo {
	raw, _ := f["agents"].([]any)
	var out []PresenceInfo
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		online, _ := m["online"].(bool)
		out = append(out, PresenceInfo{
			AgentID: strOf(m["agentId"]),
			Name:    strOf(m["name"]),
			Online:  online,
		})
	}
	return out
}

// Events implements Client.
func (d *DapClient) Events() <-chan Event { return d.events }

// Close implements Client.
func (d *DapClient) Close(_ context.Context) error {
	d.closeOnce.Do(func() { close(d.closed) })
	d.connMu.Lock()
	conn := d.conn
	d.connMu.Unlock()
	if conn != nil {
		return conn.Close(websocket.StatusNormalClosure, "bye")
	}
	return nil
}

func (d *DapClient) writeFrame(ctx context.Context, conn *websocket.Conn, f frame) error {
	raw, err := canonicalJSON(f)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, raw)
}

func (d *DapClient) readFrame(ctx context.Context, conn *websocket.Conn) (frame, error) {
	_, raw, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	var f frame
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("bad frame: %w", err)
	}
	return f, nil
}

// Close implements Client.
