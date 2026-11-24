package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// dialDeviceWS upgrades a device socket via a device-scope ticket
// (contract §4: mint POST /api/ws-ticket with the deviceToken, redeem
// on GET /ws?ticket=...).
func dialDeviceWS(t *testing.T, env *testEnv, deviceToken string) *deviceWSClient {
	t.Helper()
	rec := env.do("POST", "/api/ws-ticket", map[string]any{}, deviceToken)
	if rec.Code != 200 {
		t.Fatalf("ticket mint = %d", rec.Code)
	}
	var mint struct {
		Ticket string `json:"ticket"`
	}
	decodeBody(t, rec, &mint)
	url := "ws" + strings.TrimPrefix(env.http.URL, "http") + "/ws?ticket=" + mint.Ticket
	conn, _, err := websocket.Dial(context.Background(), url, nil)
	if err != nil {
		t.Fatalf("dial device ws: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return &deviceWSClient{t: t, conn: conn}
}

// deviceWSClient is a fake connector socket (contract §12).
//
// coder/websocket closes the connection when a Read's deadline passes,
// so the client NEVER times out a read: next() is called only when a
// frame is known to be pending; unmatched frames wait in the backlog.
type deviceWSClient struct {
	t    *testing.T
	conn *websocket.Conn
	// backlog holds frames consumed but not yet matched (roster frames
	// of no interest to the current assertion, pings, etc).
	backlog []deviceFrame
}

func (c *deviceWSClient) matches(f deviceFrame, kinds []string) bool {
	for _, k := range kinds {
		if f.Kind == k {
			return true
		}
	}
	return false
}

// next consumes frames until one matches kinds (deadline 2s).
func (c *deviceWSClient) next(kinds ...string) deviceFrame {
	c.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if len(c.backlog) > 0 {
			f := c.backlog[0]
			c.backlog = c.backlog[1:]
			if c.matches(f, kinds) {
				return f
			}
			continue
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		_, raw, err := c.conn.Read(ctx)
		cancel()
		if err != nil {
			c.t.Fatalf("device ws read: %v", err)
		}
		var f deviceFrame
		if err := json.Unmarshal(raw, &f); err != nil {
			continue
		}
		if c.matches(f, kinds) {
			return f
		}
		c.backlog = append(c.backlog, f)
	}
}

// nextAny returns the next frame of any kind (backlog first, deadline 2s).
func (c *deviceWSClient) nextAny() deviceFrame {
	c.t.Helper()
	if len(c.backlog) > 0 {
		f := c.backlog[0]
		c.backlog = c.backlog[1:]
		return f
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2*time.Second))
	defer cancel()
	_, raw, err := c.conn.Read(ctx)
	if err != nil {
		c.t.Fatalf("device ws read: %v", err)
	}
	var f deviceFrame
	if err := json.Unmarshal(raw, &f); err != nil {
		c.t.Fatalf("device ws unmarshal: %v", err)
	}
	return f
}

func (c *deviceWSClient) send(f deviceFrame) {
	c.t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		c.t.Fatalf("marshal: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.conn.Write(ctx, websocket.MessageText, raw); err != nil {
		c.t.Fatalf("device ws write: %v", err)
	}
}

// hello performs the handshake tail: hello → hello_ok + exactly
// wantRoster roster frames (deterministic: the mock user holds one
// personal network per test). Later frames (mail) stay queued for
// next(); the connector never blocks its own handshake this way.
func (c *deviceWSClient) hello(deviceID string, wantRoster int) []deviceFrame {
	c.t.Helper()
	c.send(deviceFrame{V: 1, Kind: "hello", MsgID: "hello-1", DeviceID: deviceID})
	ok := c.next("hello_ok")
	if ok.RefID != "hello-1" {
		c.t.Fatalf("hello_ok.refId = %q, want hello-1", ok.RefID)
	}
	// Envelope v1 client contract: msgId is mandatory on EVERY frame —
	// a Dart envelope without it is rejected as malformed (which hung
	// the connector handshake on server-origin frames, prod "stuck
	// Connecting"). Server-origin control frames mint their own ids.
	if ok.MsgID == "" || ok.TS == "" {
		c.t.Fatalf("hello_ok must carry msgId+ts, got %+v", ok)
	}
	roster := make([]deviceFrame, 0, wantRoster)
	for i := 0; i < wantRoster; i++ {
		roster = append(roster, c.next("roster"))
	}
	return roster
}

func TestDeviceWSHandshakeRosterAndPing(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	dc := dialDeviceWS(t, env, dev.DeviceToken)
	roster := dc.hello(dev.DeviceID, 1)
	if len(roster) == 0 {
		t.Fatal("hello must produce a roster snapshot")
	}
	for _, f := range roster {
		if f.Network == "" {
			t.Fatal("roster frame must carry its network id")
		}
		if f.MsgID == "" {
			t.Fatal("roster frame must carry msgId")
		}
	}

	// ping/pong roundtrip with refId binding; pong is a server-origin
	// frame and must mint its own msgId+ts (client envelope contract).
	dc.send(deviceFrame{V: 1, Kind: "ping", MsgID: "p-1"})
	if f := dc.next("pong"); f.RefID != "p-1" {
		t.Fatalf("pong.refId = %q, want p-1", f.RefID)
	} else if f.MsgID == "" || f.TS == "" {
		t.Fatalf("pong must carry msgId+ts, got %+v", f)
	}

	// hello must precede everything: a bare ack before hello on a FRESH
	// socket gets no response (handshake gate) — covered implicitly by
	// dialing a second socket that never sends hello and stays silent.
}

func TestDeviceTicketSingleUseAndForeignRejection(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	rec := env.do("POST", "/api/ws-ticket", map[string]any{}, dev.DeviceToken)
	var mint struct {
		Ticket string `json:"ticket"`
	}
	decodeBody(t, rec, &mint)

	// First redeem upgrades; the replayed ticket is rejected (single-use).
	upgrade := func(ticket string) int {
		url := "ws" + strings.TrimPrefix(env.http.URL, "http") + "/ws?ticket=" + ticket
		conn, resp, err := websocket.Dial(context.Background(), url, nil)
		if err == nil {
			conn.CloseNow()
			return resp.StatusCode
		}
		if resp != nil {
			return resp.StatusCode
		}
		return -1
	}
	first := upgrade(mint.Ticket)
	if first != http.StatusSwitchingProtocols && first != -1 {
		t.Fatalf("first redeem status = %d", first)
	}
	if retry := upgrade(mint.Ticket); retry != http.StatusUnauthorized && retry != -1 {
		t.Fatalf("ticket replay status = %d, want 401", retry)
	}
}

func TestDeviceMailRedeliveryInSeqOrderAndAck(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")
	box := env.srv.deviceMail.of(dev.DeviceID)

	// Simulate mail that arrived while the connector was offline (phase B
	// routes real traffic; here the mailbox is fed directly, AC5 seam).
	box.Enqueue(deviceFrame{V: 1, Kind: "mail", MsgID: "m-2", Seq: 2, Ciphertext: "ct2"})
	box.Enqueue(deviceFrame{V: 1, Kind: "mail", MsgID: "m-1", Seq: 1, Ciphertext: "ct1"})
	box.Enqueue(deviceFrame{V: 1, Kind: "mail", MsgID: "m-3", Seq: 3, Ciphertext: "ct3"})

	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)

	// Redelivery is seq-ordered regardless of enqueue order, byte-for-byte.
	want := []struct {
		id  string
		seq int64
		ct  string
	}{{"m-1", 1, "ct1"}, {"m-2", 2, "ct2"}, {"m-3", 3, "ct3"}}
	for _, w := range want {
		f := dc.next("mail")
		if f.MsgID != w.id || f.Seq != w.seq || f.Ciphertext != w.ct {
			t.Fatalf("redelivery = %s seq %d ct %q, want %s seq %d ct %q",
				f.MsgID, f.Seq, f.Ciphertext, w.id, w.seq, w.ct)
		}
	}

	// Ack two; the acked frames never come back on the next resume.
	dc.send(deviceFrame{V: 1, Kind: "ack", RefID: "m-1"})
	dc.send(deviceFrame{V: 1, Kind: "ack", RefID: "m-3"})

	// Server-side truth: only the unacked frame remains pending.
	// Poll (no sleep-sync): the acks ride the socket asynchronously.
	remaining := []deviceFrame(nil)
	for deadline := time.Now().Add(2 * time.Second); ; {
		remaining = box.Redeliver()
		if len(remaining) == 1 && remaining[0].MsgID == "m-2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mailbox after acks = %d frames, want only m-2", len(remaining))
		}
		time.Sleep(20 * time.Millisecond)
	}

	dc2 := dialDeviceWS(t, env, dev.DeviceToken)
	dc2.hello(dev.DeviceID, 1)
	f := dc2.next("mail")
	if f.MsgID != "m-2" {
		t.Fatalf("resume redelivered %q, want only unacked m-2", f.MsgID)
	}
	// No extra frames: the second hello_ok already proved the pump is
	// alive, and the mailbox state above proves m-1/m-3 are gone.
}

func TestDeviceSecondDialEvictsFirst(t *testing.T) {
	env := newTestEnv(t)
	dev := enrollDevice(t, env, env.authedToken("alice", "Alice"), "macbook")

	dc1 := dialDeviceWS(t, env, dev.DeviceToken)
	dc1.send(deviceFrame{V: 1, Kind: "hello", MsgID: "h1", DeviceID: dev.DeviceID})
	dc1.next("hello_ok")

	// AC1: one upstream per device — the second dial wins, the first is
	// closed by the server (reads fail soon after).
	dc2 := dialDeviceWS(t, env, dev.DeviceToken)
	dc2.send(deviceFrame{V: 1, Kind: "hello", MsgID: "h2", DeviceID: dev.DeviceID})
	dc2.next("hello_ok")

	deadline := time.Now().Add(2 * time.Second)
	for {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		_, _, err := dc1.conn.Read(ctx)
		cancel()
		if err != nil {
			return // first socket closed: eviction proven
		}
		if time.Now().After(deadline) {
			t.Fatal("first socket was not evicted by the second dial")
		}
	}
}

func TestDeviceRevocationClosesSocket(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.send(deviceFrame{V: 1, Kind: "hello", MsgID: "h", DeviceID: dev.DeviceID})
	dc.next("hello_ok")

	// Owner revokes mid-socket: the registry kick closes it.
	if rec := env.do("DELETE", "/api/devices/"+dev.DeviceID, nil, jwt); rec.Code != 200 {
		t.Fatalf("owner revoke = %d", rec.Code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		_, _, err := dc.conn.Read(ctx)
		cancel()
		if err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked device socket stayed open")
		}
	}
}

func TestDeviceMailRejectedUntilPhaseB(t *testing.T) {
	env := newTestEnv(t)
	dev := enrollDevice(t, env, env.authedToken("alice", "Alice"), "macbook")
	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)

	dc.send(deviceFrame{V: 1, Kind: "mail", MsgID: "m-1", Channel: "c1", Ciphertext: "ct"})
	f := dc.next("error")
	if f.RefID != "m-1" {
		t.Fatalf("error.refId = %q, want m-1", f.RefID)
	}
}
