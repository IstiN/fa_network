package hub

import (
	"context"
	"fmt"

	"github.com/coder/websocket"
)

// EnrollAgent performs a one-shot dap/1 enrollment (protocol.md §Connection
// auth): dials the hub with the master secret, hellos as name, sends enroll
// and returns the hub-issued client secret bound to that name. The
// connection closes right after; the enrolled agent later connects with its
// own keypair plus this secret and the same name. Re-enrolling a name
// rotates its secret (the old one stops working) — use it for revocation.
// The master secret itself never leaves the server.
func (d *DapClient) EnrollAgent(ctx context.Context, name string) (string, error) {
	probe, err := NewDapClient(DapConfig{URL: d.url, MasterSecret: d.secret, Name: name})
	if err != nil {
		return "", fmt.Errorf("enroll init: %w", err)
	}
	conn, _, err := websocket.Dial(ctx, d.url, &websocket.DialOptions{HTTPHeader: authHeader(d.secret)})
	if err != nil {
		return "", fmt.Errorf("enroll dial: %w", err)
	}
	defer conn.CloseNow()
	if err := probe.hello(ctx, conn); err != nil {
		return "", fmt.Errorf("enroll hello: %w", err)
	}
	if err := probe.writeFrame(ctx, conn, frame{"t": "enroll"}); err != nil {
		return "", fmt.Errorf("enroll send: %w", err)
	}
	return readEnrolled(ctx, probe, conn)
}

// readEnrolled waits for the enrolled reply (or an error frame).
func readEnrolled(ctx context.Context, probe *DapClient, conn *websocket.Conn) (string, error) {
	for {
		f, err := probe.readFrame(ctx, conn)
		if err != nil {
			return "", fmt.Errorf("enroll read: %w", err)
		}
		switch {
		case f.str("t") == "enrolled" && f.str("secret") != "":
			return f.str("secret"), nil
		case f.str("op") == "error":
			return "", fmt.Errorf("hub rejected enroll: %s %s", f.str("code"), f.str("msg"))
		}
	}
}

// HubURL implements Client: the hub base URL for invite strings.
func (d *DapClient) HubURL() string { return d.url }
