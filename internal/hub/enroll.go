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
// rotates all name-bound credentials (the old ones stop working) — use it
// for revocation.
// The master secret itself never leaves the server.
func (d *DapClient) EnrollAgent(ctx context.Context, name string) (string, error) {
	return d.enrollWithOperation(ctx, name, "enroll")
}

// CreateAgentCredential performs a master-authenticated, signed-hello
// enroll_create exchange. It mints an additional name-bound credential and
// never falls back to legacy enroll: older hubs reject it with bad_frame
// "unknown op enroll_create" without rotating the existing credentials.
func (d *DapClient) CreateAgentCredential(ctx context.Context, name string) (string, error) {
	return d.enrollWithOperation(ctx, name, "enroll_create")
}

func (d *DapClient) enrollWithOperation(ctx context.Context, name, operation string) (string, error) {
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
	if err := probe.writeFrame(ctx, conn, frame{"t": operation}); err != nil {
		return "", fmt.Errorf("enroll send: %w", err)
	}
	return readEnrolled(ctx, probe, conn, operation)
}

// readEnrolled waits for the enrolled reply (or an error frame).
func readEnrolled(ctx context.Context, probe *DapClient, conn *websocket.Conn, operation string) (string, error) {
	for {
		f, err := probe.readFrame(ctx, conn)
		if err != nil {
			return "", fmt.Errorf("enroll read: %w", err)
		}
		switch {
		case f.str("t") == "enrolled" && f.str("secret") != "":
			return f.str("secret"), nil
		case f.str("op") == "error" && isUnknownEnrollmentOperation(f, operation):
			return "", fmt.Errorf("hub rejected %s: %s %s: %w", operation, f.str("code"), f.str("msg"), ErrUnknownOperation)
		case f.str("op") == "error":
			return "", fmt.Errorf("hub rejected %s: %s %s", operation, f.str("code"), f.str("msg"))
		}
	}
}

func isUnknownEnrollmentOperation(f frame, operation string) bool {
	if f.str("code") == "unknown_op" {
		return true
	}
	// Legacy hubs report an unrecognized enrollment operation as bad_frame.
	return f.str("code") == "bad_frame" && f.str("msg") == "unknown op "+operation
}

// HubURL implements Client: the hub base URL for invite strings.
func (d *DapClient) HubURL() string { return d.url }
