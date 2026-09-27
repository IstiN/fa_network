package hub

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// EnrollAgent against the stub: one-shot dial with the master secret, hello
// as the requested name, enroll → name-bound client secret.
func TestDapClientEnrollAgent(t *testing.T) {
	stub := newHubStub(t)
	d, err := NewDapClient(DapConfig{
		URL: stub.url(), MasterSecret: "test-master-secret", Name: "relay-test",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	secret, err := d.EnrollAgent(ctx, "ops-bot")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if secret != "stub-enroll-token" {
		t.Fatalf("secret = %q", secret)
	}
}

// UT-1 (issue #2): the msg frame's `from` field lands in Envelope.SenderID.
func TestDapMsgCarriesSender(t *testing.T) {
	stub := newHubStub(t)
	client, err := NewDapClient(DapConfig{
		URL: stub.url(), MasterSecret: "test-master-secret", Name: "relay-x",
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx) }()
	defer client.Close(context.Background())
	waitFor(t, 3*time.Second, client.Online, "online")

	if err := client.Send(ctx, Envelope{ChannelID: "c1", ID: "m-1", Payload: "Y2lwaGVy", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("send: %v", err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-client.Events():
			if ev.Kind == EventMsg {
				if ev.Msg.SenderID != "a_stub" {
					t.Fatalf("SenderID = %q, want a_stub", ev.Msg.SenderID)
				}
				return
			}
		case <-deadline:
			t.Fatal("no msg event")
		}
	}
}

// Issue #2 follow-up (mailbox orphaning): a pinned IdentitySeed must yield
// the SAME agentId across client instances (deploy restarts), so the hub
// mailbox survives; a different seed must yield a different id.
func TestDapIdentitySeedStability(t *testing.T) {
	seedA := bytes.Repeat([]byte{0xA5}, 32)
	seedB := bytes.Repeat([]byte{0x5A}, 32)

	idA1 := agentIDOfSeed(t, seedA)
	idA2 := agentIDOfSeed(t, seedA)
	if idA1 != idA2 {
		t.Fatalf("same seed, different agentId: %q vs %q", idA1, idA2)
	}
	if got := agentIDOfSeed(t, seedB); got == idA1 {
		t.Fatalf("different seed, same agentId %q", got)
	}
	if !strings.HasPrefix(idA1, "r_") || len(idA1) != len("r_")+12 {
		t.Fatalf("agentId shape = %q", idA1)
	}
}

// agentIDOfSeed connects a fresh seeded client to a stub and returns the
// agentId it would present.
func agentIDOfSeed(t *testing.T, seed []byte) string {
	t.Helper()
	stub := newHubStub(t)
	client, err := NewDapClient(DapConfig{
		URL: stub.url(), MasterSecret: "test-master-secret", Name: "relay-x",
		IdentitySeed: seed,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = client.Run(ctx) }()
	defer client.Close(context.Background())
	waitFor(t, 3*time.Second, client.Online, "online")
	return client.AgentID()
}
