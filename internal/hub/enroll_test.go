package hub

import (
	"context"
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
