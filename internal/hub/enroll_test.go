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
