package wakeup

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/model"
	"github.com/IstiN/fa_network/internal/store"
)

// AC-B6: offline @tag → exactly one webhook call inside the debounce
// window, identity-only payload; online target → zero calls.
func TestDispatchDebouncedAndIdentityOnly(t *testing.T) {
	var calls [][]byte
	var signatures []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, body)
		signatures = append(signatures, r.Header.Get("X-Fa-Network-Signature"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	st := store.NewMemStore()
	ctx := context.Background()
	reg := &model.WakeupRegistration{
		NetworkID: "n1", AgentID: "a1", URL: server.URL,
		SecretHash: []byte("x"), DebounceSeconds: 60, CreatedAt: time.Now(),
	}
	if err := st.UpsertWakeup(ctx, reg); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	d := NewDispatcher(Options{Store: st, Secret: []byte("webhook-secret")})

	// Online target: zero calls, skipped_online log.
	if err := d.Dispatch(ctx, "n1", "a1", model.PresenceLive); err != nil {
		t.Fatalf("online dispatch: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("online target got %d calls", len(calls))
	}

	// Offline: first mention dispatches.
	if err := d.Dispatch(ctx, "n1", "a1", model.PresenceOffline); err != nil {
		t.Fatalf("offline dispatch: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	// Identity-only payload: exactly the three allowed fields.
	var body map[string]any
	if err := json.Unmarshal(calls[0], &body); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if len(body) != 3 || body["agentId"] != "a1" || body["networkId"] != "n1" {
		t.Fatalf("payload fields = %v", body)
	}
	if _, leaked := body["payload"]; leaked {
		t.Fatal("payload must never carry message content")
	}
	if signatures[0] == "" {
		t.Fatal("missing signature header")
	}

	// Repeated mentions inside the debounce window: no more calls.
	for i := 0; i < 3; i++ {
		if err := d.Dispatch(ctx, "n1", "a1", model.PresenceOffline); err != nil {
			t.Fatalf("debounced dispatch: %v", err)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("debounce violated: %d calls", len(calls))
	}

	// Log audit trail: skipped_online once, delivered once, backoff thrice.
	log, err := st.Dispatches(ctx, "n1", "", 10)
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	counts := map[string]int{}
	for _, item := range log.Items {
		counts[item.Outcome]++
	}
	if counts[model.OutcomeDelivered] != 1 || counts[model.OutcomeSkippedOnline] != 1 || counts[model.OutcomeBackoff] != 3 {
		t.Fatalf("log counts = %v", counts)
	}
}

func TestDispatchTargetDownLogged(t *testing.T) {
	st := store.NewMemStore()
	ctx := context.Background()
	_ = st.UpsertWakeup(ctx, &model.WakeupRegistration{
		NetworkID: "n1", AgentID: "a1", URL: "http://127.0.0.1:1/hook",
		DebounceSeconds: 30, CreatedAt: time.Now(),
	})
	d := NewDispatcher(Options{Store: st})
	if err := d.Dispatch(ctx, "n1", "a1", model.PresenceOffline); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	log, err := st.Dispatches(ctx, "n1", "", 10)
	if err != nil || len(log.Items) != 1 || log.Items[0].Outcome != model.OutcomeTargetDown {
		t.Fatalf("log = %v err=%v", log, err)
	}
}

func TestDispatchNoRegistrationIsNoop(t *testing.T) {
	st := store.NewMemStore()
	d := NewDispatcher(Options{Store: st})
	if err := d.Dispatch(context.Background(), "n1", "ghost", model.PresenceOffline); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	log, _ := st.Dispatches(context.Background(), "n1", "", 10)
	if len(log.Items) != 0 {
		t.Fatalf("unexpected log: %+v", log.Items)
	}
}
