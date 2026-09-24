// Package wakeup dispatches identity-only wake-up webhooks: an @tag
// against an OFFLINE agent fires the agent's registered webhook once per
// debounce window. The payload carries {agentId, networkId, triggeredAt}
// — never message content (law #3).
package wakeup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// WakeStore is the persistence the dispatcher needs.
type WakeStore interface {
	Wakeup(ctx context.Context, networkID, agentID string) (*model.WakeupRegistration, error)
	LogDispatch(ctx context.Context, networkID string, d *model.WakeupDispatch) error
}

// payload is the identity-only webhook body.
type payload struct {
	AgentID     string    `json:"agentId"`
	NetworkID   string    `json:"networkId"`
	TriggeredAt time.Time `json:"triggeredAt"`
}

// Dispatcher is the presence-gated, debounced webhook sender.
type Dispatcher struct {
	store        WakeStore
	http         *http.Client
	secret       []byte
	mu           sync.Mutex
	lastDispatch map[string]time.Time
	now          func() time.Time
	logf         func(string, ...any)
	maxBody      int64
}

// Options wires the dispatcher.
type Options struct {
	Store  WakeStore
	Secret []byte // HMAC key for X-Fa-Network-Signature
	HTTP   *http.Client
	Now    func() time.Time
	Logf   func(string, ...any)
}

// NewDispatcher builds the dispatcher.
func NewDispatcher(opts Options) *Dispatcher {
	httpClient := opts.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Dispatcher{
		store:        opts.Store,
		http:         httpClient,
		secret:       opts.Secret,
		lastDispatch: map[string]time.Time{},
		now:          now,
		logf:         logf,
		maxBody:      1 << 20,
	}
}

func debounceKey(networkID, agentID string) string { return networkID + "\x00" + agentID }

// Dispatch fires the webhook for one offline-agent mention, presence-gated
// and debounced per registration. `presence` is the CURRENT hub state of
// the agent; `online` targets are skipped with a log entry (zero calls).
func (d *Dispatcher) Dispatch(ctx context.Context, networkID, agentID, presence string) error {
	reg, err := d.store.Wakeup(ctx, networkID, agentID)
	if err != nil {
		// No registration → nothing to do (not an error).
		return nil
	}
	if presence != model.PresenceOffline {
		return d.log(ctx, networkID, &model.WakeupDispatch{
			AgentID: agentID, At: d.now(), Outcome: model.OutcomeSkippedOnline,
		})
	}
	key := debounceKey(networkID, agentID)
	d.mu.Lock()
	last, seen := d.lastDispatch[key]
	window := time.Duration(reg.DebounceSeconds) * time.Second
	if seen && d.now().Sub(last) < window {
		d.mu.Unlock()
		return d.log(ctx, networkID, &model.WakeupDispatch{
			AgentID: agentID, At: d.now(), Outcome: model.OutcomeBackoff,
			Note: "debounce window active",
		})
	}
	d.lastDispatch[key] = d.now()
	d.mu.Unlock()

	body, err := json.Marshal(payload{AgentID: agentID, NetworkID: networkID, TriggeredAt: d.now()})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(d.secret) > 0 {
		req.Header.Set("X-Fa-Network-Signature", d.sign(body))
	}
	resp, err := d.http.Do(req)
	if err != nil {
		_ = d.log(ctx, networkID, &model.WakeupDispatch{
			AgentID: agentID, At: d.now(), Outcome: model.OutcomeTargetDown, Note: err.Error(),
		})
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, d.maxBody))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return d.log(ctx, networkID, &model.WakeupDispatch{
			AgentID: agentID, At: d.now(), Outcome: model.OutcomeDelivered,
		})
	}
	return d.log(ctx, networkID, &model.WakeupDispatch{
		AgentID: agentID, At: d.now(), Outcome: model.OutcomeTargetDown,
		Note: fmt.Sprintf("status %d", resp.StatusCode),
	})
}

// sign computes the webhook signature header.
func (d *Dispatcher) sign(body []byte) string {
	mac := hmac.New(sha256.New, d.secret)
	mac.Write(body)
	return "sha256=" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (d *Dispatcher) log(ctx context.Context, networkID string, entry *model.WakeupDispatch) error {
	return d.store.LogDispatch(ctx, networkID, entry)
}
