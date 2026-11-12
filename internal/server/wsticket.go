package server

// wsticket.go — short-lived single-use WebSocket tickets (security review
// item #7). Browsers cannot set Authorization on a WebSocket upgrade, so
// the long-lived session bearer used to ride in ?token= and landed in
// ingress request logs. A client now exchanges its session token for a
// 60-second one-time ticket (POST /api/ws-ticket) and connects with
// ?ticket= — the session token itself never appears in a URL. ?token=
// remains accepted as a legacy fallback until clients migrate.
//
// Tickets live in process memory, which is correct while the service
// deploys as a single Cloud Run instance (max-instances 1); a
// multi-instance deployment must move this store to shared state first.

import (
	"net/http"
	"sync"
	"time"
)

const (
	// wsTicketTL bounds a ticket's life: enough for an upgrade right
	// after the mint, useless for replay from logs minutes later.
	wsTicketTL = time.Minute
	// wsTicketRate bounds ticket minting per member: reconnect storms
	// stay supported, the store cannot grow unbounded.
	wsTicketRateN   = 30
	wsTicketRatePer = time.Minute
)

// ticketEntry is one outstanding ticket: the credential it redeems (a
// session token, or a deviceToken in the device scope) and its expiry.
type ticketEntry struct {
	token  string
	exp    time.Time
	device bool
}

// ticketStore mints and redeems tickets. consume deletes before
// validating, so a ticket is single-use even when the redeeming request
// fails downstream auth.
type ticketStore struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]ticketEntry
}

func newTicketStore(now func() time.Time) *ticketStore {
	return &ticketStore{now: now, entries: map[string]ticketEntry{}}
}

// issue records one ticket and sweeps expired entries (the sweep keeps
// the map bounded; issuing is rate-limited per member on top of that).
// device=true mints a device-scope ticket (redeems a deviceToken,
// machine-connector contract §4).
func (t *ticketStore) issue(token string, device bool) string {
	id := newToken()
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.entries {
		if t.now().After(e.exp) {
			delete(t.entries, k)
		}
	}
	t.entries[id] = ticketEntry{token: token, exp: t.now().Add(wsTicketTL), device: device}
	return id
}

// consume atomically removes a ticket; ok is false for unknown, already
// used, or expired tickets. The device flag selects the upgrade path.
func (t *ticketStore) consume(id string) (string, bool, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[id]
	if ok {
		delete(t.entries, id)
	}
	if !ok || t.now().After(e.exp) {
		return "", false, false
	}
	return e.token, e.device, true
}

// issueWSTicket implements POST /api/ws-ticket: Bearer <sessionToken>
// (member scope) or Bearer <deviceToken> (device scope, machine
// connector §4) in, {ticket, expiresIn} out.
func (s *Server) issueWSTicket(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "session token required")
		return
	}
	sess, err := s.st.Session(r.Context(), token)
	if err == nil {
		if !s.limiter.Allow("wsticket|"+sess.MemberID, wsTicketRateN, wsTicketRatePer) {
			writeError(w, http.StatusTooManyRequests, CodeThrottled, "too many ticket requests")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ticket":    s.tickets.issue(token, false),
			"expiresIn": int(wsTicketTL.Seconds()),
			"scope":     "member",
		})
		return
	}
	// Device scope: the bearer must be a live deviceToken.
	device := s.deviceByToken(r.Context(), token)
	if device == nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid session token")
		return
	}
	if !s.limiter.Allow("wsticket|device|"+device.ID, wsTicketRateN, wsTicketRatePer) {
		writeError(w, http.StatusTooManyRequests, CodeThrottled, "too many ticket requests")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ticket":    s.tickets.issue(token, true),
		"expiresIn": int(wsTicketTL.Seconds()),
		"scope":     "device",
	})
}
