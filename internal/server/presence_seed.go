package server

import (
	"context"
	"log"
	"time"
)

// seedHubPresence repopulates the hub-agent roster after every (re)connect
// so senderName resolution also covers agents whose presence transitions
// happened while the relay was down (restart, deploy). A failed first
// attempt (cold/slow hub) is retried in the background — a deploy must
// never leave the roster empty until the next agent reconnect.
func (r *Relay) seedHubPresence(ctx context.Context) {
	if r.seedHubPresenceOnce(ctx) {
		return
	}
	go r.retrySeedHubPresence(ctx)
}

// seedHubPresenceOnce makes one bounded presence_query attempt and merges
// the answer into the cache; the outcome is always logged (prod
// observability for the "0 online after deploy" class of issues).
// Dropped agents (roster tombstones) are never resurrected.
func (r *Relay) seedHubPresenceOnce(ctx context.Context) bool {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	agents, err := r.hub.Presence(qctx)
	if err != nil {
		log.Printf("relay: hub presence reseed failed: %v", err)
		return false
	}
	r.mu.Lock()
	merged := 0
	for _, a := range agents {
		if r.dropped[a.AgentID] {
			continue
		}
		r.hubAgents[a.AgentID] = a
		merged++
	}
	r.mu.Unlock()
	log.Printf("relay: seeded %d hub agents (%d dropped skipped)", merged, len(agents)-merged)
	return true
}

// retrySeedHubPresence retries the failed initial seed with backoff.
func (r *Relay) retrySeedHubPresence(ctx context.Context) {
	for _, delay := range r.seedRetryDelays {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if r.seedHubPresenceOnce(ctx) {
			return
		}
	}
}
