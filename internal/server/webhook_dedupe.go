package server

import (
	"net/http"
	"sync"
	"time"
)

// deliveryCache deduplicates webhook deliveries (provider retries and
// captured-request replays) BEFORE any reaction/timer/dispatch side
// effect. fa_network runs as a single instance, so an in-process TTL
// cache closes the replay window without a schema change.
type deliveryCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newDeliveryCache() *deliveryCache {
	return &deliveryCache{seen: map[string]time.Time{}}
}

const deliveryTTL = 24 * time.Hour

// Seen reports whether this provider delivery was already processed;
// first sightings are recorded. Empty ids never dedupe (providers
// without a delivery header keep their previous behaviour).
func (d *deliveryCache) Seen(provider, id string, now time.Time) bool {
	if id == "" {
		return false
	}
	key := provider + "|" + id
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.seen) > 4096 {
		for k, at := range d.seen {
			if now.Sub(at) > deliveryTTL {
				delete(d.seen, k)
			}
		}
	}
	if at, ok := d.seen[key]; ok && now.Sub(at) <= deliveryTTL {
		return true
	}
	d.seen[key] = now
	return false
}

// deliveryID extracts the provider's unique delivery header.
func deliveryID(provider string, header http.Header) string {
	switch provider {
	case "github":
		return header.Get("X-GitHub-Delivery")
	case "gitlab":
		return header.Get("X-Gitlab-Event-UUID")
	case "bitbucket":
		return header.Get("X-Request-UUID")
	default: // generic: optional caller-supplied idempotency key
		return header.Get("X-Fa-Delivery-Id")
	}
}
