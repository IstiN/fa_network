package server

import (
	"net"
	"net/http"
	"strings"
)

// maxJSONBody bounds every REST JSON body (webhooks additionally enforce
// their own 1 MiB cap before signature verification). Unbounded public
// decoders (join!) were an unauthenticated memory/connection DoS vector.
const maxJSONBody = 1 << 20

// limitJSONBody caps request bodies for API mutations. WebSocket upgrade
// and GET/DELETE requests are unaffected; long-lived sockets must not see
// read deadlines, which is why the HTTP server sets only header/idle
// timeouts (cmd/server).
func limitJSONBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			if strings.HasPrefix(r.URL.Path, "/api/") && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP is the stable throttle identity: RemoteAddr carries a source
// PORT, so keying on it let attackers reset join-password counters by
// reconnecting. Behind Cloud Run the load balancer appends the real
// client to X-Forwarded-For; its first hop is the client. Direct clients
// (tests, no proxy) fall back to the RemoteAddr host.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
			return first
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
