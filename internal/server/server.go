// Package server hosts the fa_network HTTP surface. The service is a
// relay-only edge: it must never hold a key that decrypts channel content
// (relay-only invariant, parent card flutter_agent_harness#913).
package server

import "net/http"

// Healthz answers the liveness probe with a static ok payload.
func Healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
