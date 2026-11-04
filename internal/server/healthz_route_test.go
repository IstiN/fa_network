package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthzRoutes: /api/healthz is the contract liveness path (GFE
// intercepts the exact /healthz upstream in production).
func TestHealthzRoutes(t *testing.T) {
	s := newTestEnv(t)
	for _, p := range []string{"/api/healthz", "/healthz"} {
		rec := httptest.NewRecorder()
		s.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d want 200", p, rec.Code)
		}
	}
}
