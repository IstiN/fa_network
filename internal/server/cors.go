package server

import "net/http"

// corsGate answers browser CORS needs for the REST API and /ws: it
// replies to OPTIONS preflights and stamps Access-Control-Allow-* on
// allowed origins. Allowed origins are the fa1.dev app hosts plus local
// dev loops; everything else gets no ACAO header (browser blocks the
// response — same outcome as today, no information leak).
type corsGate struct {
	origins []string
	next    http.Handler
}

func newCORS(origins []string, next http.Handler) http.Handler {
	return &corsGate{origins: origins, next: next}
}

func (g *corsGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowed := g.allow(origin)
	if allowed != "" {
		h := w.Header()
		h.Add("Vary", "Origin")
		h.Set("Access-Control-Allow-Origin", allowed)
		h.Set("Access-Control-Allow-Headers", "authorization, content-type")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	g.next.ServeHTTP(w, r)
}

// allow matches an Origin against the allowlist (exact or .fa1.dev
// subdomain). An empty allowlist matches nothing (API-key-style clients).
func (g *corsGate) allow(origin string) string {
	for _, o := range g.origins {
		if origin == o {
			return origin
		}
		if o == "https://fa1.dev" && len(origin) > len(".fa1.dev") &&
			origin[len(origin)-len(".fa1.dev"):] == ".fa1.dev" {
			return origin
		}
	}
	return ""
}
