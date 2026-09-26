package server

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"
)

// agentNameRe mirrors the network name rules: DNS-label-ish, safe in
// dap hello names and invite strings.
var agentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)

type agentEnrollInput struct {
	Name string `json:"name"`
}

// enrollAgent implements POST /api/networks/{id}/agents/enroll
// (owner/admin). Mints a name-bound dap client secret for an external
// (pure dap) agent via a one-shot master-secret enrollment; the master
// secret never leaves the server and the issued secret is returned exactly
// once — re-enrolling the same name rotates it (revocation path).
func (s *Server) enrollAgent(w http.ResponseWriter, r *http.Request) {
	networkID := r.PathValue("networkId")
	if s.requireManager(w, r, networkID) == nil {
		return
	}
	var req agentEnrollInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !agentNameRe.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "name required ([a-z0-9][a-z0-9-]{2,63})")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	secret, err := s.hub.EnrollAgent(ctx, req.Name)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, CodeHubUnavailable, "hub enrollment failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":         req.Name,
		"hubUrl":       s.hub.HubURL(),
		"clientSecret": secret,
		"enrolledAt":   s.cfg.Now().UTC().Format(time.RFC3339),
		"note":         "store clientSecret now — it is never stored or returned again; re-enroll to rotate",
	})
}
