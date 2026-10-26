package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/store"
)

// agentNameRe mirrors the network name rules: DNS-label-ish, safe in
// dap hello names and invite strings.
var agentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)

type agentEnrollInput struct {
	Name string `json:"name"`
}

type agentCredentialIssuer func(context.Context, string) (string, error)

// enrollAgent implements legacy POST /api/networks/{id}/agents/enroll.
// Re-enrolling the same name rotates its name-bound credentials (revocation).
func (s *Server) enrollAgent(w http.ResponseWriter, r *http.Request) {
	s.handleAgentEnrollment(w, r, s.hub.EnrollAgent,
		"store clientSecret now — it is never stored or returned again; re-enroll to rotate")
}

// createAgentCredential implements POST /api/networks/{id}/agents/enrollments.
// Every call creates an additional independent credential for the same name.
func (s *Server) createAgentCredential(w http.ResponseWriter, r *http.Request) {
	s.handleAgentEnrollment(w, r, s.hub.CreateAgentCredential,
		"store clientSecret now — it is never stored or returned again; create does not rotate other credentials")
}

// handleAgentEnrollment shares validation, manager authorization, first-come
// ownership, and the AgentEnrollment response between create and rotate.
func (s *Server) handleAgentEnrollment(w http.ResponseWriter, r *http.Request, issue agentCredentialIssuer, note string) {
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
	// First-come name ownership: only the owning network may create or
	// rotate name-bound credentials (cross-tenant access is a 409).
	if err := s.st.ClaimAgentOwner(ctx, networkID, req.Name); err != nil {
		if store.IsConflict(err) {
			writeError(w, http.StatusConflict, CodeConflict, "agent name is owned by another network")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	secret, err := issue(ctx, req.Name)
	if err != nil {
		message := "hub enrollment failed"
		if errors.Is(err, hub.ErrUnknownOperation) {
			message = err.Error()
		}
		writeError(w, http.StatusServiceUnavailable, CodeHubUnavailable, message)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":         req.Name,
		"hubUrl":       s.hub.HubURL(),
		"clientSecret": secret,
		"enrolledAt":   s.cfg.Now().UTC().Format(time.RFC3339),
		"note":         note,
	})
}
