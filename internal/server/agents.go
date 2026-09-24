package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// listAgents implements GET /api/networks/{id}/agents — the agent roster
// with presence (AC-B6 input) and wake-up registration state.
func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	networkID := r.PathValue("networkId")
	if s.resolveIdentity(w, r, networkID) == nil {
		return
	}
	agents, err := s.relay.Agents(r.Context(), networkID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

type wakeupRegistrationInput struct {
	URL             string `json:"url"`
	Secret          string `json:"secret"`
	DebounceSeconds int    `json:"debounceSeconds"`
}

// getWakeup implements GET .../agents/{id}/wakeups (owner/admin).
func (s *Server) getWakeup(w http.ResponseWriter, r *http.Request) {
	networkID, agentID := r.PathValue("networkId"), r.PathValue("agentId")
	if s.requireManager(w, r, networkID) == nil {
		return
	}
	reg, err := s.st.Wakeup(r.Context(), networkID, agentID)
	if err != nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "no registration")
		return
	}
	writeJSON(w, http.StatusOK, model.WakeupRegistrationWire{
		URL:             reg.URL,
		DebounceSeconds: reg.DebounceSeconds,
		CreatedAt:       reg.CreatedAt,
	})
}

// registerWakeup implements POST (owner/admin, authed). The secret is
// stored as a hash, never returned (rotatable via re-registration).
func (s *Server) registerWakeup(w http.ResponseWriter, r *http.Request) {
	networkID, agentID := r.PathValue("networkId"), r.PathValue("agentId")
	if s.requireManager(w, r, networkID) == nil {
		return
	}
	var req wakeupRegistrationInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "bad json")
		return
	}
	if !validWebhookURL(req.URL) {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "invalid webhook url")
		return
	}
	debounce := req.DebounceSeconds
	if debounce == 0 {
		debounce = 300
	}
	if debounce < 30 {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "debounceSeconds >= 30")
		return
	}
	if !s.limiter.Allow("wakeup|"+networkID+"|"+agentID, 5, time.Minute) {
		writeErrorRetry(w, http.StatusTooManyRequests, CodeThrottled, "registration throttled", 60)
		return
	}
	reg := &model.WakeupRegistration{
		NetworkID:       networkID,
		AgentID:         agentID,
		URL:             req.URL,
		SecretHash:      hashSecret(req.Secret),
		DebounceSeconds: debounce,
		CreatedAt:       s.cfg.Now(),
	}
	if err := s.st.UpsertWakeup(r.Context(), reg); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	writeJSON(w, http.StatusCreated, model.WakeupRegistrationWire{
		URL:             reg.URL,
		DebounceSeconds: reg.DebounceSeconds,
		CreatedAt:       reg.CreatedAt,
	})
}

// validWebhookURL accepts http(s) endpoints only (no file:, gopher:, ...).
func validWebhookURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// removeWakeup implements DELETE (owner/admin).
func (s *Server) removeWakeup(w http.ResponseWriter, r *http.Request) {
	networkID, agentID := r.PathValue("networkId"), r.PathValue("agentId")
	if s.requireManager(w, r, networkID) == nil {
		return
	}
	if err := s.st.DeleteWakeup(r.Context(), networkID, agentID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// wakeupLog implements GET /api/networks/{id}/wakeups/log (owner/admin).
func (s *Server) wakeupLog(w http.ResponseWriter, r *http.Request) {
	networkID := r.PathValue("networkId")
	if s.requireManager(w, r, networkID) == nil {
		return
	}
	page, err := s.st.Dispatches(r.Context(), networkID, r.URL.Query().Get("cursor"), 50)
	if err != nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown cursor")
		return
	}
	items := make([]model.WakeupDispatchWire, 0, len(page.Items))
	for _, d := range page.Items {
		items = append(items, model.WakeupDispatchWire{
			AgentID: d.AgentID, At: d.At, Outcome: d.Outcome, Note: d.Note,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": page.NextCursor})
}

// hashSecret stores only a digest (empty input → empty hash).
func hashSecret(secret string) []byte {
	if secret == "" {
		return nil
	}
	sum := sha256Sum([]byte(secret))
	return sum[:]
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// wakeupRegistered reports whether an agent has a registration.
func (s *Server) wakeupRegistered(ctx context.Context, networkID, agentID string) bool {
	_, err := s.st.Wakeup(ctx, networkID, agentID)
	return err == nil
}
