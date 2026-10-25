package server

import (
	"context"
	"log"
	"net/http"
	"time"
)

// dropAgent implements DELETE /api/networks/{id}/agents/{agentId}
// (owner/admin, authed). The persistent tombstone excludes the hub agent
// from every roster (snapshots, /agents, presence events) across reseeds
// and restarts; the hub admin eviction is best-effort hygiene on top
// (requires FA_NETWORK_DAP_ADMIN_TOKEN, refused while the agent is
// online — the tombstone applies regardless). Idempotent: 204 even for
// unknown or already-dropped agents.
func (s *Server) dropAgent(w http.ResponseWriter, r *http.Request) {
	networkID, agentID := r.PathValue("networkId"), r.PathValue("agentId")
	if s.requireManager(w, r, networkID) == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.st.DropHubAgent(ctx, agentID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	s.relay.dropHubAgent(agentID)
	if err := s.hub.EvictAgent(ctx, agentID); err != nil {
		log.Printf("drop agent %s: hub evict not applied: %v", agentID, err)
	}
	s.broadcastRosterSnapshotsAll(ctx)
	w.WriteHeader(http.StatusNoContent)
}
