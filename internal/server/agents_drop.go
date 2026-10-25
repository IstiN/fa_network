package server

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/IstiN/fa_network/internal/store"
)

// dropAgent implements DELETE /api/networks/{id}/agents/{agentId}
// (owner/admin, authed). The exclusion is PER-NETWORK: the hub agent
// disappears from this network's roster only (snapshots, /agents,
// presence.changed), never from other tenants'. The tombstone persists
// across reseeds and restarts. Hub-admin eviction is restricted to
// agents ENROLLED BY THIS NETWORK (AgentOwnership) — a manager must never
// wield the global hub credential against other tenants' agents. Unknown
// agents are a 404 no-op (no tombstones/eviction/broadcast spam);
// re-dropping an already-dropped agent is an idempotent 204.
func (s *Server) dropAgent(w http.ResponseWriter, r *http.Request) {
	networkID, agentID := r.PathValue("networkId"), r.PathValue("agentId")
	if s.requireManager(w, r, networkID) == nil {
		return
	}
	if s.relay.isDropped(networkID, agentID) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	name := s.relay.hubAgentName(agentID)
	if name == "" {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown agent")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.st.DropAgent(ctx, networkID, agentID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	s.relay.dropHubAgent(networkID, agentID)
	if owner, err := s.st.AgentOwner(ctx, name); err == nil && owner == networkID {
		if err := s.hub.EvictAgent(ctx, agentID); err != nil {
			log.Printf("drop agent %s: hub evict not applied: %v", agentID, err)
		}
	} else if err != nil && !store.IsNotFound(err) {
		log.Printf("drop agent %s: ownership check: %v", agentID, err)
	}
	s.broadcastRosterSnapshot(ctx, networkID)
	w.WriteHeader(http.StatusNoContent)
}
