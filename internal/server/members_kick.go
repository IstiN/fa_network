package server

import (
	"log"
	"net/http"

	"github.com/IstiN/fa_network/internal/model"
)

// kickMember implements DELETE /api/networks/{id}/members/{memberId}
// (owner/admin, authed): removes a store member (guest/member/agent
// class) from the roster, revokes their sessions and disconnects their
// sockets. Owner/admin rows are protected (use the admins endpoints for
// admin demotion; the owner is immutable). Idempotent: 204 for unknown
// or already-removed members.
func (s *Server) kickMember(w http.ResponseWriter, r *http.Request) {
	networkID, memberID := r.PathValue("networkId"), r.PathValue("memberId")
	if s.requireManager(w, r, networkID) == nil {
		return
	}
	ctx := r.Context()
	member, err := s.st.Member(ctx, networkID, memberID)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if member.Class == model.ClassOwner || member.Class == model.ClassAdmin {
		writeError(w, http.StatusForbidden, CodeForbiddenClass, "cannot kick owner/admin")
		return
	}
	if err := s.st.DeleteMember(ctx, networkID, memberID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	// Session rows are hygiene: even without them the deleted member row
	// makes every token useless (member lookup fails closed).
	if err := s.st.DeleteSessionsOfMember(ctx, networkID, memberID); err != nil {
		log.Printf("kick member %s/%s: session cleanup: %v", networkID, memberID, err)
	}
	s.sessions.KickMember(networkID, memberID)
	s.broadcastRosterSnapshot(ctx, networkID)
	w.WriteHeader(http.StatusNoContent)
}
