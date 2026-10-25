package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/IstiN/fa_network/internal/model"
	"github.com/IstiN/fa_network/internal/store"
)

// addAdmin implements POST .../admins (owner only, authed).
func (s *Server) addAdmin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("networkId")
	if !s.requireOwner(w, r, id) {
		return
	}
	var req struct {
		UserID string `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "userId required")
		return
	}
	member, err := s.appointAdmin(r, id, req.UserID)
	if err != nil {
		if err == errGuestPromotion {
			writeError(w, http.StatusForbidden, CodeForbiddenClass, "guests cannot be promoted to admin")
			return
		}
		if store.IsConflict(err) {
			writeError(w, http.StatusConflict, CodeConflict, "already admin")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	writeJSON(w, http.StatusCreated, model.MemberWireOf(member))
}

// requireOwner gates owner-only routes.
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request, networkID string) bool {
	idn := s.requireManager(w, r, networkID)
	if idn == nil {
		return false
	}
	if idn.class() != model.ClassOwner {
		writeError(w, http.StatusForbidden, CodeForbiddenClass, "owner required")
		return false
	}
	return true
}

// appointAdmin promotes a user to network admin (idempotent per network).
var errGuestPromotion = errors.New("guest/agent members cannot become admins")

func (s *Server) appointAdmin(r *http.Request, networkID, userID string) (*model.Member, error) {
	ctx := r.Context()
	network, err := s.st.Network(ctx, networkID)
	if err != nil {
		return nil, err
	}
	if containsString(network.Admins, userID) {
		return nil, store.ErrConflict
	}
	// Two-class law: guest/agent rows carry no authenticated provenance —
	// promoting one would turn its already-issued guest token into a
	// management token. Only authed members can become admins.
	if existing, err := s.st.Member(ctx, networkID, userID); err == nil &&
		(existing.Class == model.ClassGuest || existing.Class == model.ClassAgent) {
		return nil, errGuestPromotion
	}
	network.Admins = append(network.Admins, userID)
	if err := s.st.UpdateNetwork(ctx, network); err != nil {
		return nil, err
	}
	return s.promoteMember(ctx, networkID, userID)
}

func containsString(list []string, v string) bool {
	for _, a := range list {
		if a == v {
			return true
		}
	}
	return false
}

func (s *Server) promoteMember(ctx context.Context, networkID, userID string) (*model.Member, error) {
	member := &model.Member{
		ID:          userID,
		NetworkID:   networkID,
		Class:       model.ClassAdmin,
		DisplayName: userID,
		Presence:    model.PresenceOffline,
	}
	if existing, err := s.st.Member(ctx, networkID, userID); err == nil {
		member.DisplayName = existing.DisplayName
		member.Presence = existing.Presence
	}
	if err := s.st.UpsertMember(ctx, member); err != nil {
		return nil, err
	}
	return member, nil
}

// removeAdmin implements DELETE .../admins/{userId} (owner only).
func (s *Server) removeAdmin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("networkId")
	if !s.requireOwner(w, r, id) {
		return
	}
	userID := r.PathValue("userId")
	if err := s.revokeAdmin(r, id, userID); err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, CodeNotFound, "not an admin")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeAdmin demotes a network admin back to member.
func (s *Server) revokeAdmin(r *http.Request, networkID, userID string) error {
	ctx := r.Context()
	network, err := s.st.Network(ctx, networkID)
	if err != nil {
		return err
	}
	kept, found := withoutUser(network.Admins, userID)
	if !found {
		return store.ErrNotFound
	}
	network.Admins = kept
	if err := s.st.UpdateNetwork(ctx, network); err != nil {
		return err
	}
	s.demoteMember(ctx, networkID, userID)
	return nil
}

func withoutUser(list []string, userID string) ([]string, bool) {
	kept := list[:0]
	found := false
	for _, a := range list {
		if a == userID {
			found = true
			continue
		}
		kept = append(kept, a)
	}
	return kept, found
}

func (s *Server) demoteMember(ctx context.Context, networkID, userID string) {
	member, err := s.st.Member(ctx, networkID, userID)
	if err == nil && member.Class == model.ClassAdmin {
		member.Class = model.ClassMember
		_ = s.st.UpsertMember(ctx, member)
	}
}
