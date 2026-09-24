package server

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/IstiN/fa_network/internal/auth"
	"github.com/IstiN/fa_network/internal/model"
	"github.com/IstiN/fa_network/internal/store"
)

var networkNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type networkCreateRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// createNetwork implements POST /api/networks (AC-B1: authed only, creator
// becomes owner; guests get 401 with zero side effects).
func (s *Server) createNetwork(w http.ResponseWriter, r *http.Request) {
	principal := s.requireAuthed(w, r)
	if principal == nil {
		return
	}
	req, ok := decodeNetworkCreate(w, r)
	if !ok {
		return
	}
	network, err := s.insertNetwork(r, principal, &req)
	if err != nil {
		writeStoreErr(w, err, "network name taken")
		return
	}
	s.seedOwnerMember(r, network, principal)
	writeJSON(w, http.StatusCreated, map[string]any{
		"network":         model.NetworkWireOf(network),
		"joinCredentials": model.JoinCredentialsWire{NetworkID: network.ID, Password: req.Password},
	})
}

func decodeNetworkCreate(w http.ResponseWriter, r *http.Request) (networkCreateRequest, bool) {
	var req networkCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validNetworkCreate(&req) {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "name or password invalid")
		return req, false
	}
	return req, true
}

func validNetworkCreate(req *networkCreateRequest) bool {
	return validNetworkName(req.Name) && len(req.Password) >= 8 && len(req.Password) <= 128
}

func (s *Server) insertNetwork(r *http.Request, principal *auth.Principal, req *networkCreateRequest) (*model.Network, error) {
	if _, err := s.st.NetworkByName(r.Context(), req.Name); err == nil {
		return nil, store.ErrConflict
	} else if !store.IsNotFound(err) {
		return nil, err
	}
	hash, salt, err := s.passwords.Hash(req.Password)
	if err != nil {
		return nil, err
	}
	network := &model.Network{
		ID:           newToken(),
		Name:         req.Name,
		OwnerID:      principal.UserID,
		CreatedAt:    s.cfg.Now(),
		PasswordHash: hash,
		PasswordSalt: salt,
	}
	if err := s.st.CreateNetwork(r.Context(), network); err != nil {
		return nil, err
	}
	return network, nil
}

func (s *Server) seedOwnerMember(r *http.Request, network *model.Network, principal *auth.Principal) {
	_ = s.st.UpsertMember(r.Context(), &model.Member{
		ID:          principal.UserID,
		NetworkID:   network.ID,
		Class:       model.ClassOwner,
		DisplayName: principal.DisplayName,
		Presence:    model.PresenceOffline,
	})
}

func validNetworkName(name string) bool {
	return len(name) >= 3 && len(name) <= 64 && networkNamePattern.MatchString(name)
}

type joinRequest struct {
	Password    string `json:"password"`
	DisplayName string `json:"displayName"`
}

// joinNetwork implements POST /api/networks/{id}/join (AC-B2). Auth is
// OPTIONAL: authed joiners carry the locked auth-service name; guests ride
// as agent-class identities with deduped display names.
func (s *Server) joinNetwork(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	networkID := r.PathValue("networkId")
	network, err := s.resolveNetwork(ctx, networkID)
	if err != nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown network")
		return
	}
	failKey := r.RemoteAddr + "|" + network.ID
	if blocked, retry := s.failures.Blocked(failKey, 5); blocked {
		writeErrorRetry(w, http.StatusTooManyRequests, CodeThrottled, "too many failed attempts", retry)
		return
	}
	var req joinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "password required")
		return
	}
	if !s.passwords.Verify(req.Password, network.PasswordHash, network.PasswordSalt) {
		s.failures.RecordFailure(failKey)
		writeErrorRetry(w, http.StatusForbidden, CodeInvalidCreds, "invalid credentials", 0)
		return
	}
	if !s.limiter.Allow("join|"+failKey, 30, minuteWindow) {
		writeErrorRetry(w, http.StatusTooManyRequests, CodeThrottled, "joins throttled", 60)
		return
	}
	s.failures.Reset(failKey)

	token := bearerToken(r)
	if token != "" {
		if principal, err := s.auth.Validate(ctx, token); err == nil {
			s.joinAsAuthed(w, r, network, principal)
			return
		}
	}
	s.joinAsGuest(w, r, network, req.DisplayName)
}

const minuteWindow = time.Minute

// joinAsAuthed locks the display name to the auth-service identity (AC-B2).
func (s *Server) joinAsAuthed(w http.ResponseWriter, r *http.Request, network *model.Network, principal *auth.Principal) {
	ctx := r.Context()
	class := memberClass(network, principal.UserID)
	member := &model.Member{
		ID:          principal.UserID,
		NetworkID:   network.ID,
		Class:       class,
		DisplayName: principal.DisplayName,
		Presence:    model.PresenceOffline,
	}
	if existing, err := s.st.Member(ctx, network.ID, principal.UserID); err == nil {
		member.Presence = existing.Presence
	}
	if err := s.st.UpsertMember(ctx, member); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	s.respondJoined(w, r, network, member, principal.DisplayName, principal.DisplayName)
}

// joinAsGuest creates (or reuses) an agent-class identity with a deduped
// display name (`name (2)` on collision — E2).
func (s *Server) joinAsGuest(w http.ResponseWriter, r *http.Request, network *model.Network, displayName string) {
	ctx := r.Context()
	name := strings.TrimSpace(displayName)
	if name == "" || len(name) > 64 {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "displayName required for guest join")
		return
	}
	base := name
	for i := 2; ; i++ {
		if _, err := s.st.MemberByName(ctx, network.ID, name); store.IsNotFound(err) {
			break
		}
		name = guestName(base, i)
	}
	memberID := "g_" + newToken()[:12]
	member := &model.Member{
		ID:          memberID,
		NetworkID:   network.ID,
		Class:       model.ClassGuest,
		DisplayName: name,
		Presence:    model.PresenceOffline,
	}
	if err := s.st.UpsertMember(ctx, member); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	s.respondJoined(w, r, network, member, name, "")
}

func guestName(base string, n int) string {
	return base + " (" + strconv.Itoa(n) + ")"
}

// respondJoined issues the session token and the join response contract.
func (s *Server) respondJoined(w http.ResponseWriter, r *http.Request, network *model.Network, member *model.Member, displayName, authName string) {
	ctx := r.Context()
	sess := &model.Session{
		Token:     newToken(),
		NetworkID: network.ID,
		MemberID:  member.ID,
		CreatedAt: s.cfg.Now(),
		LastSeen:  s.cfg.Now(),
	}
	if err := s.st.CreateSession(ctx, sess); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	_ = s.st.TouchActivity(ctx, network.ID, s.cfg.Now())
	identity := model.IdentityWire{ID: member.ID, Class: member.Class, DisplayName: displayName}
	if authName != "" {
		identity.AuthName = authName
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessionToken": sess.Token,
		"identity":     identity,
		"network":      model.NetworkWireOf(network),
	})
}

// getNetwork implements GET /api/networks/{id} (member).
func (s *Server) getNetwork(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("networkId")
	if id := s.resolveIdentity(w, r, id); id == nil {
		return
	}
	network, err := s.resolveNetwork(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown network")
		return
	}
	writeJSON(w, http.StatusOK, model.NetworkWireOf(network))
}

type networkUpdateRequest struct {
	Name     *string `json:"name"`
	Password *string `json:"password"`
}

// patchNetwork implements PATCH (owner/admin, authed only — E9).
func (s *Server) patchNetwork(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("networkId")
	if s.requireManager(w, r, id) == nil {
		return
	}
	network, err := s.st.Network(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown network")
		return
	}
	var req networkUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "bad json")
		return
	}
	if !s.applyNetworkUpdate(network, &req) {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "invalid network update")
		return
	}
	if err := s.st.UpdateNetwork(r.Context(), network); err != nil {
		if store.IsConflict(err) {
			writeError(w, http.StatusConflict, CodeConflict, "network name taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	writeJSON(w, http.StatusOK, model.NetworkWireOf(network))
}

// applyNetworkUpdate mutates the network (false = invalid request).
func (s *Server) applyNetworkUpdate(network *model.Network, req *networkUpdateRequest) bool {
	if req.Name != nil {
		if !validNetworkName(*req.Name) {
			return false
		}
		network.Name = *req.Name
	}
	return s.rotatePassword(network, req.Password)
}

func (s *Server) rotatePassword(network *model.Network, password *string) bool {
	if password == nil {
		return true
	}
	if len(*password) < 8 || len(*password) > 128 {
		return false
	}
	hash, salt, err := s.passwords.Hash(*password)
	if err != nil {
		return false
	}
	network.PasswordHash = hash
	network.PasswordSalt = salt
	return true
}

// deleteNetwork implements DELETE (owner only).
func (s *Server) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("networkId")
	idn := s.requireManager(w, r, id)
	if idn == nil {
		return
	}
	if idn.class() != model.ClassOwner {
		writeError(w, http.StatusForbidden, CodeForbiddenClass, "owner required")
		return
	}
	if err := s.wipeNetwork(r, id); err != nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown network")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) wipeNetwork(r *http.Request, id string) error {
	ctx := r.Context()
	if err := s.st.DeleteNetworkData(ctx, id); err != nil {
		return err
	}
	return s.st.DeleteNetwork(ctx, id)
}

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
func (s *Server) appointAdmin(r *http.Request, networkID, userID string) (*model.Member, error) {
	ctx := r.Context()
	network, err := s.st.Network(ctx, networkID)
	if err != nil {
		return nil, err
	}
	if containsString(network.Admins, userID) {
		return nil, store.ErrConflict
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

// listMembers implements GET .../members (member roster with presence).
func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("networkId")
	if s.resolveIdentity(w, r, id) == nil {
		return
	}
	members, err := s.st.Members(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	wires := make([]model.MemberWire, 0, len(members))
	for _, m := range members {
		wires = append(wires, model.MemberWireOf(m))
	}
	writeJSON(w, http.StatusOK, wires)
}
