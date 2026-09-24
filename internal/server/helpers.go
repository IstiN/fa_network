package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/IstiN/fa_network/internal/auth"
	"github.com/IstiN/fa_network/internal/model"
	"github.com/IstiN/fa_network/internal/store"
)

// bearerToken extracts the token from an Authorization: Bearer header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}

// identity is the resolved caller for one request.
type identity struct {
	member    *model.Member   // set when the caller belongs to the network
	principal *auth.Principal // set for JWT-authed callers
	isGuest   bool
	session   *model.Session
}

// class returns the caller's class within the network.
func (i *identity) class() string {
	if i.member != nil {
		return i.member.Class
	}
	if i.isGuest {
		return model.ClassGuest
	}
	return ""
}

// resolveIdentity authenticates the caller against a network. Accepts
// session tokens (join-issued) or ai-native JWTs. Returns nil (and writes
// the 401/403 response) when authentication fails.
func (s *Server) resolveIdentity(w http.ResponseWriter, r *http.Request, networkID string) *identity {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "credentials required")
		return nil
	}
	ctx := r.Context()
	if sess, err := s.st.Session(ctx, token); err == nil {
		member, err := s.st.Member(ctx, networkID, sess.MemberID)
		if err != nil {
			writeError(w, http.StatusForbidden, CodeForbiddenClass, "not a network member")
			return nil
		}
		s.touchSession(ctx, sess)
		return &identity{member: member, session: sess, isGuest: member.Class == model.ClassGuest}
	}
	principal, err := s.auth.Validate(ctx, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid token")
		return nil
	}
	member, err := s.st.Member(ctx, networkID, principal.UserID)
	if err != nil {
		// Authed but not a member of this network.
		writeError(w, http.StatusForbidden, CodeForbiddenClass, "not a network member")
		return nil
	}
	return &identity{member: member, principal: principal}
}

// touchSession stamps activity (retention clock) best-effort.
func (s *Server) touchSession(ctx context.Context, sess *model.Session) {
	_ = s.st.TouchSession(ctx, sess.Token, s.cfg.Now())
	_ = s.st.TouchActivity(ctx, sess.NetworkID, s.cfg.Now())
}

// requireManager gates owner/admin-only routes: authed AND elevated class.
func (s *Server) requireManager(w http.ResponseWriter, r *http.Request, networkID string) *identity {
	id := s.resolveIdentity(w, r, networkID)
	if id == nil {
		return nil
	}
	if id.session != nil && id.isGuest {
		writeError(w, http.StatusForbidden, CodeForbiddenClass, "guests cannot manage")
		return nil
	}
	switch id.class() {
	case model.ClassOwner, model.ClassAdmin:
		return id
	}
	writeError(w, http.StatusForbidden, CodeForbiddenClass, "owner or admin required")
	return nil
}

// requireAuthed gates routes that need a real ai-native JWT (create/manage,
// impossible-by-construction for guests): a session token never passes.
func (s *Server) requireAuthed(w http.ResponseWriter, r *http.Request) *auth.Principal {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "auth token required")
		return nil
	}
	principal, err := s.auth.Validate(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid token")
		return nil
	}
	return principal
}

// resolveNetwork loads a network by id, else by name (join accepts both).
func (s *Server) resolveNetwork(ctx context.Context, idOrName string) (*model.Network, error) {
	n, err := s.st.Network(ctx, idOrName)
	if err == nil {
		return n, nil
	}
	if store.IsNotFound(err) {
		return s.st.NetworkByName(ctx, idOrName)
	}
	return nil, err
}

// isManagerClass reports whether a class may manage (owner/admin).
func isManagerClass(class string) bool {
	return class == model.ClassOwner || class == model.ClassAdmin
}

// memberClass computes the class of an authed user within a network.
func memberClass(n *model.Network, userID string) string {
	if n.OwnerID == userID {
		return model.ClassOwner
	}
	for _, a := range n.Admins {
		if a == userID {
			return model.ClassAdmin
		}
	}
	return model.ClassMember
}

// newToken mints a random session token.
func newToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func nowPtr(t time.Time) *time.Time { return &t }
