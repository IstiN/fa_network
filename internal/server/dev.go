package server

import (
	"encoding/json"
	"net/http"
)

// devLogin issues a dev JWT for the mock provider only — the offline path
// for UI development and integration tests (card flutter_agent_harness#955).
// Absent under ai-native/oidc providers: the route 404s in production, so
// no management capability can ever ride it (two-class law).
func (s *Server) devLogin(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.auth.(interface {
		IssueToken(login, password string) (string, error)
	})
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "unknown route")
		return
	}
	var body struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Login == "" {
		writeError(w, http.StatusBadRequest, "invalid_credentials", "login and password required")
		return
	}
	token, err := issuer.IssueToken(body.Login, body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid login or password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}
