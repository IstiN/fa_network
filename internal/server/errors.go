package server

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Error codes of the OpenAPI contract (docs/openapi.yaml).
const (
	CodeUnauthorized    = "unauthorized"
	CodeInvalidCreds    = "invalid_credentials"
	CodeForbiddenClass  = "forbidden_by_class"
	CodeChannelReadOnly = "channel_read_only"
	CodeThrottled       = "throttled"
	CodeNotFound        = "not_found"
	CodeConflict        = "conflict"
)

// Healthz answers the liveness probe with a static ok payload.
func Healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}

func writeErrorRetry(w http.ResponseWriter, status int, code, msg string, retryAfter int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeError(w, status, code, msg)
}
