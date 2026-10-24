package server

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/IstiN/fa_network/internal/triggers"
)

// Webhook ingress (issue #3): public, signature-verified SCM/generic
// endpoints. Routes stay JWT-free by design — authenticity is the
// provider secret, never a session. All triggers are relay-only: the
// prompt is forwarded to the CI worker, never decrypted or stored here.

const (
	CodeWebhookNotConfigured = "webhooks_not_configured"
	CodeWakeupNotConfigured  = "wakeup_not_configured"
	CodeWakeupFailed         = "wakeup_failed"
	CodeInvalidPayload       = "invalid_payload"
	webhookMaxBody           = 1 << 20
)

// handleWebhook returns the ingress handler for one provider.
func (s *Server) handleWebhook(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.triggers == nil {
			writeError(w, http.StatusServiceUnavailable, CodeWebhookNotConfigured, "webhook ingress disabled")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, webhookMaxBody))
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalidPayload, "cannot read payload")
			return
		}
		if !s.triggers.Authenticate(provider, r.Header, body) {
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid webhook signature")
			return
		}
		event, err := s.triggers.Parse(provider, r.Header, body)
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalidPayload, err.Error())
			return
		}
		s.handleWebhookEvent(w, r, event)
	}
}

func (s *Server) handleWebhookEvent(w http.ResponseWriter, r *http.Request, event *triggers.Event) {
	switch event.Kind {
	case triggers.KindPing:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "event": "ping"})
	case triggers.KindIgnored:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored", "reason": event.Reason})
	default:
		s.processTrigger(w, r, event)
	}
}

// processTrigger routes one normalized trigger: live agent (with the
// grace-window CI fallback) or immediate CI wake-up.
func (s *Server) processTrigger(w http.ResponseWriter, r *http.Request, event *triggers.Event) {
	t := event.Trigger
	if event.Reaction != nil {
		s.ackReaction(*event.Reaction)
	}
	agentID, online := s.relay.AgentOnlineByNameOrID(t.SessionKey)
	if online && !s.triggers.AlwaysFallback() {
		s.watchGrace(t)
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "accepted", "sessionKey": t.SessionKey, "mode": "live", "agentId": agentID,
		})
		return
	}
	s.dispatchWakeup(w, r, t)
}

// dispatchWakeup fires the CI adapter and maps the outcome to the
// documented statuses (202 dispatched / 503 unconfigured / 502 failed).
func (s *Server) dispatchWakeup(w http.ResponseWriter, r *http.Request, t *triggers.Trigger) {
	backend, err := s.triggers.Dispatch(r.Context(), t)
	if errors.Is(err, triggers.ErrNoBackend) {
		writeError(w, http.StatusServiceUnavailable, CodeWakeupNotConfigured, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, CodeWakeupFailed, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "dispatched", "sessionKey": t.SessionKey, "mode": "ci_wakeup", "backend": backend,
	})
}

// watchGrace implements the 5-second grace-window guard: an agent that
// was online when the event arrived but drops offline within the window
// gets the CI wake-up anyway (catch-up inbox dedupes by comment_id).
func (s *Server) watchGrace(t *triggers.Trigger) {
	period := s.triggers.GracePeriod()
	go func() {
		timer := time.NewTimer(period)
		defer timer.Stop()
		<-timer.C
		if _, online := s.relay.AgentOnlineByNameOrID(t.SessionKey); online {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err := s.triggers.Dispatch(ctx, t); err != nil {
			log.Printf("webhooks: grace-window wakeup for %s: %v", t.SessionKey, err)
		}
	}()
}

// ackReaction leaves the best-effort 👀 on the originating comment.
func (s *Server) ackReaction(reaction triggers.Reaction) {
	if !s.triggers.CanReact() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.triggers.ReactEyes(ctx, reaction); err != nil {
			log.Printf("webhooks: eyes reaction on %s: %v", reaction.Repo, err)
		}
	}()
}
