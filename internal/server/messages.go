package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

const maxEnvelopePayloadBytes = 256 << 10

type envelopeInput struct {
	ID        string   `json:"id"`
	Payload   string   `json:"payload"`
	SenderKey string   `json:"senderKey,omitempty"`
	Mentions  []string `json:"mentions,omitempty"`
}

// getMessages implements GET /api/channels/{id}/messages — opaque envelope
// history (AC-B4: payloads are ciphertext, this server never decrypts).
func (s *Server) getMessages(w http.ResponseWriter, r *http.Request) {
	channel := s.loadChannel(w, r)
	if channel == nil {
		return
	}
	if s.resolveIdentity(w, r, channel.NetworkID) == nil {
		return
	}
	limit := queryInt(r, "limit", 50)
	if limit > 200 {
		limit = 200
	}
	page, err := s.st.Envelopes(r.Context(), channel.ID, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown cursor")
		return
	}
	items := make([]model.EnvelopeWire, 0, len(page.Items))
	for _, e := range page.Items {
		items = append(items, model.EnvelopeWireOf(&e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": page.NextCursor})
}

// sendMessage implements POST — relay-accept with public-channel write
// guard (AC-B5: non-owner write into a public channel → 403
// channel_read_only). The payload is never parsed; @tag addressing rides
// in `mentions` as agent ids (identity metadata, never content).
func (s *Server) sendMessage(w http.ResponseWriter, r *http.Request) {
	channel := s.loadChannel(w, r)
	if channel == nil {
		return
	}
	idn := s.resolveIdentity(w, r, channel.NetworkID)
	if idn == nil {
		return
	}
	var req envelopeInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validEnvelopeInput(&req) {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "invalid envelope")
		return
	}
	if channel.Public && !isManagerClass(idn.class()) {
		writeError(w, http.StatusForbidden, CodeChannelReadOnly, "public channel is read-only for non-owners")
		return
	}
	if !s.sendAllowed(w, r, idn, channel.ID) {
		return
	}
	env := &model.Envelope{
		ID:        req.ID,
		ChannelID: channel.ID,
		SenderID:  idn.member.ID,
		SenderKey: req.SenderKey,
		Payload:   req.Payload,
		Mentions:  model.DedupeMentions(req.Mentions),
		CreatedAt: s.cfg.Now(),
	}
	stored, err := s.st.AppendEnvelope(r.Context(), env)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	if stored {
		// The id is the at-least-once dedup key on every hop (AC-B7): a
		// retried send (same id) relays nothing — the first copy is live.
		s.relay.Outbound(r.Context(), env)
		s.relay.Mentions(r.Context(), channel.NetworkID, env)
		s.sessions.FanoutEnvelope(channel.NetworkID, model.EnvelopeWireOf(env))
	}
	if !stored {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusAccepted, model.EnvelopeWireOf(env))
}

// sendAllowed combines the member rate limit and the channel byte cap.
func (s *Server) sendAllowed(w http.ResponseWriter, r *http.Request, idn *identity, channelID string) bool {
	if !s.limiter.Allow("send|"+idn.member.ID, 20, time.Minute) {
		writeErrorRetry(w, http.StatusTooManyRequests, CodeThrottled, "sends throttled", 5)
		return false
	}
	over, err := s.overByteCap(r, channelID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return false
	}
	if over {
		writeErrorRetry(w, http.StatusTooManyRequests, CodeThrottled, "channel storage cap reached", 300)
		return false
	}
	return true
}

// overByteCap enforces the per-channel stored-byte abuse guard.
func (s *Server) overByteCap(r *http.Request, channelID string) (bool, error) {
	total, err := s.st.ChannelBytes(r.Context(), channelID)
	if err != nil {
		return false, err
	}
	return total > s.cfg.ChannelBytesCap, nil
}

// validEnvelopeInput enforces the EnvelopeInput contract: non-empty id,
// base64 payload within the cap. The content itself stays opaque.
func validEnvelopeInput(req *envelopeInput) bool {
	if req.ID == "" || len(req.ID) > 64 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil || len(raw) > maxEnvelopePayloadBytes {
		return false
	}
	return validSenderKey(req.SenderKey)
}

// validSenderKey: optional X25519 pubkey (base64, 32 raw bytes). Pure
// directory metadata — the payload stays opaque.
func validSenderKey(key string) bool {
	if key == "" {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(raw) <= 64
}

func queryInt(r *http.Request, key string, fallback int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
