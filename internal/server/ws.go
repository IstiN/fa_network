package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/IstiN/fa_network/internal/model"
)

// WS tuning: 30s heartbeat, ghost cleanup after two missed beats (E7).
const (
	wsHeartbeat  = 30 * time.Second
	wsGhostAfter = 65 * time.Second
)

// serveWS implements GET /ws — the realtime session (WebSocket upgrade).
// Auth: Bearer <sessionToken> from join, or a single-use ?ticket= minted
// by POST /api/ws-ticket (browser clients; review #7), or the legacy
// ?token= fallback. One socket per session.
func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		// Single-use ticket first: consume happens before any further
		// validation, so a redeemed ticket can never be replayed even
		// if the session underneath fails.
		if t := r.URL.Query().Get("ticket"); t != "" {
			if redeemed, ok := s.tickets.consume(t); ok {
				token = redeemed
			}
		}
	}
	if token == "" {
		// Legacy fallback: browsers cannot set Authorization. The
		// bearer rides in the URL only until clients migrate to
		// tickets (review #7); server logs never carry it further.
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "session token required")
		return
	}
	sess, err := s.st.Session(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid session token")
		return
	}
	member, err := s.st.Member(r.Context(), sess.NetworkID, sess.MemberID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid session")
		return
	}
	// Browser cross-origin upgrades must follow the SAME allowlist as
	// REST CORS (coder's default would reject every cross-origin app).
	// Same-host upgrades stay allowed inside coder; requests without an
	// Origin header (agents, CLIs) are unaffected.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: s.corsOrigins})
	if err != nil {
		return
	}
	s.handleWSConn(r.Context(), conn, sess, member)
}

// handleWSConn runs one socket: read pump + write pump + heartbeat.
func (s *Server) handleWSConn(ctx context.Context, conn *websocket.Conn, sess *model.Session, member *model.Member) {
	ws := newWSConn(sess, member.Class)
	ws.closeConn = func() { _ = conn.CloseNow() }
	s.sessions.Add(ws)
	defer func() {
		s.sessions.Remove(sess.Token)
		s.staleCheck(context.Background(), member)
		conn.CloseNow()
	}()
	s.relay.SyncMemberPresence(ctx, member)

	// Greet: roster snapshot (members + DAP hub agents, issue #4) +
	// offline state when the hub is down.
	members, _ := s.st.Members(ctx, sess.NetworkID)
	members = append(members, s.relay.hubAgentMembers(sess.NetworkID, members)...)
	s.relay.decorateAccess(ctx, members)
	ws.send <- s.sessions.SnapshotFor(sess.NetworkID, members)
	if !s.hub.Online() {
		ws.send <- wsFrame{Type: "network.offline", Payload: networkOfflineWire{Reason: "hub unreachable"}}
	}

	writeDone := make(chan struct{})
	go s.wsWriteLoop(conn, ws, writeDone)
	s.wsReadPump(ctx, conn, ws, member)
	ws.shutdown()
	<-writeDone
}

// staleCheck recomputes a member's presence after their last socket dies.
func (s *Server) staleCheck(ctx context.Context, member *model.Member) {
	fresh, err := s.st.Member(ctx, member.NetworkID, member.ID)
	if err != nil {
		return
	}
	s.relay.SyncMemberPresence(ctx, fresh)
}

// wsWriteLoop pumps queued frames and the 30s heartbeat to the socket.
func (s *Server) wsWriteLoop(conn *websocket.Conn, ws *wsConn, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(wsHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case frame := <-ws.send:
			if err := wsWrite(conn, frame); err != nil {
				return
			}
		case <-ws.done:
			return
		case <-ticker.C:
			if s.wsHeartbeat(conn, ws) {
				return // write failed or ghost: two missed beats (E7)
			}
		}
	}
}

// wsHeartbeat sends a keepalive and reports whether the socket is dead.
func (s *Server) wsHeartbeat(conn *websocket.Conn, ws *wsConn) bool {
	if err := wsWrite(conn, wsFrame{Type: "ping"}); err != nil {
		return true
	}
	return ws.silentFor(time.Now(), wsGhostAfter)
}

func wsWrite(conn *websocket.Conn, frame wsFrame) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, raw)
}

// wsReadPump decodes client frames until disconnect.
func (s *Server) wsReadPump(ctx context.Context, conn *websocket.Conn, ws *wsConn, member *model.Member) {
	for {
		_, raw, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var frame struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &frame); err != nil {
			continue
		}
		s.handleClientFrame(ctx, ws, member, frame.Type, raw)
	}
}

// handleClientFrame routes one client→server frame.
func (s *Server) handleClientFrame(ctx context.Context, ws *wsConn, member *model.Member, typ string, raw json.RawMessage) {
	switch typ {
	case "ping":
		ws.markPong()
		deliver(ws, wsFrame{Type: "pong"})
	case "subscribe":
		ws.setSub(subFrameChannel(raw), true)
	case "unsubscribe":
		ws.setSub(subFrameChannel(raw), false)
	case "envelope.send":
		s.wsEnvelopeSend(ctx, ws, member, raw)
	}
}

func subFrameChannel(raw json.RawMessage) string {
	var f struct {
		ChannelID string `json:"channelId"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return ""
	}
	return f.ChannelID
}

// parseWSSend decodes an envelope.send frame (channelId + EnvelopeInput).
func parseWSSend(raw json.RawMessage) (string, envelopeInput, bool) {
	var f struct {
		ChannelID string   `json:"channelId"`
		ID        string   `json:"id"`
		Payload   string   `json:"payload"`
		SenderKey string   `json:"senderKey"`
		Mentions  []string `json:"mentions"`
	}
	var empty envelopeInput
	if err := json.Unmarshal(raw, &f); err != nil || f.ChannelID == "" {
		return "", empty, false
	}
	req := envelopeInput{ID: f.ID, Payload: f.Payload, SenderKey: f.SenderKey, Mentions: f.Mentions}
	if !validEnvelopeInput(&req) {
		return "", empty, false
	}
	return f.ChannelID, req, true
}

// wsEnvelopeSend relays one socket-originated envelope (same contract as
// the REST POST, including the public-channel write guard). The frame
// carries channelId alongside the EnvelopeInput fields.
func (s *Server) wsEnvelopeSend(ctx context.Context, ws *wsConn, member *model.Member, raw json.RawMessage) {
	channelID, req, ok := parseWSSend(raw)
	if !ok {
		return
	}
	channel, err := s.st.Channel(ctx, channelID)
	if err != nil || channel.NetworkID != member.NetworkID {
		return
	}
	if !s.wsSendAllowed(ctx, ws, member, channel) {
		return
	}
	env := &model.Envelope{
		ID:        req.ID,
		ChannelID: channel.ID,
		SenderID:  member.ID,
		Payload:   req.Payload,
		Mentions:  model.DedupeMentions(req.Mentions),
		CreatedAt: s.cfg.Now(),
	}
	stored, err := s.st.AppendEnvelope(ctx, env)
	if err != nil || !stored {
		return
	}
	s.relay.Outbound(ctx, env)
	s.relay.Mentions(ctx, channel.NetworkID, env)
	s.sessions.FanoutEnvelope(channel.NetworkID, model.EnvelopeWireOf(env))
}

// wsSendAllowed applies the same guards as the REST send path: public
// channels are owner/admin-write only, per-member rate limit and the
// per-channel stored-byte cap. Failures emit an error frame (store
// errors drop silently, matching the REST idempotency style).
func (s *Server) wsSendAllowed(ctx context.Context, ws *wsConn, member *model.Member, channel *model.Channel) bool {
	if channel.Public && member.Class != model.ClassOwner && member.Class != model.ClassAdmin {
		ws.send <- wsFrame{Type: "error", Payload: map[string]string{"code": CodeChannelReadOnly}}
		return false
	}
	// Same abuse controls as the REST send path (review #6): per-member
	// rate limit and the per-channel stored-byte cap.
	if !s.limiter.Allow("send|"+member.ID, 20, time.Minute) {
		ws.send <- wsFrame{Type: "error", Payload: map[string]string{"code": CodeThrottled}}
		return false
	}
	over, err := s.overByteCap(ctx, channel.ID)
	if err != nil {
		return false
	}
	if over {
		ws.send <- wsFrame{Type: "error", Payload: map[string]string{"code": CodeThrottled}}
		return false
	}
	return true
}
