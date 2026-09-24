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
// Auth: Bearer <sessionToken> from join. One socket per session.
func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
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
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return
	}
	s.handleWSConn(r.Context(), conn, sess, member)
}

// handleWSConn runs one socket: read pump + write pump + heartbeat.
func (s *Server) handleWSConn(ctx context.Context, conn *websocket.Conn, sess *model.Session, member *model.Member) {
	ws := newWSConn(sess, member.Class)
	s.sessions.Add(ws)
	defer func() {
		s.sessions.Remove(sess.Token)
		s.staleCheck(context.Background(), member)
		conn.CloseNow()
	}()
	s.relay.SyncMemberPresence(ctx, member)

	// Greet: roster snapshot + offline state when the hub is down.
	members, _ := s.st.Members(ctx, sess.NetworkID)
	ws.send <- s.sessions.SnapshotFor(sess.NetworkID, members)
	if !s.hub.Online() {
		ws.send <- wsFrame{Type: "network.offline", Payload: networkOfflineWire{Reason: "hub unreachable"}}
	}

	writeDone := make(chan struct{})
	go s.wsWriteLoop(conn, ws, writeDone)
	s.wsReadPump(ctx, conn, ws, member)
	close(ws.send)
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
		case frame, ok := <-ws.send:
			if !ok {
				return
			}
			if err := wsWrite(conn, frame); err != nil {
				return
			}
		case <-ticker.C:
			if err := wsWrite(conn, wsFrame{Type: "ping"}); err != nil {
				return
			}
			if ws.silentFor(time.Now(), wsGhostAfter) {
				return // ghost: two missed beats (E7)
			}
		}
	}
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
		Mentions  []string `json:"mentions"`
	}
	var empty envelopeInput
	if err := json.Unmarshal(raw, &f); err != nil || f.ChannelID == "" {
		return "", empty, false
	}
	req := envelopeInput{ID: f.ID, Payload: f.Payload, Mentions: f.Mentions}
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
	if channel.Public && member.Class != model.ClassOwner && member.Class != model.ClassAdmin {
		ws.send <- wsFrame{Type: "error", Payload: map[string]string{"code": CodeChannelReadOnly}}
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
