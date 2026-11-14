package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// DM virtual-channel routing (contract §7): the channel id
// `dm:user:<userId>:<agentName>@<deviceId>` is stable both directions,
// carries NO channel row and no member list — persistence reuses the
// per-channel envelope store keyed by the full dm id, and history rides
// the same windowed `/api/channels/{id}/messages` view (owner-only).
//
// Structural ACL (relay-only: the server never reads ciphertext):
//   - user → agent: the sender speaks as `user:<uid>` where uid is BOTH
//     the connection's owner and the dm namespace owner; the target
//     device must belong to that same uid.
//   - agent → user (reply): the sender speaks as `agent:<name>` or the
//     bare `<name>@<device>` address, the connection IS the dm device
//     and the agent is currently exposed on it.
//   - the network on the frame is transport-only: the sender's user
//     must hold membership (same law as channel mail).
//
// Fanout: the dm device plus every live device of the namespace owner
// (one frame per socket, deduped) — inbox views for both parties.

// dmAddress is the parsed virtual channel id.
type dmAddress struct {
	userID    string
	agentName string
	deviceID  string
}

// parseDMChannel splits `dm:user:<uid>:<agent>@<device>`; ok=false on
// any shape violation (empty segments, missing separators).
func parseDMChannel(channel string) (dmAddress, bool) {
	rest, ok := strings.CutPrefix(channel, "dm:user:")
	if !ok {
		return dmAddress{}, false
	}
	uid, agentAddr, ok := strings.Cut(rest, ":")
	if !ok {
		return dmAddress{}, false
	}
	agent, device, ok := strings.Cut(agentAddr, "@")
	if !ok || uid == "" || agent == "" || device == "" {
		return dmAddress{}, false
	}
	return dmAddress{userID: uid, agentName: agent, deviceID: device}, true
}

// deviceDMRoute validates and relays one upstream DM mail frame.
func (s *Server) deviceDMRoute(ctx context.Context, dc *deviceConn, f deviceFrame) {
	if f.MsgID == "" || f.Network == "" || f.Channel == "" || f.Ciphertext == "" {
		s.deviceMailErr(dc, f.MsgID, "invalid_mail")
		return
	}
	dm, ok := parseDMChannel(f.Channel)
	if !ok {
		s.deviceMailErr(dc, f.MsgID, "invalid_mail")
		return
	}
	if _, err := s.st.Member(ctx, f.Network, dc.device.UserID); err != nil {
		s.deviceMailErr(dc, f.MsgID, "not_a_member")
		return
	}
	target, err := s.st.Device(ctx, dm.deviceID)
	if err != nil || target.UserID != dm.userID {
		s.deviceMailErr(dc, f.MsgID, "unknown_device")
		return
	}
	// Sender authorization: user namespace owner, or the exposed agent
	// on the dm device itself.
	var from string
	switch {
	case f.From == "user:"+dc.device.UserID && dc.device.UserID == dm.userID:
		from = dc.device.UserID
	case dc.device.ID == dm.deviceID && s.deviceExposure.ExposedAgent(dm.deviceID, dm.agentName) &&
		(f.From == "agent:"+dm.agentName || f.From == dm.agentName+"@"+dm.deviceID):
		from = dm.agentName + "@" + dm.deviceID
	default:
		s.deviceMailErr(dc, f.MsgID, "sender_not_exposed")
		return
	}

	env := &model.Envelope{
		ID:        f.MsgID,
		ChannelID: f.Channel,
		SenderID:  from,
		Payload:   f.Ciphertext,
		CreatedAt: s.cfg.Now(),
	}
	stored, err := s.st.AppendEnvelope(ctx, env)
	if err != nil {
		s.deviceMailErr(dc, f.MsgID, "store_error")
		return
	}
	if !stored {
		// Duplicate msgId: the first copy is already live — at-least-once
		// upstream of the ack, no error frame.
		return
	}
	if storedEnv, err := s.st.EnvelopeByID(ctx, f.Channel, env.ID); err == nil {
		env = storedEnv
	}
	frame := deviceFrame{
		V: 1, Kind: kindMail, MsgID: env.ID, Network: f.Network,
		Channel: f.Channel, From: from,
		TS: env.CreatedAt.UTC().Format(time.RFC3339), Seq: env.Seq,
		Ciphertext: env.Payload,
	}
	// Fanout: the dm device + every live owner device, one frame each.
	seen := map[*deviceConn]bool{}
	for _, c := range s.deviceConns.OfUsers([]string{dm.userID}) {
		seen[c] = true
	}
	if c := s.deviceConns.OfDevice(dm.deviceID); c != nil {
		seen[c] = true
	}
	for c := range seen {
		s.deviceSend(c, frame)
	}
}

// serveDMMessages answers GET /api/channels/dm:.../messages: the same
// windowed envelope view as channel history, restricted to the dm
// namespace owner (both parties read through the owner's account).
func (s *Server) serveDMMessages(w http.ResponseWriter, r *http.Request, channelID string) {
	principal := s.requireAuthed(w, r)
	if principal == nil {
		return
	}
	dm, ok := parseDMChannel(channelID)
	if !ok || principal.UserID != dm.userID {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown channel")
		return
	}
	s.writeEnvelopePage(w, r, &model.Channel{ID: channelID})
}
