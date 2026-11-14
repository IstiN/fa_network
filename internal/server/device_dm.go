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
	dm, code := s.dmTarget(ctx, dc, f)
	if code != "" {
		s.deviceMailErr(dc, f.MsgID, code)
		return
	}
	from, code := s.dmSender(dc, dm, f.From)
	if code != "" {
		s.deviceMailErr(dc, f.MsgID, code)
		return
	}
	s.relayDM(ctx, dc, dm, f, from)
}

// dmTarget resolves the structural target ACL: frame shape, dm channel
// shape, network membership and target-device ownership. An empty code
// means the parsed address is routable.
func (s *Server) dmTarget(ctx context.Context, dc *deviceConn, f deviceFrame) (dmAddress, string) {
	if f.MsgID == "" || f.Network == "" || f.Channel == "" || f.Ciphertext == "" {
		return dmAddress{}, "invalid_mail"
	}
	dm, ok := parseDMChannel(f.Channel)
	if !ok {
		return dmAddress{}, "invalid_mail"
	}
	if _, err := s.st.Member(ctx, f.Network, dc.device.UserID); err != nil {
		return dmAddress{}, "not_a_member"
	}
	target, err := s.st.Device(ctx, dm.deviceID)
	if err != nil || target.UserID != dm.userID {
		return dmAddress{}, "unknown_device"
	}
	return dm, ""
}

// dmSender authorizes the wire `from`: the user namespace owner, or the
// exposed agent on the dm device itself (both accepted spellings).
func (s *Server) dmSender(dc *deviceConn, dm dmAddress, from string) (string, string) {
	if from == "user:"+dc.device.UserID && dc.device.UserID == dm.userID {
		return dc.device.UserID, ""
	}
	if dc.device.ID == dm.deviceID &&
		s.deviceExposure.ExposedAgent(dm.deviceID, dm.agentName) &&
		(from == "agent:"+dm.agentName || from == dm.agentName+"@"+dm.deviceID) {
		return dm.agentName + "@" + dm.deviceID, ""
	}
	return "", "sender_not_exposed"
}

// relayDM persists (dedup by msgId) and fans out one authorized DM.
func (s *Server) relayDM(ctx context.Context, dc *deviceConn, dm dmAddress, f deviceFrame, from string) {
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
		Channel: f.Channel, From: from, To: f.To,
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
