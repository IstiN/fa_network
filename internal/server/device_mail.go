package server

import (
	"context"
	"strings"
	"time"

	"github.com/IstiN/fa_network/internal/model"
	"github.com/IstiN/fa_network/internal/store"
)

// Envelope v1 mail routing (machine-connector contract §3).
//
// Upstream (device → server): route by (network, channel, to), dedup by
// msgId (= envelope id, the at-least-once key on every hop), preserve
// per-sender order (one read pump per socket processes frames
// sequentially; the store stamps Seq under its own lock). The server
// never reads ciphertext (relay-only law) — every rejection below is
// STRUCTURAL (contract v1.1 §6): membership, channel existence, class
// write guard, exposed-sender check. Content ACL lives on the connector.
//
// Downstream (server → device): one mail frame per envelope for every
// live device socket whose user holds membership in the network — the
// connector muxes channel mail for its exposed agents plus DM (phase C).

// deviceMailErr is the structural-rejection frame (refId = the msgId).
func (s *Server) deviceMailErr(dc *deviceConn, msgID, code string) {
	s.deviceSend(dc, deviceFrame{V: 1, Kind: kindError, RefID: msgID,
		TS: s.cfg.Now().UTC().Format(time.RFC3339), Ciphertext: `{"code":"` + code + `"}`})
}

// mailTarget resolves the structural ACL for one upstream mail frame:
// the routable channel + canonical sender, or a rejection code (§6 —
// all structural: membership, channel existence, class guard, exposure).
func (s *Server) mailTarget(ctx context.Context, dc *deviceConn, f deviceFrame) (*model.Channel, string, string) {
	// Membership: the device speaks for its user — no membership row, no
	// route (not-member-network negative).
	member, err := s.st.Member(ctx, f.Network, dc.device.UserID)
	if err != nil {
		return nil, "", "not_a_member"
	}
	channel, err := s.deviceChannel(ctx, f.Network, f.Channel)
	if err != nil || channel.NetworkID != f.Network {
		return nil, "", "unknown_channel"
	}
	// Law 4: public channels are showcases — write for owners/admins.
	if channel.Public && !isManagerClass(member.Class) {
		return nil, "", "channel_read_only"
	}
	// Exposed-sender check: the connector may speak as its user or as an
	// agent it currently exposes (never-exposed from = structural reject).
	from := s.canonicalFrom(dc, f.From)
	if from == "" {
		return nil, "", "sender_not_exposed"
	}
	return channel, from, ""
}

// deviceMailRoute validates and relays one upstream mail frame.
func (s *Server) deviceMailRoute(ctx context.Context, dc *deviceConn, f deviceFrame) {
	// Shape: msgId (the dedup + fanet1 frameId), network, channel and
	// ciphertext are all required for channel mail (contract §3).
	if f.MsgID == "" || f.Network == "" || f.Channel == "" || f.Ciphertext == "" {
		s.deviceMailErr(dc, f.MsgID, "invalid_mail")
		return
	}
	if strings.HasPrefix(f.Channel, "dm:") {
		// DM routing lands with phase C (§7); reject structurally so the
		// connector never assumes a silent drop.
		s.deviceMailErr(dc, f.MsgID, "dm_not_routed_yet")
		return
	}
	channel, from, code := s.mailTarget(ctx, dc, f)
	if code != "" {
		s.deviceMailErr(dc, f.MsgID, code)
		return
	}

	env := &model.Envelope{
		ID:        f.MsgID,
		ChannelID: channel.ID,
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
		// Duplicate msgId: the first copy is already live and will be
		// (re)delivered — at-least-once upstream of the ack. No error.
		return
	}
	// The store owns Seq: read the persisted row so the device fanout
	// carries the authoritative position (AppendEnvelope does not stamp
	// the caller's struct).
	if storedEnv, err := s.st.EnvelopeByID(ctx, channel.ID, env.ID); err == nil {
		env = storedEnv
	}
	s.relay.Outbound(ctx, env)
	s.relay.Mentions(ctx, channel.NetworkID, env)
	s.sessions.FanoutEnvelope(channel.NetworkID, model.EnvelopeWireOf(env))
	s.fanoutDeviceMail(channel.NetworkID, env)
}

// canonicalFrom resolves the wire `from` address against this device's
// exposure state: "user:<id>" (self) or an exposed agent address.
// Empty = rejected sender (not exposed / foreign address).
func (s *Server) canonicalFrom(dc *deviceConn, from string) string {
	if from == "user:"+dc.device.UserID {
		return dc.device.UserID
	}
	addr, ok := strings.CutPrefix(from, "agent:")
	if ok && s.deviceExposure.ExposedAgent(dc.device.ID, addr) {
		return addr
	}
	return ""
}

// fanoutDeviceMail enqueues one stored envelope to every live device
// socket whose user is a member of the network (the connector acks after
// its local write; unacked frames ride the per-device mailbox).
func (s *Server) fanoutDeviceMail(networkID string, env *model.Envelope) {
	for _, dc := range s.deviceConns.OfUsers(s.memberUserIDs(networkID)) {
		s.deviceSend(dc, deviceFrame{
			V: 1, Kind: kindMail, MsgID: env.ID, Network: networkID,
			Channel: env.ChannelID, From: env.SenderID,
			TS: env.CreatedAt.UTC().Format(time.RFC3339), Seq: env.Seq,
			Ciphertext: env.Payload,
		})
	}
}

// memberUserIDs lists the user ids holding membership rows in a network.
func (s *Server) memberUserIDs(networkID string) []string {
	members, err := s.st.Members(context.Background(), networkID)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.ID)
	}
	return ids
}

// deviceChannel resolves a mail target by id, falling back to name
// (contract §3: "group channel id"; names keep CLI/connector ergonomics).
func (s *Server) deviceChannel(ctx context.Context, networkID, idOrName string) (*model.Channel, error) {
	ch, err := s.st.Channel(ctx, idOrName)
	if err == nil {
		return ch, nil
	}
	if !store.IsNotFound(err) {
		return nil, err
	}
	return s.st.ChannelByName(ctx, networkID, idOrName)
}
