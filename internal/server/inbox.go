package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// inboxDefaultLimit / inboxMaxLimit bound GET /api/inbox pages.
const (
	inboxDefaultLimit = 50
	inboxMaxLimit     = 100
)

// inboxItemView is the handler-side merge view of one conversation row
// (store channel entry or roster agent) plus its total sort key.
type inboxItemView struct {
	wire     model.InboxItemWire
	activity time.Time // zero = no activity (sorts last, stably)
}

// key is the stable sort tuple: activity, networkId, id. Pages continue
// strictly BELOW the last emitted key — no duplicates, no gaps.
type inboxCursorKey struct {
	nano      int64
	networkID string
	id        string
}

func (v inboxItemView) key() inboxCursorKey {
	return inboxCursorKey{nano: v.activity.UnixNano(), networkID: v.wire.NetworkID, id: v.wire.ID}
}

// before is the strict total order over keys (newest activity first,
// then networkId/id DESC as the deterministic tie-break).
func (a inboxCursorKey) before(b inboxCursorKey) bool {
	if a.nano != b.nano {
		return a.nano > b.nano
	}
	if a.networkID != b.networkID {
		return a.networkID > b.networkID
	}
	return a.id > b.id
}

func (k inboxCursorKey) encode() string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%d\x00%s\x00%s", k.nano, k.networkID, k.id)))
}

func decodeInboxCursor(s string) (inboxCursorKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return inboxCursorKey{}, err
	}
	parts := strings.SplitN(string(raw), "\x00", 3)
	if len(parts) != 3 {
		return inboxCursorKey{}, fmt.Errorf("bad cursor")
	}
	nano, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return inboxCursorKey{}, err
	}
	return inboxCursorKey{nano: nano, networkID: parts[1], id: parts[2]}, nil
}

// getInbox implements GET /api/inbox — the account-scoped aggregate
// conversation list across every network the caller holds a membership
// row in (JWT like /api/networks/mine; session tokens are NOT enough).
// Channel entries carry an OPAQUE last envelope (client-side preview
// decrypt; the server never decodes payloads) and a per-USER unread
// count; agent entries are roster-only presence hints.
func (s *Server) getInbox(w http.ResponseWriter, r *http.Request) {
	principal := s.requireAuthed(w, r)
	if principal == nil {
		return
	}
	views, err := s.inboxViews(r, principal.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	out, err := paginateInboxViews(views, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// inboxViews assembles the fully ordered merge view: store channel
// entries plus roster agents of every membership network.
func (s *Server) inboxViews(r *http.Request, userID string) ([]inboxItemView, error) {
	entries, err := s.st.InboxEntries(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	accountNets, err := s.st.AccountNetworks(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	networks := make([]string, 0, len(accountNets))
	for _, an := range accountNets {
		networks = append(networks, an.Network.ID)
	}
	views := inboxChannelViews(entries)
	views = append(views, s.inboxAgentViews(r, networks)...)
	sortInboxViews(views)
	return views, nil
}

// inboxChannelViews projects store entries: unread count + OPAQUE last
// envelope (preview decryption is client-side, never here).
func inboxChannelViews(entries []*model.InboxEntry) []inboxItemView {
	views := make([]inboxItemView, 0, len(entries))
	for _, entry := range entries {
		unread := entry.UnreadCount
		item := model.InboxItemWire{
			Kind:        "channel",
			NetworkID:   entry.Channel.NetworkID,
			ID:          entry.Channel.ID,
			Title:       entry.Channel.Name,
			UnreadCount: &unread,
		}
		var activity time.Time
		if entry.LastEnvelope != nil {
			at := entry.LastEnvelope.CreatedAt
			item.LastActivity = &at
			env := model.EnvelopeWireOf(entry.LastEnvelope)
			item.LastEnvelope = &env
			activity = at
		}
		views = append(views, inboxItemView{wire: item, activity: activity})
	}
	return views
}

// inboxAgentViews merges roster agents of the given networks —
// presence hint only (no unread, no envelope; DMs are not relay
// channels). A roster failure degrades to no entries, never a 500.
func (s *Server) inboxAgentViews(r *http.Request, networkIDs []string) []inboxItemView {
	views := []inboxItemView{}
	for _, networkID := range networkIDs {
		agents, err := s.relay.Agents(r.Context(), networkID)
		if err != nil {
			continue
		}
		views = append(views, agentWiresToViews(networkID, agents)...)
	}
	return views
}

func agentWiresToViews(networkID string, agents []model.AgentWire) []inboxItemView {
	views := []inboxItemView{}
	for _, a := range agents {
		item := model.InboxItemWire{
			Kind:      "agent",
			NetworkID: networkID,
			ID:        a.AgentID,
			Title:     a.DisplayName,
			Presence:  a.Presence,
		}
		var activity time.Time
		if a.LastSeen != nil {
			item.LastActivity = a.LastSeen
			activity = *a.LastSeen
		}
		views = append(views, inboxItemView{wire: item, activity: activity})
	}
	return views
}

// sortInboxViews orders newest activity first with the deterministic
// (networkId, id) DESC tie-break — the same total order the cursor
// paginates, so equal/null activities never duplicate or gap.
func sortInboxViews(views []inboxItemView) {
	for i := 1; i < len(views); i++ {
		for j := i; j > 0 && views[j].key().before(views[j-1].key()); j-- {
			views[j], views[j-1] = views[j-1], views[j]
		}
	}
}

// inboxPage is one bounded slice of the ordered views.
type inboxPage struct {
	items   []model.InboxItemWire
	lastKey inboxCursorKey
	hasMore bool
}

// sliceInbox cuts the page that continues strictly below `after`
// (zero key = first page) at the given limit.
func sliceInbox(views []inboxItemView, after inboxCursorKey, hasCursor bool, limit int) inboxPage {
	start := 0
	if hasCursor {
		for start < len(views) && !after.before(views[start].key()) {
			start++
		}
	}
	end := start + limit
	if end > len(views) {
		end = len(views)
	}
	items := make([]model.InboxItemWire, 0, end-start)
	for _, v := range views[start:end] {
		items = append(items, v.wire)
	}
	var lastKey inboxCursorKey
	if end > start {
		lastKey = views[end-1].key()
	}
	return inboxPage{
		items:   items,
		lastKey: lastKey,
		hasMore: end < len(views),
	}
}

// paginateInboxViews applies limit/cursor to the ordered views.
func paginateInboxViews(views []inboxItemView, r *http.Request) (model.InboxResponseWire, error) {
	limit := queryInt(r, "limit", inboxDefaultLimit)
	if limit <= 0 {
		limit = inboxDefaultLimit
	}
	if limit > inboxMaxLimit {
		limit = inboxMaxLimit
	}
	var after inboxCursorKey
	hasCursor := false
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		k, err := decodeInboxCursor(raw)
		if err != nil {
			return model.InboxResponseWire{}, err
		}
		after, hasCursor = k, true
	}
	page := sliceInbox(views, after, hasCursor, limit)
	out := model.InboxResponseWire{Items: page.items}
	if page.hasMore {
		out.NextCursor = page.lastKey.encode()
	}
	return out, nil
}

// readMarkInput is the PATCH /read body: exactly one of seq, envelopeId,
// all.
type readMarkInput struct {
	Seq        *int64 `json:"seq"`
	EnvelopeID string `json:"envelopeId"`
	All        bool   `json:"all"`
}

// markChannelRead implements PATCH /api/channels/{id}/read — advance the
// CALLER's per-user (cross-device) read cursor. Body: {"seq": n} |
// {"envelopeId": "…"} | {"all": true}. Positions are monotonic and
// clamped to the channel max; a foreign envelope id is a 4xx.
func (s *Server) markChannelRead(w http.ResponseWriter, r *http.Request) {
	principal := s.requireAuthed(w, r)
	if principal == nil {
		return
	}
	channel := s.loadChannel(w, r)
	if channel == nil {
		return
	}
	// Membership gate: the same class ruling as channel reads (E1 — the
	// generic 404/403 never leaks channel existence to strangers).
	if s.resolveIdentity(w, r, channel.NetworkID) == nil {
		return
	}
	if err := s.applyReadMark(r, principal.UserID, channel); err != nil {
		var client *readMarkClientError
		if errors.As(err, &client) {
			writeError(w, http.StatusBadRequest, "bad_request", client.msg)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// readMarkClientError marks a 4xx read-mark failure (bad body, foreign
// envelope id); anything else is a store failure (500).
type readMarkClientError struct{ msg string }

func (e *readMarkClientError) Error() string { return e.msg }

// applyReadMark validates the body and advances the cursor.
func (s *Server) applyReadMark(r *http.Request, userID string, channel *model.Channel) error {
	var body readMarkInput
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return &readMarkClientError{msg: "invalid body"}
	}
	switch {
	case body.All:
		return s.markReadToMax(r, userID, channel.ID)
	case body.Seq != nil:
		return s.st.MarkRead(r.Context(), userID, channel.ID, *body.Seq)
	case body.EnvelopeID != "":
		return s.markReadByEnvelope(r, userID, channel, body.EnvelopeID)
	}
	return &readMarkClientError{msg: "seq, envelopeId or all required"}
}

func (s *Server) markReadToMax(r *http.Request, userID, channelID string) error {
	maxSeq, err := s.st.ChannelMaxSeq(r.Context(), channelID)
	if err != nil {
		return err
	}
	return s.st.MarkRead(r.Context(), userID, channelID, maxSeq)
}

// markReadByEnvelope resolves the envelope INSIDE the channel — a
// foreign or unknown id is a client error, never a silent cursor move.
func (s *Server) markReadByEnvelope(r *http.Request, userID string, channel *model.Channel, envelopeID string) error {
	env, err := s.st.EnvelopeByID(r.Context(), channel.ID, envelopeID)
	if err != nil {
		return &readMarkClientError{msg: "envelope not in this channel"}
	}
	return s.st.MarkRead(r.Context(), userID, channel.ID, env.Seq)
}
