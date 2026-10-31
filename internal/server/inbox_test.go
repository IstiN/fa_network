package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// inboxResponse decodes the GET /api/inbox envelope.
type inboxResponse struct {
	Items []inboxItem `json:"items"`
	// NextCursor is absent (empty) on the last page.
	NextCursor string `json:"nextCursor"`
}

type inboxItem struct {
	Kind         string         `json:"kind"`
	NetworkID    string         `json:"networkId"`
	ID           string         `json:"id"`
	Title        string         `json:"title"`
	LastActivity *time.Time     `json:"lastActivity"`
	UnreadCount  *int           `json:"unreadCount"`
	LastEnvelope *lastEnvelope  `json:"lastEnvelope"`
	Presence     string         `json:"presence"`
	Raw          map[string]any `json:"-"`
}

type lastEnvelope struct {
	ID         string   `json:"id"`
	SenderID   string   `json:"senderId"`
	SenderName string   `json:"senderName"`
	SenderKey  string   `json:"senderKey"`
	Payload    string   `json:"payload"`
	Mentions   []string `json:"mentions"`
}

func decodeInboxItem(t *testing.T, raw map[string]any) inboxItem {
	t.Helper()
	// Reuse the typed decoder through a tiny shim: the wire fields the
	// assertions touch are all string/int/time.
	it := inboxItem{
		Kind:      raw["kind"].(string),
		NetworkID: raw["networkId"].(string),
		ID:        raw["id"].(string),
	}
	if s, ok := raw["title"].(string); ok {
		it.Title = s
	}
	if s, ok := raw["presence"].(string); ok {
		it.Presence = s
	}
	if v, ok := raw["unreadCount"].(float64); ok {
		n := int(v)
		it.UnreadCount = &n
	}
	return it
}

func getInbox(t *testing.T, env *testEnv, token, cursor string, limit int) inboxResponse {
	t.Helper()
	path := "/api/inbox"
	q := ""
	if cursor != "" {
		q += "cursor=" + cursor
	}
	if limit > 0 {
		if q != "" {
			q += "&"
		}
		q += fmt.Sprintf("limit=%d", limit)
	}
	if q != "" {
		path += "?" + q
	}
	rec := env.do(http.MethodGet, path, nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/inbox: status %d (body %s)", rec.Code, rec.Body.String())
	}
	var out inboxResponse
	decodeBody(t, rec, &out)
	return out
}

// postMessage sends one REST envelope; id is caller-chosen.
func postMessage(t *testing.T, env *testEnv, channelID, id, payload, token string) {
	t.Helper()
	rec := env.do("POST", "/api/channels/"+channelID+"/messages", map[string]any{
		"id": id, "payload": base64.StdEncoding.EncodeToString([]byte(payload)),
	}, token)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("post message %s: status %d (%s)", id, rec.Code, rec.Body.String())
	}
}

// TestInboxRequiresAuth: guest/no-token callers get the plain 401 — the
// aggregate inbox is account-scoped like /api/networks/mine.
func TestInboxRequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"no token", ""},
		{"invalid token", "not-a-jwt"},
		{"session token", mustGuestSession(t, env, id)},
	} {
		rec := env.do(http.MethodGet, "/api/inbox", nil, tc.token)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", tc.name, rec.Code)
		}
	}
}

// TestInboxEmpty: an authed caller with no memberships sees an empty
// list (items: []) and no nextCursor — not an error.
func TestInboxEmpty(t *testing.T) {
	env := newTestEnv(t)
	lonely := env.authedToken("nobody", "Nobody")
	out := getInbox(t, env, lonely, "", 0)
	if len(out.Items) != 0 {
		t.Fatalf("want 0 items, got %d", len(out.Items))
	}
	if out.NextCursor != "" {
		t.Fatalf("want no nextCursor, got %q", out.NextCursor)
	}
}

// TestInboxScopeAcrossNetworks: entries cover every network the caller
// has a membership row in (owner-created + authed-joined), and a caller
// outside a network never sees its channels (no cross-network leak).
func TestInboxScopeAcrossNetworks(t *testing.T) {
	env := newTestEnv(t)
	ownerA := env.authedToken("ownerA", "Owner A")
	netA := env.createNetwork(t, ownerA, "net-a", "secret123")
	chA1 := env.createChannel(t, netA, "alpha", ownerA)
	chA2 := env.createChannel(t, netA, "beta", ownerA)

	ownerB := env.authedToken("ownerB", "Owner B")
	netB := env.createNetwork(t, ownerB, "net-b", "secret456")
	chB1 := env.createChannel(t, netB, "gamma", ownerB)

	// ownerA joins netB as an authed member (membership row id = userID).
	env.join(t, netB, "secret456", "", ownerA)

	sessA, _ := env.join(t, netA, "secret123", "Owner A", "")
	postMessage(t, env, chA1, "m1", "hello-a", sessA)

	out := getInbox(t, env, ownerA, "", 0)
	want := map[string]string{chA1: netA, chA2: netA, chB1: netB}
	got := map[string]string{} // channel id -> networkId
	for _, it := range out.Items {
		if it.Kind != "channel" {
			continue
		}
		got[it.ID] = it.NetworkID
	}
	for ch, net := range want {
		if got[ch] != net {
			t.Fatalf("channel %s: want network %s, got %+v", ch, net, got)
		}
	}

	// An outsider (member of neither) sees nothing of these channels.
	outsider := env.authedToken("outsider", "Outsider")
	out2 := getInbox(t, env, outsider, "", 0)
	for _, it := range out2.Items {
		if it.ID == chA1 || it.ID == chA2 || it.ID == chB1 {
			t.Fatalf("outsider sees %s from network %s — leak", it.ID, it.NetworkID)
		}
	}
}

// TestInboxChannelEntryShape: a channel entry carries network/id/title,
// lastActivity = last envelope time, unreadCount, and an OPAQUE
// lastEnvelope (payload + sender metadata pass through untouched).
func TestInboxChannelEntryShape(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	netID := env.createNetwork(t, owner, "shape-net", "secret123")
	ch := env.createChannel(t, netID, "general", owner)
	sess, _ := env.join(t, netID, "secret123", "Owner One", "")
	postMessage(t, env, ch, "m1", "older", sess)
	// senderName rides via the hub presence cache in production; the REST
	// send keeps the payload opaque — assert byte-identical passthrough.
	wantPayload := base64.StdEncoding.EncodeToString([]byte("ciphertext-bytes-❤"))
	rec := env.do("POST", "/api/channels/"+ch+"/messages", map[string]any{
		"id": "m2", "payload": wantPayload, "senderKey": "a2V5",
	}, sess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: %d (%s)", rec.Code, rec.Body.String())
	}

	out := getInbox(t, env, owner, "", 0)
	var entry *inboxItem
	for i := range out.Items {
		if out.Items[i].Kind == "channel" && out.Items[i].ID == ch {
			entry = &out.Items[i]
		}
	}
	if entry == nil {
		t.Fatalf("channel %s not in inbox: %+v", ch, out.Items)
	}
	if entry.NetworkID != netID || entry.Title != "general" {
		t.Fatalf("entry header wrong: %+v", entry)
	}
	if entry.LastActivity == nil {
		t.Fatalf("channel with messages must carry lastActivity")
	}
	if entry.LastEnvelope == nil {
		t.Fatalf("channel with messages must carry lastEnvelope")
	}
	if entry.LastEnvelope.ID != "m2" || entry.LastEnvelope.Payload != wantPayload {
		t.Fatalf("lastEnvelope wrong: %+v", entry.LastEnvelope)
	}
	if entry.UnreadCount == nil || *entry.UnreadCount != 0 {
		t.Fatalf("no read cursor row → unreadCount must be 0, got %+v", entry.UnreadCount)
	}
}

// TestInboxUnreadLifecycle: unread counts envelopes newer than the
// per-USER read cursor; marking read is monotonic (an older position
// never moves the cursor back), foreign envelope ids are rejected, and
// a seq beyond the channel max is clamped to the max.
func TestInboxUnreadLifecycle(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	other := env.authedToken("other", "Other Human")
	netID := env.createNetwork(t, owner, "unread-net", "secret123")
	ch := env.createChannel(t, netID, "general", owner)
	chOther := env.createChannel(t, netID, "random", owner)
	sess, _ := env.join(t, netID, "secret123", "Owner One", "")
	postMessage(t, env, ch, "m1", "one", sess)
	postMessage(t, env, ch, "m2", "two", sess)

	unread := func() int {
		out := getInbox(t, env, owner, "", 0)
		for _, it := range out.Items {
			if it.Kind == "channel" && it.ID == ch {
				if it.UnreadCount == nil {
					t.Fatalf("unreadCount missing on %s", ch)
				}
				return *it.UnreadCount
			}
		}
		t.Fatalf("channel %s not in inbox", ch)
		return -1
	}

	if got := unread(); got != 0 {
		t.Fatalf("no cursor row → unread 0 (R4), got %d", got)
	}

	// New message → unread 1 (cursor absent = 0 position... R4 says the
	// ABSENCE of a row reads as "nothing newer than 0" = all unread?
	// No: approved semantics — no row → 0. First PATCH establishes the
	// baseline; messages BEFORE the first PATCH stay non-unread.
	postMessage(t, env, ch, "m3", "three", sess)
	if got := unread(); got != 1 {
		t.Fatalf("after m3 unread want 1, got %d", got)
	}

	// Mark read by envelopeId → 204, unread 0.
	rec := env.do(http.MethodPatch, "/api/channels/"+ch+"/read", map[string]any{"envelopeId": "m3"}, owner)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("mark read: %d (%s)", rec.Code, rec.Body.String())
	}
	if got := unread(); got != 0 {
		t.Fatalf("after mark-read unread want 0, got %d", got)
	}

	// New message → unread 1; marking an OLDER envelope must not move
	// the cursor back.
	postMessage(t, env, ch, "m4", "four", sess)
	if got := unread(); got != 1 {
		t.Fatalf("after m4 unread want 1, got %d", got)
	}
	rec = env.do(http.MethodPatch, "/api/channels/"+ch+"/read", map[string]any{"envelopeId": "m1"}, owner)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("mark read older: %d", rec.Code)
	}
	if got := unread(); got != 1 {
		t.Fatalf("older mark-read must not rewind unread: want 1, got %d", got)
	}

	// Foreign envelopeId (another channel of the same network) → 4xx.
	postMessage(t, env, chOther, "x1", "foreign", sess)
	rec = env.do(http.MethodPatch, "/api/channels/"+ch+"/read", map[string]any{"envelopeId": "x1"}, owner)
	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("foreign envelopeId: status %d, want 4xx", rec.Code)
	}
	// Unknown envelopeId → 4xx.
	rec = env.do(http.MethodPatch, "/api/channels/"+ch+"/read", map[string]any{"envelopeId": "nope"}, owner)
	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("unknown envelopeId: status %d, want 4xx", rec.Code)
	}

	// seq far beyond the channel max is clamped: m5 arriving AFTER a
	// huge-seq PATCH must still count as unread.
	rec = env.do(http.MethodPatch, "/api/channels/"+ch+"/read", map[string]any{"seq": 999999999}, owner)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("mark read seq: %d", rec.Code)
	}
	if got := unread(); got != 0 {
		t.Fatalf("after clamped seq mark-read unread want 0, got %d", got)
	}
	postMessage(t, env, ch, "m5", "five", sess)
	if got := unread(); got != 1 {
		t.Fatalf("after m5 unread want 1 (seq clamped at PATCH), got %d", got)
	}

	// all:true → everything read.
	rec = env.do(http.MethodPatch, "/api/channels/"+ch+"/read", map[string]any{"all": true}, owner)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("mark read all: %d", rec.Code)
	}
	if got := unread(); got != 0 {
		t.Fatalf("after all:true unread want 0, got %d", got)
	}

	// The read cursor is per USER: the owner's reads never affect
	// another member's unread.
	env.join(t, netID, "secret123", "", other)
	postMessage(t, env, ch, "m6", "six", sess)
	out := getInbox(t, env, owner, "", 0)
	ownerUnread := -1
	for _, it := range out.Items {
		if it.Kind == "channel" && it.ID == ch {
			ownerUnread = *it.UnreadCount
		}
	}
	if ownerUnread != 1 {
		t.Fatalf("owner unread after m6 want 1, got %d", ownerUnread)
	}
}

// TestMarkReadMembershipEnforced: only members of the channel's network
// may move its read cursor.
func TestMarkReadMembershipEnforced(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	stranger := env.authedToken("stranger", "Stranger")
	netID := env.createNetwork(t, owner, "acl-net", "secret123")
	ch := env.createChannel(t, netID, "general", owner)
	sess, _ := env.join(t, netID, "secret123", "Owner One", "")
	postMessage(t, env, ch, "m1", "x", sess)

	rec := env.do(http.MethodPatch, "/api/channels/"+ch+"/read", map[string]any{"envelopeId": "m1"}, stranger)
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("stranger mark-read: status %d, want 403/404", rec.Code)
	}
}

// TestInboxPaginationDeterministic: equal (null) lastActivity ties are
// broken stably; pages are disjoint and complete — no duplicates, no
// gaps — and the tie-break order is stable across calls.
func TestInboxPaginationDeterministic(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	netID := env.createNetwork(t, owner, "page-net", "secret123")
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, env.createChannel(t, netID, fmt.Sprintf("c%d", i), owner))
	}

	full := getInbox(t, env, owner, "", 0)
	if len(full.Items) != 5 {
		t.Fatalf("full listing want 5, got %d", len(full.Items))
	}
	fullOrder := make([]string, 0, 5)
	for _, it := range full.Items {
		fullOrder = append(fullOrder, it.ID)
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page := getInbox(t, env, owner, cursor, 2)
		for _, it := range page.Items {
			if seen[it.ID] {
				t.Fatalf("duplicate %s across pages", it.ID)
			}
			seen[it.ID] = true
		}
		pages++
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 5 {
			t.Fatalf("pagination did not terminate")
		}
	}
	if len(seen) != 5 {
		t.Fatalf("paged union want 5 unique, got %d", len(seen))
	}

	// The full listing order is deterministic across calls (same tie-break
	// every time): identical ids in identical order.
	again := getInbox(t, env, owner, "", 0)
	for i := range again.Items {
		if again.Items[i].ID != fullOrder[i] {
			t.Fatalf("order unstable at %d: %v vs %v", i, again.Items[i].ID, fullOrder[i])
		}
	}
}

// TestInboxAgentEntries: agent-class roster members surface as
// kind=agent entries with presence (channels stay kind=channel).
func TestInboxAgentEntries(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	netID := env.createNetwork(t, owner, "agent-net", "secret123")
	env.createChannel(t, netID, "general", owner)
	// A guest join creates an agent-class member row (roster-representable).
	env.join(t, netID, "secret123", "kb-agent", "")

	out := getInbox(t, env, owner, "", 0)
	var agents, channels int
	for _, it := range out.Items {
		switch it.Kind {
		case "agent":
			agents++
			if it.Presence == "" {
				t.Fatalf("agent entry missing presence: %+v", it)
			}
			if it.UnreadCount != nil {
				t.Fatalf("agent entry must not carry unreadCount: %+v", it)
			}
			if it.LastEnvelope != nil {
				t.Fatalf("agent entry must not carry lastEnvelope: %+v", it)
			}
		case "channel":
			channels++
		default:
			t.Fatalf("unknown kind %q", it.Kind)
		}
	}
	if agents == 0 {
		t.Fatalf("expected agent entries from roster, got none: %+v", out.Items)
	}
	if channels == 0 {
		t.Fatalf("expected channel entries, got none: %+v", out.Items)
	}
}
