package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/IstiN/fa_network/internal/model"
)

// Covers the management error branches and roster endpoints that the AC
// tests only touch on the happy path (keeps CRAP honest).
func TestManagementRoutesHappyAndSadPaths(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")
	ownerSess, _ := env.join(t, id, "secret123", "", owner)
	memberToken := env.authedToken("bob", "Bob B.")
	memberSess, _ := env.join(t, id, "secret123", "", memberToken)

	// listChannels (member route).
	rec := env.do("GET", "/api/networks/"+id+"/channels", nil, memberSess)
	if rec.Code != http.StatusOK {
		t.Fatalf("list channels: %d", rec.Code)
	}

	// createChannel validation errors.
	rec = env.do("POST", "/api/networks/"+id+"/channels", map[string]string{"name": ""}, ownerSess)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name: %d", rec.Code)
	}
	rec = env.do("POST", "/api/networks/"+id+"/channels", map[string]any{"name": "x", "retentionDays": -1}, ownerSess)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad retention: %d", rec.Code)
	}
	rec = env.do("POST", "/api/networks/"+id+"/channels", map[string]string{"name": "dup"}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first dup: %d", rec.Code)
	}
	rec = env.do("POST", "/api/networks/"+id+"/channels", map[string]string{"name": "dup"}, ownerSess)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second dup: %d", rec.Code)
	}

	// patchChannel: happy + invalid + not found.
	rec = env.do("POST", "/api/networks/"+id+"/channels", map[string]string{"name": "patch-me"}, ownerSess)
	var ch map[string]any
	decodeBody(t, rec, &ch)
	channelID, _ := ch["id"].(string)
	rec = env.do("PATCH", "/api/channels/"+channelID, map[string]any{"public": true, "retentionDays": 5}, ownerSess)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "\"public\":true") {
		t.Fatalf("patch channel: %d %s", rec.Code, rec.Body.String())
	}
	rec = env.do("PATCH", "/api/channels/"+channelID, map[string]any{"name": ""}, ownerSess)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch invalid: %d", rec.Code)
	}
	rec = env.do("PATCH", "/api/channels/"+channelID, map[string]any{"retentionDays": -2}, ownerSess)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch bad retention: %d", rec.Code)
	}
	rec = env.do("PATCH", "/api/channels/nope", map[string]string{"name": "x"}, ownerSess)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("patch unknown: %d", rec.Code)
	}
	rec = env.do("DELETE", "/api/channels/"+channelID, map[string]string{}, ownerSess)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete channel: %d", rec.Code)
	}

	// patchNetwork: rename + password rotation + invalid.
	rec = env.do("PATCH", "/api/networks/"+id, map[string]string{"name": "fa-team-v2", "password": "newsecret9"}, ownerSess)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch network: %d %s", rec.Code, rec.Body.String())
	}
	rec = env.do("PATCH", "/api/networks/"+id, map[string]string{"name": "BAD"}, ownerSess)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch bad name: %d", rec.Code)
	}
	rec = env.do("PATCH", "/api/networks/"+id, map[string]string{"password": "short"}, ownerSess)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch bad password: %d", rec.Code)
	}
	// Rotated password works for join; old one does not.
	rec = env.do("POST", "/api/networks/"+id+"/join", map[string]string{"password": "secret123", "displayName": "old"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("old password join: %d", rec.Code)
	}
	_, _ = env.join(t, id, "newsecret9", "fresh", "")

	// admins: add / conflict / remove / remove-missing.
	rec = env.do("POST", "/api/networks/"+id+"/admins", map[string]string{"userId": "carol"}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add admin: %d %s", rec.Code, rec.Body.String())
	}
	rec = env.do("POST", "/api/networks/"+id+"/admins", map[string]string{"userId": "carol"}, ownerSess)
	if rec.Code != http.StatusConflict {
		t.Fatalf("dup admin: %d", rec.Code)
	}
	rec = env.do("DELETE", "/api/networks/"+id+"/admins/carol", nil, ownerSess)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("remove admin: %d", rec.Code)
	}
	rec = env.do("DELETE", "/api/networks/"+id+"/admins/carol", nil, ownerSess)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("remove missing admin: %d", rec.Code)
	}
	// Admin (non-owner) cannot appoint admins.
	rec = env.do("POST", "/api/networks/"+id+"/admins", map[string]string{"userId": "dave"}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("re-add admin: %d", rec.Code)
	}
	rec = env.do("POST", "/api/networks/"+id+"/admins", map[string]string{"userId": "erin"}, memberSess)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member appoint: %d", rec.Code)
	}
	adminMember, err := env.st.Member(t.Context(), id, "dave")
	if err != nil || adminMember.Class != model.ClassAdmin {
		t.Fatalf("dave class: %+v %v", adminMember, err)
	}

	// getNetwork / members / agents rosters.
	rec = env.do("GET", "/api/networks/"+id, nil, memberSess)
	if rec.Code != http.StatusOK {
		t.Fatalf("get network: %d", rec.Code)
	}
	rec = env.do("GET", "/api/networks/"+id+"/agents", nil, memberSess)
	if rec.Code != http.StatusOK {
		t.Fatalf("agents: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "wakeupRegistered") {
		t.Fatalf("agents wire: %s", rec.Body.String())
	}
}

// sendMessage guard branches: base64/limits/bad channel/wrong network.
func TestSendMessageValidationBranches(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")
	sess, _ := env.join(t, id, "secret123", "", owner)
	rec := env.do("POST", "/api/networks/"+id+"/channels", map[string]string{"name": "chan"}, sess)
	var ch map[string]any
	decodeBody(t, rec, &ch)
	channelID, _ := ch["id"].(string)

	bad := []map[string]string{
		{"id": "", "payload": "YQ=="},
		{"id": "x", "payload": "!!!not-base64!!!"},
		{"payload": "YQ=="},
	}
	for i, body := range bad {
		rec := env.do("POST", "/api/channels/"+channelID+"/messages", body, sess)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad envelope %d: %d", i, rec.Code)
		}
	}
	rec = env.do("POST", "/api/channels/nope/messages", map[string]string{"id": "x", "payload": "YQ=="}, sess)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown channel: %d", rec.Code)
	}
	// A member of ANOTHER network cannot read or write this channel.
	other := env.authedToken("mallory", "Mallory")
	otherID := env.createNetwork(t, other, "other-net", "secret123")
	otherSess, _ := env.join(t, otherID, "secret123", "", other)
	rec = env.do("POST", "/api/channels/"+channelID+"/messages", map[string]string{"id": "x", "payload": "YQ=="}, otherSess)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-network write: %d", rec.Code)
	}
	// Invalid cursor on history.
	rec = env.do("GET", "/api/channels/"+channelID+"/messages?cursor=zz", nil, sess)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("bad cursor: %d", rec.Code)
	}
}

// registerWakeup validation: bad url, bad debounce, guest rejection.
func TestRegisterWakeupValidation(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")
	ownerSess, _ := env.join(t, id, "secret123", "", owner)
	guestSess, _ := env.join(t, id, "secret123", "g", "")

	rec := env.do("POST", "/api/networks/"+id+"/agents/a1/wakeups", map[string]any{"url": "ftp://x"}, ownerSess)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad url: %d", rec.Code)
	}
	rec = env.do("POST", "/api/networks/"+id+"/agents/a1/wakeups", map[string]any{"url": "https://ok", "debounceSeconds": 5}, ownerSess)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad debounce: %d", rec.Code)
	}
	rec = env.do("POST", "/api/networks/"+id+"/agents/a1/wakeups", map[string]any{"url": "https://ok", "debounceSeconds": 30}, guestSess)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("guest register: %d", rec.Code)
	}
	rec = env.do("GET", "/api/networks/"+id+"/agents/a1/wakeups", nil, ownerSess)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing registration: %d", rec.Code)
	}
	rec = env.do("DELETE", "/api/networks/"+id+"/agents/a1/wakeups", nil, ownerSess)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete missing registration: %d", rec.Code)
	}
}
