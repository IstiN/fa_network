package server

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// senderKey echoes end-to-end: REST send → stored → history + WS fan-out.
func TestSendMessageCarriesSenderKey(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	netID := env.createNetwork(t, owner, "key-net", "password123")
	sess, _ := env.join(t, netID, "password123", "Alice", "")

	chID := env.createChannel(t, netID, "general", owner)
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	payload := base64.StdEncoding.EncodeToString([]byte("ciphertext"))

	rec := env.do("POST", "/api/channels/"+chID+"/messages", map[string]any{
		"id": "msg-1", "payload": payload, "senderKey": key,
	}, sess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"senderKey":"`+key+`"`) {
		t.Fatalf("send response missing senderKey: %s", rec.Body.String())
	}

	hist := env.do("GET", "/api/channels/"+chID+"/messages", nil, sess)
	if !strings.Contains(hist.Body.String(), `"senderKey":"`+key+`"`) {
		t.Fatalf("history missing senderKey: %s", hist.Body.String())
	}
}

func TestSendMessageRejectsMalformedSenderKey(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	netID := env.createNetwork(t, owner, "badkey-net", "password123")
	sess, _ := env.join(t, netID, "password123", "Alice", "")
	chID := env.createChannel(t, netID, "general", owner)

	rec := env.do("POST", "/api/channels/"+chID+"/messages", map[string]any{
		"id": "msg-2", "payload": base64.StdEncoding.EncodeToString([]byte("ct")),
		"senderKey": "!!!not-base64!!!",
	}, sess)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestSenderKeyOmittedWhenAbsent(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	netID := env.createNetwork(t, owner, "nokey-net", "password123")
	sess, _ := env.join(t, netID, "password123", "Alice", "")
	chID := env.createChannel(t, netID, "general", owner)

	rec := env.do("POST", "/api/channels/"+chID+"/messages", map[string]any{
		"id": "msg-3", "payload": base64.StdEncoding.EncodeToString([]byte("ct")),
	}, sess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "senderKey") {
		t.Fatalf("senderKey must be omitted, got: %s", rec.Body.String())
	}
}

// createChannel creates a channel as the owner and returns its id.
func (e *testEnv) createChannel(t *testing.T, networkID, name, ownerToken string) string {
	t.Helper()
	rec := e.do("POST", "/api/networks/"+networkID+"/channels", map[string]string{"name": name}, ownerToken)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create channel: %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		ID string `json:"id"`
	}
	decodeBody(t, rec, &body)
	return body.ID
}
