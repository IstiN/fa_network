package server

import (
	"net/http"
	"testing"
)

// Agent enrollment (owner/admin): one-shot name-bound hub client secret,
// returned exactly once. Guests and plain members are rejected by class.
func TestEnrollAgent(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("own9", "Owner Nine")
	id := env.createNetwork(t, owner, "enroll-net", "secret123")
	ownerSess, _ := env.join(t, id, "secret123", "", owner)

	rec := env.do("POST", "/api/networks/"+id+"/agents/enroll", map[string]string{"name": "ops-bot"}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	decodeBody(t, rec, &body)
	if body["name"] != "ops-bot" {
		t.Fatalf("name: %v", body["name"])
	}
	if body["clientSecret"] != "fake-secret-ops-bot" {
		t.Fatalf("clientSecret: %v", body["clientSecret"])
	}
	if body["hubUrl"] != "ws://fake-hub/ws" {
		t.Fatalf("hubUrl: %v", body["hubUrl"])
	}
	if _, ok := body["enrolledAt"].(string); !ok {
		t.Fatalf("enrolledAt missing: %v", body)
	}
}

func TestEnrollAgentValidation(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("own10", "Owner Ten")
	id := env.createNetwork(t, owner, "enroll-val", "secret123")
	ownerSess, _ := env.join(t, id, "secret123", "", owner)

	for _, name := range []string{"", "ab", "Bad Name", "-leading", "x_y"} {
		rec := env.do("POST", "/api/networks/"+id+"/agents/enroll", map[string]string{"name": name}, ownerSess)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("name %q: status %d, want 400", name, rec.Code)
		}
	}
}

func TestEnrollAgentClassGates(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("own11", "Owner Eleven")
	id := env.createNetwork(t, owner, "enroll-cls", "secret123")
	memberSess, _ := env.join(t, id, "secret123", "", env.authedToken("mem9", "Member M"))
	guestSess, _ := env.join(t, id, "secret123", "g-bot", "")

	for _, token := range []string{memberSess, guestSess, ""} {
		rec := env.do("POST", "/api/networks/"+id+"/agents/enroll", map[string]string{"name": "bot-x"}, token)
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
			t.Fatalf("non-manager enroll: %d", rec.Code)
		}
	}
}

func TestEnrollAgentHubOffline(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("own12", "Owner Twelve")
	id := env.createNetwork(t, owner, "enroll-off", "secret123")
	ownerSess, _ := env.join(t, id, "secret123", "", owner)
	env.hub.SetOnline(false)

	rec := env.do("POST", "/api/networks/"+id+"/agents/enroll", map[string]string{"name": "ops-bot"}, ownerSess)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("offline enroll: %d", rec.Code)
	}
	if code := errCode(t, rec); code != CodeHubUnavailable {
		t.Fatalf("code: %s", code)
	}
}
