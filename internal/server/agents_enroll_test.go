package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/IstiN/fa_network/internal/hub"
)

type unknownCreateHub struct{ *hub.FakeClient }

func (unknownCreateHub) CreateAgentCredential(context.Context, string) (string, error) {
	return "", hub.ErrUnknownOperation
}

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

func TestCreateAgentCredentialIndependent(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("own13", "Owner Thirteen")
	id := env.createNetwork(t, owner, "create-net", "secret123")
	ownerSess, _ := env.join(t, id, "secret123", "", owner)
	path := "/api/networks/" + id + "/agents/enrollments"

	var bodies [2]map[string]any
	for i, wantSecret := range []string{"fake-create-secret-ops-bot-1", "fake-create-secret-ops-bot-2"} {
		rec := env.do("POST", path, map[string]string{"name": "ops-bot"}, ownerSess)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
		decodeBody(t, rec, &bodies[i])
		if bodies[i]["clientSecret"] != wantSecret {
			t.Fatalf("create %d clientSecret: %v, want %q", i+1, bodies[i]["clientSecret"], wantSecret)
		}
	}
	if bodies[0]["clientSecret"] == bodies[1]["clientSecret"] {
		t.Fatal("independent creates returned the same secret")
	}
	for key, want := range map[string]any{"name": "ops-bot", "hubUrl": "ws://fake-hub/ws"} {
		if bodies[0][key] != want {
			t.Fatalf("response %s: %v, want %v", key, bodies[0][key], want)
		}
	}
	if _, ok := bodies[0]["enrolledAt"].(string); !ok {
		t.Fatalf("enrolledAt missing: %v", bodies[0])
	}
}

func TestCreateAgentCredentialOldHubError(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("own-old-hub", "Owner Old Hub")
	id := env.createNetwork(t, owner, "create-old-hub", "secret123")
	env.srv.hub = unknownCreateHub{FakeClient: env.hub}

	rec := env.do("POST", "/api/networks/"+id+"/agents/enrollments", map[string]string{"name": "ops-bot"}, owner)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("old hub create: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "unknown enrollment operation") {
		t.Fatalf("old hub error hidden: %s", rec.Body.String())
	}
}

func TestCreateAgentCredentialCrossTenant(t *testing.T) {
	env := newTestEnv(t)
	ownerA := env.authedToken("owner-create-a", "Owner A")
	ownerB := env.authedToken("owner-create-b", "Owner B")
	netA := env.createNetwork(t, ownerA, "create-net-a", "secret123")
	netB := env.createNetwork(t, ownerB, "create-net-b", "secret123")

	create := func(networkID, token string) *int {
		rec := env.do("POST", "/api/networks/"+networkID+"/agents/enrollments",
			map[string]string{"name": "shared-agent"}, token)
		return &rec.Code
	}
	if code := create(netA, ownerA); *code != http.StatusCreated {
		t.Fatalf("first create = %d, want 201", *code)
	}
	if code := create(netA, ownerA); *code != http.StatusCreated {
		t.Fatalf("same-network second create = %d, want 201", *code)
	}
	if code := create(netB, ownerB); *code != http.StatusConflict {
		t.Fatalf("cross-tenant create = %d, want 409", *code)
	}
}

func TestCreateAgentCredentialAuthorization(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("own14", "Owner Fourteen")
	id := env.createNetwork(t, owner, "create-cls", "secret123")
	memberSess, _ := env.join(t, id, "secret123", "", env.authedToken("mem10", "Member M"))
	guestSess, _ := env.join(t, id, "secret123", "g-create", "")

	for _, endpoint := range []string{"enroll", "enrollments"} {
		for _, token := range []string{memberSess, guestSess, ""} {
			rec := env.do("POST", "/api/networks/"+id+"/agents/"+endpoint, map[string]string{"name": "bot-x"}, token)
			if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
				t.Fatalf("non-manager %s: %d", endpoint, rec.Code)
			}
		}
	}

	adminToken := env.authedToken("admin-create", "Admin Create")
	adminSess, _ := env.join(t, id, "secret123", "", adminToken)
	rec := env.do("POST", "/api/networks/"+id+"/admins", map[string]string{"userId": "admin-create"}, owner)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add admin: %d %s", rec.Code, rec.Body.String())
	}
	rec = env.do("POST", "/api/networks/"+id+"/agents/enrollments", map[string]string{"name": "admin-bot"}, adminSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin create: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreateAgentCredentialValidationAndHubOffline(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("own15", "Owner Fifteen")
	id := env.createNetwork(t, owner, "create-val", "secret123")
	ownerSess, _ := env.join(t, id, "secret123", "", owner)
	path := "/api/networks/" + id + "/agents/enrollments"

	for _, name := range []string{"", "ab", "Bad Name", "-leading", "x_y"} {
		rec := env.do("POST", path, map[string]string{"name": name}, ownerSess)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("name %q: status %d, want 400", name, rec.Code)
		}
	}
	env.hub.SetOnline(false)
	rec := env.do("POST", path, map[string]string{"name": "ops-bot"}, ownerSess)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("offline create: %d %s", rec.Code, rec.Body.String())
	}
	if code := errCode(t, rec); code != CodeHubUnavailable {
		t.Fatalf("code: %s", code)
	}
}
