package server

import (
	"net/http"
	"strings"
	"testing"
)

// mineItems decodes the GET /api/networks/mine response envelope.
type mineItems struct {
	Items []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Public      bool   `json:"public"`
		MemberClass string `json:"memberClass"`
	} `json:"items"`
}

func mineIDs(items mineItems) []string {
	out := make([]string, 0, len(items.Items))
	for _, it := range items.Items {
		out = append(out, it.ID)
	}
	return out
}

// getMine calls the endpoint and returns the decoded envelope.
func getMine(t *testing.T, env *testEnv, token string) mineItems {
	t.Helper()
	rec := env.do(http.MethodGet, "/api/networks/mine", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/networks/mine: status %d (body %s)", rec.Code, rec.Body.String())
	}
	var items mineItems
	decodeBody(t, rec, &items)
	return items
}

// TestNetworksMineRequiresAuth: guest/no-token callers get the plain
// unauthorized error with zero data — a join-issued session token is NOT
// an ai-native JWT and must never unlock account discovery.
func TestNetworksMineRequiresAuth(t *testing.T) {
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
		rec := env.do(http.MethodGet, "/api/networks/mine", nil, tc.token)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401 (body %s)", tc.name, rec.Code, rec.Body.String())
		}
		if code := errCode(t, rec); code != CodeUnauthorized {
			t.Fatalf("%s: code %q, want %q", tc.name, code, CodeUnauthorized)
		}
		if strings.Contains(rec.Body.String(), "items") {
			t.Fatalf("%s: unauthorized body leaked data: %s", tc.name, rec.Body.String())
		}
	}
}

// mustGuestSession joins as a guest and returns the session token.
func mustGuestSession(t *testing.T, env *testEnv, networkID string) string {
	t.Helper()
	sess, _ := env.join(t, networkID, "secret123", "guest", "")
	return sess
}

// TestNetworksMineListsOwnerPrivateNetwork: an owner sees the private
// network created with their JWT, class owner, public:false — and the
// projection carries no secret, owner, admin, channel or session material.
func TestNetworksMineListsOwnerPrivateNetwork(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "fa-team", "secret123")

	rec := env.do(http.MethodGet, "/api/networks/mine", nil, owner)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	items := getMine(t, env, owner)
	if len(items.Items) != 1 {
		t.Fatalf("items = %+v, want exactly the created network", items.Items)
	}
	got := items.Items[0]
	if got.ID != id || got.Name != "fa-team" || got.Public || got.MemberClass != "owner" {
		t.Fatalf("item = %+v, want {id:%s name:fa-team public:false memberClass:owner}", got, id)
	}
	for _, forbidden := range []string{
		"password", "hash", "salt", "ownerId", "admins",
		"sessionToken", "channels", "channel",
	} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("response leaks %q: %s", forbidden, rec.Body.String())
		}
	}
}

// TestNetworksMineHidesForeignPrivateNetworks: another authenticated
// account never sees networks it has no membership row in.
func TestNetworksMineHidesForeignPrivateNetworks(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	_ = env.createNetwork(t, owner, "owner-private", "secret123")

	other := env.authedToken("mallory", "Mallory")
	rec := env.do(http.MethodGet, "/api/networks/mine", nil, other)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	var items mineItems
	decodeBody(t, rec, &items)
	if len(items.Items) != 0 {
		t.Fatalf("foreign account sees private networks: %+v", items.Items)
	}
	if strings.Contains(rec.Body.String(), "owner-private") {
		t.Fatalf("foreign account body leaks the network name: %s", rec.Body.String())
	}
}

// TestNetworksMineClassesAndOrder: admin and member memberships are
// listed with the right class; public networks appear with public:true;
// newest network first.
func TestNetworksMineClassesAndOrder(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	olderID := env.createNetwork(t, owner, "older-net", "secret123")

	// Alice joins the older network as a plain authed member.
	alice := env.authedToken("alice", "Alice")
	env.join(t, olderID, "secret123", "", alice)

	// Owner creates a newer network, opts it into the catalog, and
	// promotes Alice to admin there.
	newerID := env.createNetwork(t, owner, "newer-net", "secret123")
	rec := env.do(http.MethodPatch, "/api/networks/"+newerID, map[string]any{"public": true}, owner)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch public: %d %s", rec.Code, rec.Body.String())
	}
	rec = env.do(http.MethodPost, "/api/networks/"+newerID+"/admins", map[string]string{"userId": "alice"}, owner)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add admin: %d %s", rec.Code, rec.Body.String())
	}

	// Alice: newest first — admin in the public network, member in the
	// older private one.
	items := getMine(t, env, alice)
	if len(items.Items) != 2 {
		t.Fatalf("alice items = %+v, want 2 networks", items.Items)
	}
	if got := mineIDs(items); got[0] != newerID || got[1] != olderID {
		t.Fatalf("alice order = %v, want [%s %s] (newest first)", got, newerID, olderID)
	}
	if it := items.Items[0]; it.MemberClass != "admin" || !it.Public {
		t.Fatalf("newer item = %+v, want admin/public:true", it)
	}
	if it := items.Items[1]; it.MemberClass != "member" || it.Public {
		t.Fatalf("older item = %+v, want member/public:false", it)
	}

	// Owner: both networks, class owner, same order.
	ownerItems := getMine(t, env, owner)
	if len(ownerItems.Items) != 2 {
		t.Fatalf("owner items = %+v, want 2 networks", ownerItems.Items)
	}
	if got := mineIDs(ownerItems); got[0] != newerID || got[1] != olderID {
		t.Fatalf("owner order = %v, want [%s %s]", got, newerID, olderID)
	}
	for _, it := range ownerItems.Items {
		if it.MemberClass != "owner" {
			t.Fatalf("owner item = %+v, want memberClass owner", it)
		}
	}
}
