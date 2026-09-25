package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// catalogBody decodes the catalog page wire shape.
type catalogBody struct {
	Items []struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		PublicChannels int    `json:"publicChannels"`
		MemberCount    int    `json:"memberCount"`
	} `json:"items"`
	NextCursor string `json:"nextCursor"`
}

func getCatalog(t *testing.T, env *testEnv, query string) catalogBody {
	t.Helper()
	rec := env.do(http.MethodGet, "/api/networks/public"+query, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("catalog: status %d body %s", rec.Code, rec.Body.String())
	}
	var body catalogBody
	decodeBody(t, rec, &body)
	return body
}

// makePublicNetwork creates a network and flips it into the catalog.
func makePublicNetwork(t *testing.T, env *testEnv, ownerToken, name string) string {
	t.Helper()
	id := env.createNetwork(t, ownerToken, name, "pass-123456")
	rec := env.do("PATCH", "/api/networks/"+id, map[string]any{"public": true}, ownerToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish %s: status %d body %s", name, rec.Code, rec.Body.String())
	}
	return id
}

func TestPublicCatalogListing(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	other := env.authedToken("user2", "User Two")

	pubID := makePublicNetwork(t, env, owner, "pub-net")
	privID := env.createNetwork(t, other, "priv-net", "pass-123456")

	body := getCatalog(t, env, "")
	if len(body.Items) != 1 {
		t.Fatalf("catalog size = %d, want 1", len(body.Items))
	}
	item := body.Items[0]
	if item.ID != pubID || item.Name != "pub-net" {
		t.Fatalf("catalog entry = %+v, want pub-net", item)
	}
	if item.MemberCount != 1 {
		t.Fatalf("memberCount = %d, want 1 (owner seeds the roster)", item.MemberCount)
	}
	if body.NextCursor != "" {
		t.Fatalf("nextCursor = %q, want empty single page", body.NextCursor)
	}

	// The catalog must leak nothing about the private network.
	raw := getCatalogRaw(t, env)
	for _, leak := range []string{privID, "priv-net", "password", "ownerId"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("catalog leaks %q: %s", leak, raw)
		}
	}
}

func getCatalogRaw(t *testing.T, env *testEnv) string {
	t.Helper()
	rec := env.do(http.MethodGet, "/api/networks/public", nil, "")
	return rec.Body.String()
}

// TestPublicCatalogPagination walks a multi-page catalog in order.
func TestPublicCatalogPagination(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	var ids []string
	for i := 1; i <= 3; i++ {
		ids = append(ids, makePublicNetwork(t, env, owner, fmt.Sprintf("pub-%d", i)))
	}

	page1 := getCatalog(t, env, "?limit=2")
	if len(page1.Items) != 2 || page1.NextCursor == "" {
		t.Fatalf("page1 = %+v, want 2 items + cursor", page1)
	}
	page2 := getCatalog(t, env, "?limit=2&cursor="+page1.NextCursor)
	if len(page2.Items) != 1 || page2.NextCursor != "" {
		t.Fatalf("page2 = %+v, want 1 item, no cursor", page2)
	}
	seen := []string{page1.Items[0].ID, page1.Items[1].ID, page2.Items[0].ID}
	for i, id := range ids {
		if seen[i] != id {
			t.Fatalf("catalog order = %v, want %v (oldest first)", seen, ids)
		}
	}
}

// TestPublicCatalogBadCursor degrades to page one.
func TestPublicCatalogBadCursor(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	makePublicNetwork(t, env, owner, "pub-net")

	bogus := base64.RawURLEncoding.EncodeToString([]byte("not-a-time|x"))
	rec := env.do(http.MethodGet, "/api/networks/public?cursor="+bogus, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("bad cursor status = %d, want 200", rec.Code)
	}
}

// TestPublicCatalogJoinStillNeedsPassword: listing is discovery only —
// the join contract is unchanged (E1 story intact).
func TestPublicCatalogJoinStillNeedsPassword(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	pubID := makePublicNetwork(t, env, owner, "pub-net")

	rec := env.do("POST", "/api/networks/"+pubID+"/join", map[string]string{"displayName": "g"}, "")
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != CodeInvalidCreds {
		t.Fatalf("passwordless join = %d %s, want 400 invalid_credentials (rejected)", rec.Code, rec.Body.String())
	}
	rec = env.do("POST", "/api/networks/"+pubID+"/join", map[string]string{"password": "wrong-pass"}, "")
	if rec.Code != http.StatusForbidden || errCode(t, rec) != CodeInvalidCreds {
		t.Fatalf("wrong-password join = %d, want 403 invalid_credentials", rec.Code)
	}
	_, out := env.join(t, pubID, "pass-123456", "guest", "")
	if out["sessionToken"] == "" {
		t.Fatalf("correct-password join missing token: %v", out)
	}
}

// TestPublicCatalogTogglePermissions: only owner/admin flip the flag.
func TestPublicCatalogTogglePermissions(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := env.createNetwork(t, owner, "toggle-net", "pass-123456")

	member := env.authedToken("member1", "Member One")
	if _, out := env.join(t, id, "pass-123456", "", member); out["sessionToken"] == "" {
		t.Fatal("member join failed")
	}
	rec := env.do("PATCH", "/api/networks/"+id, map[string]any{"public": true}, member)
	if rec.Code != http.StatusForbidden || errCode(t, rec) != "forbidden_by_class" {
		t.Fatalf("member publish = %d %s, want 403 forbidden_by_class", rec.Code, rec.Body.String())
	}
}

// TestPublicCatalogChannelCount counts only public showcase channels.
func TestPublicCatalogChannelCount(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	id := makePublicNetwork(t, env, owner, "chan-net")

	for _, body := range []map[string]any{
		{"name": "general"},
		{"name": "showcase", "public": true},
	} {
		rec := env.do("POST", "/api/networks/"+id+"/channels", body, owner)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create channel %v: %d %s", body, rec.Code, rec.Body.String())
		}
	}

	item := getCatalog(t, env, "").Items[0]
	if item.PublicChannels != 1 {
		t.Fatalf("publicChannels = %d, want 1 (only the showcase)", item.PublicChannels)
	}
}

// TestPublicCatalogWireShape: raw JSON keys match the spec exactly.
func TestPublicCatalogWireShape(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	makePublicNetwork(t, env, owner, "shape-net")

	var raw map[string]any
	if err := json.Unmarshal([]byte(getCatalogRaw(t, env)), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	items, ok := raw["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items missing: %v", raw)
	}
	entry, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("entry not an object: %v", items[0])
	}
	for _, key := range []string{"id", "name", "publicChannels", "memberCount"} {
		if _, present := entry[key]; !present {
			t.Fatalf("entry missing key %q: %v", key, entry)
		}
	}
	for _, secret := range []string{"password", "ownerId", "admins", "passwordHash"} {
		if _, present := entry[secret]; present {
			t.Fatalf("entry leaks key %q", secret)
		}
	}
}
