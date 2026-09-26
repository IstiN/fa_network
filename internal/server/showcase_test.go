package server

import (
	"net/http"
	"testing"
)

// setupShowcaseNetwork: a public network with one public showcase channel
// (seeded with an envelope) and one private channel.
func setupShowcaseNetwork(t *testing.T, env *testEnv, ownerToken string) (networkID, pubChannelID, privChannelID string) {
	t.Helper()
	networkID = makePublicNetwork(t, env, ownerToken, "showcase-net")
	create := func(name string, public bool) string {
		body := map[string]any{"name": name}
		if public {
			body["public"] = true
		}
		rec := env.do("POST", "/api/networks/"+networkID+"/channels", body, ownerToken)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create channel %s: %d %s", name, rec.Code, rec.Body.String())
		}
		var out struct {
			ID string `json:"id"`
		}
		decodeBody(t, rec, &out)
		return out.ID
	}
	pubChannelID = create("showcase", true)
	privChannelID = create("ops", false)

	sess, _ := env.join(t, networkID, "pass-123456", "", ownerToken)
	rec := env.do("POST", "/api/channels/"+pubChannelID+"/messages",
		map[string]string{"id": "m-show-1", "payload": "aGVsbG8tdmlzaXRvcg=="}, sess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("seed envelope: %d %s", rec.Code, rec.Body.String())
	}
	return networkID, pubChannelID, privChannelID
}

func TestShowcaseListing(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	networkID, pubChannelID, _ := setupShowcaseNetwork(t, env, owner)

	rec := env.do(http.MethodGet, "/api/networks/"+networkID+"/showcase", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("showcase = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Channels []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"channels"`
	}
	decodeBody(t, rec, &body)
	if body.ID != networkID || body.Name != "showcase-net" {
		t.Fatalf("showcase header = %+v", body)
	}
	if len(body.Channels) != 1 || body.Channels[0].ID != pubChannelID || body.Channels[0].Name != "showcase" {
		t.Fatalf("showcase channels = %+v, want only the public one", body.Channels)
	}
}

func TestShowcaseListingRejectsPrivate(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	privID := env.createNetwork(t, owner, "priv-net", "pass-123456")
	unknown := "net-does-not-exist"

	for _, id := range []string{privID, unknown} {
		rec := env.do(http.MethodGet, "/api/networks/"+id+"/showcase", nil, "")
		if rec.Code != http.StatusNotFound || errCode(t, rec) != CodeNotFound {
			t.Fatalf("showcase %s = %d %s, want 404 not_found (no oracle)", id, rec.Code, rec.Body.String())
		}
	}
}

func TestAnonymousShowcaseRead(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	_, pubChannelID, _ := setupShowcaseNetwork(t, env, owner)

	rec := env.do(http.MethodGet, "/api/channels/"+pubChannelID+"/messages", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous read = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Items []struct {
			ID      string `json:"id"`
			Payload string `json:"payload"`
		} `json:"items"`
	}
	decodeBody(t, rec, &page)
	if len(page.Items) != 1 || page.Items[0].ID != "m-show-1" {
		t.Fatalf("anonymous page = %+v", page.Items)
	}
}

// TestAnonymousReadNoOracle: private channels and channels of private
// networks are 404 (not 401) for anonymous readers — existence never leaks.
func TestAnonymousReadNoOracle(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	_, _, privChannelID := setupShowcaseNetwork(t, env, owner)
	privNetID := env.createNetwork(t, owner, "hidden-net", "pass-123456")
	rec := env.do("POST", "/api/networks/"+privNetID+"/channels", map[string]any{"name": "ch"}, owner)
	if rec.Code != http.StatusCreated {
		t.Fatalf("channel in private net: %d", rec.Code)
	}
	var out struct {
		ID string `json:"id"`
	}
	decodeBody(t, rec, &out)
	privateNetChannel := out.ID

	for _, id := range []string{privChannelID, privateNetChannel, "chan-does-not-exist"} {
		rec := env.do(http.MethodGet, "/api/channels/"+id+"/messages", nil, "")
		if rec.Code != http.StatusNotFound || errCode(t, rec) != CodeNotFound {
			t.Fatalf("anonymous read %s = %d %s, want 404 not_found", id, rec.Code, rec.Body.String())
		}
	}
}

// TestAnonymousGarbageTokenRejected: a present-but-invalid token keeps the
// existing 401 behavior (an anonymous fast-path must not swallow it).
func TestAnonymousGarbageTokenRejected(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	_, pubChannelID, _ := setupShowcaseNetwork(t, env, owner)

	rec := env.do(http.MethodGet, "/api/channels/"+pubChannelID+"/messages", nil, "garbage-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("garbage token read = %d, want 401: %s", rec.Code, rec.Body.String())
	}
}

// TestMemberReadUnchanged: a joined member still reads private channels
// (regression guard on the anonymous branch).
func TestMemberReadUnchanged(t *testing.T) {
	env := newTestEnv(t)
	owner := env.authedToken("owner1", "Owner One")
	networkID, _, privChannelID := setupShowcaseNetwork(t, env, owner)
	sess, _ := env.join(t, networkID, "pass-123456", "viewer", "")

	rec := env.do(http.MethodGet, "/api/channels/"+privChannelID+"/messages", nil, sess)
	if rec.Code != http.StatusOK {
		t.Fatalf("member read of private channel = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}
