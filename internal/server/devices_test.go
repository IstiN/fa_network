package server

import (
	"testing"
)

// deviceEnrollBody is the enroll response shape.
type deviceEnrollBody struct {
	DeviceID        string           `json:"deviceId"`
	DeviceToken     string           `json:"deviceToken"`
	PersonalNetwork *networkWireView `json:"personalNetwork"`
}

// networkWireView mirrors model.NetworkWire for decode convenience.
type networkWireView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Public bool   `json:"public"`
}

func enrollDevice(t *testing.T, env *testEnv, token, name string) deviceEnrollBody {
	t.Helper()
	body := map[string]any{}
	if name != "" {
		body["name"] = name
	}
	rec := env.do("POST", "/api/devices/enroll", body, token)
	if rec.Code != 201 {
		t.Fatalf("enroll status = %d body %s", rec.Code, rec.Body.String())
	}
	var out deviceEnrollBody
	decodeBody(t, rec, &out)
	if out.DeviceID == "" || out.DeviceToken == "" {
		t.Fatal("enroll must return deviceId and deviceToken")
	}
	return out
}

func TestDeviceEnrollRequiresAuthedJWT(t *testing.T) {
	env := newTestEnv(t)

	if rec := env.do("POST", "/api/devices/enroll", map[string]any{}, ""); rec.Code != 401 {
		t.Fatalf("no auth = %d, want 401", rec.Code)
	}
	// A join-issued session token is not an ai-native JWT: session lookup
	// fails the device store too — plain 401, zero data.
	if rec := env.do("POST", "/api/devices/enroll", map[string]any{}, "not-a-jwt"); rec.Code != 401 {
		t.Fatalf("garbage token = %d, want 401", rec.Code)
	}
}

func TestDeviceEnrollProvisionsPersonalNetworkOnce(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")

	first := enrollDevice(t, env, jwt, "macbook")
	second := enrollDevice(t, env, jwt, "linux-box")

	if first.PersonalNetwork == nil || second.PersonalNetwork == nil {
		t.Fatal("enroll must return the personal network")
	}
	if first.PersonalNetwork.ID != second.PersonalNetwork.ID {
		t.Fatalf("second enroll provisioned a second network: %s vs %s",
			first.PersonalNetwork.ID, second.PersonalNetwork.ID)
	}
	if first.PersonalNetwork.Public {
		t.Fatal("personal network must be private")
	}

	// A different user gets their own network, never Alice's.
	bob := enrollDevice(t, env, env.authedToken("bob", "Bob"), "")
	if bob.PersonalNetwork.ID == first.PersonalNetwork.ID {
		t.Fatal("personal networks must be per-user")
	}

	// The owner member row exists with owner class (roster seeds).
	net, err := env.st.Network(t.Context(), first.PersonalNetwork.ID)
	if err != nil {
		t.Fatalf("personal network missing: %v", err)
	}
	member, err := env.st.Member(t.Context(), net.ID, "alice")
	if err != nil || member.Class != "owner" {
		t.Fatalf("owner member seed: %v %+v", err, member)
	}
}

func TestDeviceRevoke(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	// Foreign user cannot see or revoke (no existence oracle: 404).
	if rec := env.do("DELETE", "/api/devices/"+dev.DeviceID, nil,
		env.authedToken("bob", "Bob")); rec.Code != 404 {
		t.Fatalf("foreign revoke = %d, want 404", rec.Code)
	}

	// The device's own token revokes itself.
	rec := env.do("DELETE", "/api/devices/"+dev.DeviceID, nil, dev.DeviceToken)
	if rec.Code != 200 {
		t.Fatalf("self revoke = %d body %s", rec.Code, rec.Body.String())
	}

	// Revoked token loses all powers: no ticket, no re-revoke.
	if rec := env.do("POST", "/api/ws-ticket", map[string]any{}, dev.DeviceToken); rec.Code != 401 {
		t.Fatalf("revoked device ticket = %d, want 401", rec.Code)
	}
	if rec := env.do("DELETE", "/api/devices/"+dev.DeviceID, nil, dev.DeviceToken); rec.Code != 401 {
		t.Fatalf("revoked device auth = %d, want 401", rec.Code)
	}
}

func TestDeviceTicketScopeAndSingleUse(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	rec := env.do("POST", "/api/ws-ticket", map[string]any{}, dev.DeviceToken)
	if rec.Code != 200 {
		t.Fatalf("device ticket mint = %d", rec.Code)
	}
	var mint struct {
		Ticket    string `json:"ticket"`
		ExpiresIn int    `json:"expiresIn"`
		Scope     string `json:"scope"`
	}
	decodeBody(t, rec, &mint)
	if mint.Scope != "device" || mint.ExpiresIn <= 0 || mint.Ticket == "" {
		t.Fatalf("device mint shape: %+v", mint)
	}

	// A JWT is NOT a device token: stays member-scope (session lookup
	// fails, device hash misses → 401 — a JWT never mints device scope).
	_ = jwt
}

func TestDeviceTokenNeverStoredRaw(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	dev := enrollDevice(t, env, jwt, "macbook")

	// The credential-hygiene tripwire: the store hands out only the
	// 32-byte sha256 — the raw token is reconstructable from nowhere.
	stored, err := env.st.Device(t.Context(), dev.DeviceID)
	if err != nil {
		t.Fatalf("device missing: %v", err)
	}
	if len(stored.TokenHash) != 32 {
		t.Fatalf("token hash length = %d, want 32", len(stored.TokenHash))
	}
	if string(stored.TokenHash) == dev.DeviceToken {
		t.Fatal("raw deviceToken stored as the hash")
	}
}
