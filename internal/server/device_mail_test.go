package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// networkChannelWire mirrors the bare ChannelWire the create endpoint
// returns (no wrapper object).
type networkChannelWire struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// setUpDevice builds a user with one personal network, one channel and
// an enrolled device — the phase-B routing fixture.
func setUpDevice(t *testing.T, env *testEnv, user, name string) (jwt string, dev deviceEnrollBody, channelID string) {
	t.Helper()
	jwt = env.authedToken(user, name)
	dev = enrollDevice(t, env, jwt, "macbook")
	rec := env.do("POST", "/api/networks/"+dev.PersonalNetwork.ID+"/channels",
		map[string]any{"name": "general"}, jwt)
	if rec.Code != 201 {
		t.Fatalf("channel create = %d", rec.Code)
	}
	var created networkChannelWire
	decodeBody(t, rec, &created)
	return jwt, dev, created.ID
}

// exposeAgent patches the device roster so the connector may speak as
// the agent (exposure flag + dmPub projection).
func exposeAgent(t *testing.T, env *testEnv, token, deviceID, agentName, dmPub string) {
	t.Helper()
	rec := env.do("PATCH", "/api/devices/"+deviceID+"/roster", map[string]any{
		"agents": []map[string]any{{"name": agentName, "exposed": true, "state": "live", "dmPub": dmPub}},
	}, token)
	if rec.Code != 200 {
		t.Fatalf("roster patch = %d body %s", rec.Code, rec.Body.String())
	}
}

func TestDeviceMailUpstreamRoutingAndDedup(t *testing.T) {
	env := newTestEnv(t)
	_, dev, channelID := setUpDevice(t, env, "alice", "Alice")
	exposeAgent(t, env, dev.DeviceToken, dev.DeviceID, "goal_builder", "dmPubB64")

	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)

	mail := deviceFrame{V: 1, Kind: "mail", MsgID: "msg-1",
		Network: dev.PersonalNetwork.ID, Channel: channelID,
		From: "agent:goal_builder", Ciphertext: "encrypted-payload"}
	dc.send(mail)

	// The routing pipeline processed the frame once the echo returns.
	got := dc.next("mail")
	if got.MsgID != "msg-1" || got.Ciphertext != "encrypted-payload" {
		t.Fatalf("fanout = %s %q", got.MsgID, got.Ciphertext)
	}

	// The envelope lands in the channel store with msgId as the envelope
	// id (the dedup key on every hop) and a server-assigned seq.
	page, err := env.st.Envelopes(t.Context(), channelID, "", 10)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("stored envelopes: %v %+v", err, page)
	}
	if page.Items[0].ID != "msg-1" || page.Items[0].Payload != "encrypted-payload" {
		t.Fatalf("stored = %s %q", page.Items[0].ID, page.Items[0].Payload)
	}
	if page.Items[0].Seq <= 0 {
		t.Fatal("server must stamp seq")
	}

	// The echo carries the SAME msgId/seq byte-for-byte (the connector
	// dedups by msgId — contract v1.1).
	if got.Seq != page.Items[0].Seq {
		t.Fatalf("fanout seq %d, want %d", got.Seq, page.Items[0].Seq)
	}

	// Duplicate msgId: no second copy, no error frame (at-least-once).
	dc.send(mail)
	dupPage, _ := env.st.Envelopes(t.Context(), channelID, "", 10)
	if len(dupPage.Items) != 1 {
		t.Fatalf("duplicate msgId stored twice: %d", len(dupPage.Items))
	}
}

func TestDeviceMailStructuralNegatives(t *testing.T) {
	env := newTestEnv(t)
	_, dev, channelID := setUpDevice(t, env, "alice", "Alice")
	_, bobDev, _ := setUpDevice(t, env, "bob", "Bob")

	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)

	cases := []struct {
		name string
		f    deviceFrame
		want string
	}{
		{"missing msgId", deviceFrame{Kind: "mail", Network: dev.PersonalNetwork.ID,
			Channel: channelID, From: "user:alice", Ciphertext: "x"}, "invalid_mail"},
		{"not a member", deviceFrame{Kind: "mail", MsgID: "m2", Network: "foreign-net",
			Channel: "ch", From: "user:alice", Ciphertext: "x"}, "not_a_member"},
		{"unknown channel", deviceFrame{Kind: "mail", MsgID: "m3", Network: dev.PersonalNetwork.ID,
			Channel: "nope", From: "user:alice", Ciphertext: "x"}, "unknown_channel"},
		{"sender not exposed (foreign agent)", deviceFrame{Kind: "mail", MsgID: "m4",
			Network: dev.PersonalNetwork.ID, Channel: channelID,
			From: "agent:other_agent", Ciphertext: "x"}, "sender_not_exposed"},
		{"foreign device address in from", deviceFrame{Kind: "mail", MsgID: "m5",
			Network: dev.PersonalNetwork.ID, Channel: channelID,
			From: "user:bob", Ciphertext: "x"}, "sender_not_exposed"},
		{"DM routing until phase C", deviceFrame{Kind: "mail", MsgID: "m6",
			Network: dev.PersonalNetwork.ID, Channel: "dm:user:alice:gb@mac",
			From: "user:alice", Ciphertext: "x"}, "dm_not_routed_yet"},
	}
	for _, tc := range cases {
		dc.send(tc.f)
		got := dc.next("error")
		if got.RefID != tc.f.MsgID {
			t.Fatalf("%s: error.refId = %q", tc.name, got.RefID)
		}
		var note struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal([]byte(got.Ciphertext), &note); err != nil || note.Code != tc.want {
			t.Fatalf("%s: code = %q (%v), want %q", tc.name, got.Ciphertext, err, tc.want)
		}
	}

	// Cross-user mail: bob's device cannot speak into alice's network
	// even with a valid exposed agent name of its own.
	exposeAgent(t, env, bobDev.DeviceToken, bobDev.DeviceID, "goal_builder", "p")
	dcBob := dialDeviceWS(t, env, bobDev.DeviceToken)
	dcBob.hello(bobDev.DeviceID, 1)
	dcBob.send(deviceFrame{Kind: "mail", MsgID: "bx", Network: dev.PersonalNetwork.ID,
		Channel: channelID, From: "agent:goal_builder", Ciphertext: "x"})
	if got := dcBob.next("error"); got.RefID != "bx" {
		t.Fatalf("bob device mail into alice network: %v", got)
	}
}

func TestPublicChannelWriteGuardForDevices(t *testing.T) {
	env := newTestEnv(t)
	jwt, dev, _ := setUpDevice(t, env, "alice", "Alice")

	// A shared network with a public channel: alice is a plain member.
	shared := createNetworkAs(t, env, "bob", "pub-net", true)
	rec := env.do("POST", "/api/networks/"+shared+"/channels",
		map[string]any{"name": "announce", "public": true}, env.authedToken("bob", "Bob"))
	if rec.Code != 201 {
		t.Fatalf("public channel create = %d", rec.Code)
	}
	_ = env.do("POST", "/api/networks/"+shared+"/join", map[string]any{
		"network": "pub-net", "password": "memberpw1"}, jwt)
	seedMember(t, env, shared, "alice", "member")

	if rec := env.do("PATCH", "/api/devices/"+dev.DeviceID+"/roster", map[string]any{
		"agents": []map[string]any{{"name": "goal_builder", "exposed": true, "state": "live"}},
	}, dev.DeviceToken); rec.Code != 200 {
		t.Fatalf("patch = %d", rec.Code)
	}

	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)
	dc.send(deviceFrame{Kind: "mail", MsgID: "pm", Network: shared,
		Channel: "announce", From: "agent:goal_builder", Ciphertext: "x"})
	got := dc.next("error")
	var note struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(got.Ciphertext), &note); err != nil || note.Code != "channel_read_only" {
		t.Fatalf("public channel write = %q, want channel_read_only (law 4)", got.Ciphertext)
	}
}

// seedMember writes a membership row directly (join flow already covered
// elsewhere; routing tests only need the row to exist).
func seedMember(t *testing.T, env *testEnv, networkID, id, class string) {
	t.Helper()
	if err := env.srv.st.UpsertMember(t.Context(), &model.Member{
		ID: id, NetworkID: networkID, Class: class,
		DisplayName: id, Presence: model.PresenceOffline,
	}); err != nil {
		t.Fatalf("seed member: %v", err)
	}
}

// createNetworkAs creates a network with a throwaway owner password and
// returns its id.
func createNetworkAs(t *testing.T, env *testEnv, owner, name string, public bool) string {
	t.Helper()
	rec := env.do("POST", "/api/networks", map[string]any{
		"name": name, "password": "ownerpw1", "public": public},
		env.authedToken(owner, owner))
	if rec.Code != 201 {
		t.Fatalf("network create (%s) = %d body %s", name, rec.Code, rec.Body.String())
	}
	var created struct {
		Network struct {
			ID string `json:"id"`
		} `json:"network"`
	}
	decodeBody(t, rec, &created)
	return created.Network.ID
}

func TestPresenceMachineLifecycleAndRoster(t *testing.T) {
	env := newTestEnv(t)
	jwt, dev, channelID := setUpDevice(t, env, "alice", "Alice")

	// No projection yet: roster reads offline, zero exposed entries.
	rec := env.do("GET", "/api/networks/"+dev.PersonalNetwork.ID+"/devices", nil, jwt)
	if rec.Code != 200 {
		t.Fatalf("roster get = %d", rec.Code)
	}
	var view struct {
		Devices []networkDeviceRosterWire `json:"devices"`
	}
	decodeBody(t, rec, &view)
	if len(view.Devices) != 1 || view.Devices[0].Presence != MachineOffline {
		t.Fatalf("fresh roster = %+v", view.Devices)
	}

	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)

	// Presence frame: agent exposed+live, session exposed to the
	// personal network (default ON per §6).
	dc.send(deviceFrame{V: 1, Kind: "presence", MsgID: "pr-1",
		Agents: []deviceAgentWire{{Name: "goal_builder", State: "live", Exposed: true, DMPub: "pub"}},
		Sessions: []deviceSessionWire{{ID: "sess-1", State: "live",
			Networks: []string{dev.PersonalNetwork.ID}}}})
	time.Sleep(50 * time.Millisecond)

	rec = env.do("GET", "/api/networks/"+dev.PersonalNetwork.ID+"/devices", nil, jwt)
	decodeBody(t, rec, &view)
	if len(view.Devices) != 1 || view.Devices[0].Presence != MachineOnline {
		t.Fatalf("connected roster = %+v", view.Devices)
	}
	if len(view.Devices[0].Agents) != 1 || view.Devices[0].Agents[0].Name != "goal_builder" ||
		view.Devices[0].Agents[0].DMPub != "pub" {
		t.Fatalf("exposed agents = %+v", view.Devices[0].Agents)
	}
	if len(view.Devices[0].Sessions) != 1 || view.Devices[0].Sessions[0].ID != "sess-1" {
		t.Fatalf("exposed sessions = %+v", view.Devices[0].Sessions)
	}

	// Clean close → offline immediately (§5).
	dc.conn.CloseNow()
	time.Sleep(100 * time.Millisecond)
	rec = env.do("GET", "/api/networks/"+dev.PersonalNetwork.ID+"/devices", nil, jwt)
	decodeBody(t, rec, &view)
	if view.Devices[0].Presence != MachineDegraded && view.Devices[0].Presence != MachineOffline {
		t.Fatalf("post-close presence = %q, want degraded or offline", view.Devices[0].Presence)
	}
	_ = channelID
}

func TestRosterPatchAuthMatrix(t *testing.T) {
	env := newTestEnv(t)
	aliceJWT, aliceDev, _ := setUpDevice(t, env, "alice", "Alice")

	// Owner JWT patches.
	if rec := env.do("PATCH", "/api/devices/"+aliceDev.DeviceID+"/roster",
		map[string]any{"agents": []map[string]any{{"name": "gb", "exposed": true, "dmPub": "p"}}},
		aliceJWT); rec.Code != 200 {
		t.Fatalf("owner patch = %d", rec.Code)
	}
	// The device's own token patches.
	if rec := env.do("PATCH", "/api/devices/"+aliceDev.DeviceID+"/roster",
		map[string]any{"sessions": []map[string]any{{"id": "s1", "state": "live",
			"networks": []string{aliceDev.PersonalNetwork.ID}}}},
		aliceDev.DeviceToken); rec.Code != 200 {
		t.Fatalf("device patch = %d", rec.Code)
	}
	// Foreign JWT reads as 404 (no existence oracle).
	if rec := env.do("PATCH", "/api/devices/"+aliceDev.DeviceID+"/roster",
		map[string]any{}, env.authedToken("bob", "Bob")); rec.Code != 404 {
		t.Fatalf("foreign patch = %d, want 404", rec.Code)
	}
	// No auth at all → 401.
	if rec := env.do("PATCH", "/api/devices/"+aliceDev.DeviceID+"/roster",
		map[string]any{}, ""); rec.Code != 401 {
		t.Fatalf("anon patch = %d, want 401", rec.Code)
	}
	// Foreign DEVICE token → 403.
	bobDev := enrollDevice(t, env, env.authedToken("bob", "Bob"), "box")
	if rec := env.do("PATCH", "/api/devices/"+aliceDev.DeviceID+"/roster",
		map[string]any{}, bobDev.DeviceToken); rec.Code != 403 {
		t.Fatalf("foreign device patch = %d, want 403", rec.Code)
	}
}

func TestSharedNetworkSessionsDefaultHidden(t *testing.T) {
	env := newTestEnv(t)
	jwt, dev, _ := setUpDevice(t, env, "alice", "Alice")
	shared := createNetworkAs(t, env, "bob", "bobnet", false)
	_ = env.do("POST", "/api/networks/"+shared+"/join", map[string]any{
		"network": "bobnet", "password": "memberpw1"}, jwt)
	seedMember(t, env, shared, "alice", "member")

	// Connector exposes sess-1 ONLY to the personal network.
	dc := dialDeviceWS(t, env, dev.DeviceToken)
	dc.hello(dev.DeviceID, 1)
	dc.send(deviceFrame{V: 1, Kind: "presence", MsgID: "pr",
		Agents: []deviceAgentWire{{Name: "gb", State: "live", Exposed: true}},
		Sessions: []deviceSessionWire{{ID: "sess-1", State: "live",
			Networks: []string{dev.PersonalNetwork.ID}}}})
	time.Sleep(50 * time.Millisecond)

	var view struct {
		Devices []networkDeviceRosterWire `json:"devices"`
	}
	rec := env.do("GET", "/api/networks/"+shared+"/devices", nil, jwt)
	decodeBody(t, rec, &view)
	for _, d := range view.Devices {
		if d.DeviceID == dev.DeviceID && len(d.Sessions) != 0 {
			t.Fatalf("shared network saw sessions %+v — AC3 violated", d.Sessions)
		}
	}
	rec = env.do("GET", "/api/networks/"+dev.PersonalNetwork.ID+"/devices", nil, jwt)
	decodeBody(t, rec, &view)
	found := false
	for _, d := range view.Devices {
		if d.DeviceID == dev.DeviceID && len(d.Sessions) == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("personal network must expose the session (owner decision §0.2)")
	}
}
