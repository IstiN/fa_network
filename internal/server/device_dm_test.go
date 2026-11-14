package server

import (
	"encoding/json"
	"testing"
)

// setUpDM builds two devices for one user: the "desktop" sender and the
// "mobile" device hosting the exposed agent — the §7 DM fixture.
func setUpDM(t *testing.T, env *testEnv, user, name string) (jwt string, desktop, mobile deviceEnrollBody, channel string) {
	t.Helper()
	jwt = env.authedToken(user, name)
	desktop = enrollDevice(t, env, jwt, "desktop")
	mobile = enrollDevice(t, env, jwt, "mobile")
	exposeAgent(t, env, mobile.DeviceToken, mobile.DeviceID, "goal_builder", "dmPubB64")
	channel = "dm:user:" + user + ":goal_builder@" + mobile.DeviceID
	return jwt, desktop, mobile, channel
}

func TestDeviceDMUserToAgentRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	_, desktop, mobile, channel := setUpDM(t, env, "alice", "Alice")

	deskConn := dialDeviceWS(t, env, desktop.DeviceToken)
	deskConn.hello(desktop.DeviceID, 1)
	mobConn := dialDeviceWS(t, env, mobile.DeviceToken)
	mobConn.hello(mobile.DeviceID, 1)

	mail := deviceFrame{V: 1, Kind: "mail", MsgID: "dm-1",
		Network: desktop.PersonalNetwork.ID, Channel: channel,
		From: "user:alice", To: "goal_builder@" + mobile.DeviceID, Ciphertext: "sealed-1"}
	deskConn.send(mail)

	// The agent's device receives the DM with the full virtual channel
	// id and the sender's user id; the sender's own socket gets the echo
	// (inbox view for the user side).
	got := mobConn.next("mail")
	if got.MsgID != "dm-1" || got.Channel != channel || got.From != "alice" || got.Ciphertext != "sealed-1" {
		t.Fatalf("agent-side frame = %+v", got)
	}
	if got.Seq <= 0 {
		t.Fatal("server must stamp seq on DM mail")
	}
	echo := deskConn.next("mail")
	if echo.MsgID != "dm-1" {
		t.Fatalf("sender echo = %+v", echo)
	}

	// Persisted under the full dm channel id, deduped by msgId.
	page, err := env.st.Envelopes(t.Context(), channel, "", 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].Payload != "sealed-1" {
		t.Fatalf("dm store: %v %+v", err, page)
	}
	deskConn.send(mail)
	dup, _ := env.st.Envelopes(t.Context(), channel, "", 10)
	if len(dup.Items) != 1 {
		t.Fatalf("duplicate DM stored twice: %d", len(dup.Items))
	}
}

func TestDeviceDMAgentReplyBothShapes(t *testing.T) {
	for _, from := range []string{"agent:goal_builder", "goal_builder@" + ""} {
		t.Run(from, func(t *testing.T) {
			env := newTestEnv(t)
			_, desktop, mobile, channel := setUpDM(t, env, "alice", "Alice")
			fromAddr := from
			if fromAddr != "agent:goal_builder" {
				fromAddr = "goal_builder@" + mobile.DeviceID
			}

			deskConn := dialDeviceWS(t, env, desktop.DeviceToken)
			deskConn.hello(desktop.DeviceID, 1)
			mobConn := dialDeviceWS(t, env, mobile.DeviceToken)
			mobConn.hello(mobile.DeviceID, 1)

			mobConn.send(deviceFrame{V: 1, Kind: "mail", MsgID: "dm-r1",
				Network: mobile.PersonalNetwork.ID, Channel: channel,
				From: fromAddr, To: "user:alice", Ciphertext: "sealed-reply"})
			got := deskConn.next("mail")
			wantFrom := "goal_builder@" + mobile.DeviceID
			if got.MsgID != "dm-r1" || got.From != wantFrom || got.Ciphertext != "sealed-reply" {
				t.Fatalf("user-side reply = %+v", got)
			}
		})
	}
}

func TestDeviceDMStructuralNegatives(t *testing.T) {
	env := newTestEnv(t)
	_, desktop, mobile, channel := setUpDM(t, env, "alice", "Alice")
	_, bobDev, _ := setUpDevice(t, env, "bob", "Bob")

	deskConn := dialDeviceWS(t, env, desktop.DeviceToken)
	deskConn.hello(desktop.DeviceID, 1)
	bobConn := dialDeviceWS(t, env, bobDev.DeviceToken)
	bobConn.hello(bobDev.DeviceID, 1)

	cases := []struct {
		name string
		f    deviceFrame
		want string
	}{
		{"malformed dm channel", deviceFrame{Kind: "mail", MsgID: "d1",
			Network: desktop.PersonalNetwork.ID, Channel: "dm:user:alice",
			From: "user:alice", Ciphertext: "x"}, "invalid_mail"},
		{"foreign namespace", deviceFrame{Kind: "mail", MsgID: "d2",
			Network: desktop.PersonalNetwork.ID,
			Channel: "dm:user:bob:goal_builder@" + mobile.DeviceID,
			From:    "user:alice", Ciphertext: "x"}, "unknown_device"},
		{"foreign user sender", deviceFrame{Kind: "mail", MsgID: "d3",
			Network: bobDev.PersonalNetwork.ID, Channel: channel,
			From: "user:bob", Ciphertext: "x"}, "sender_not_exposed"},
		{"agent reply from wrong device", deviceFrame{Kind: "mail", MsgID: "d4",
			Network: desktop.PersonalNetwork.ID, Channel: channel,
			From: "agent:goal_builder", Ciphertext: "x"}, "sender_not_exposed"},
		{"unexposed agent name", deviceFrame{Kind: "mail", MsgID: "d5",
			Network: desktop.PersonalNetwork.ID,
			Channel: "dm:user:alice:other_agent@" + mobile.DeviceID,
			From:    "user:alice", Ciphertext: "x"}, ""}, // user → any own device is routable; exposure gates agent SENDERS only
		{"not a member", deviceFrame{Kind: "mail", MsgID: "d6",
			Network: "foreign-net", Channel: channel,
			From: "user:alice", Ciphertext: "x"}, "not_a_member"},
		{"unknown target device", deviceFrame{Kind: "mail", MsgID: "d7",
			Network: desktop.PersonalNetwork.ID, Channel: "dm:user:alice:gb@nope",
			From: "user:alice", Ciphertext: "x"}, "unknown_device"},
	}
	for _, tc := range cases {
		if tc.want == "" {
			continue
		}
		conn := deskConn
		if tc.name == "foreign user sender" {
			conn = bobConn
		}
		conn.send(tc.f)
		got := conn.next("error")
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
}

func TestDeviceDMUnexposedAgentCannotReply(t *testing.T) {
	env := newTestEnv(t)
	jwt := env.authedToken("alice", "Alice")
	mobile := enrollDevice(t, env, jwt, "mobile")
	// NOTE: no exposeAgent — the agent is hidden, replies must reject.
	channel := "dm:user:alice:ghost@" + mobile.DeviceID

	mobConn := dialDeviceWS(t, env, mobile.DeviceToken)
	mobConn.hello(mobile.DeviceID, 1)
	mobConn.send(deviceFrame{V: 1, Kind: "mail", MsgID: "dm-x1",
		Network: mobile.PersonalNetwork.ID, Channel: channel,
		From: "agent:ghost", Ciphertext: "x"})
	got := mobConn.next("error")
	var note struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(got.Ciphertext), &note); err != nil || note.Code != "sender_not_exposed" {
		t.Fatalf("unexposed reply: %q (%v)", got.Ciphertext, err)
	}
}

func TestDeviceDMHistoryOwnerOnly(t *testing.T) {
	env := newTestEnv(t)
	jwt, desktop, mobile, channel := setUpDM(t, env, "alice", "Alice")
	_ = mobile
	bobJWT := env.authedToken("bob", "Bob")

	deskConn := dialDeviceWS(t, env, desktop.DeviceToken)
	deskConn.hello(desktop.DeviceID, 1)
	deskConn.send(deviceFrame{V: 1, Kind: "mail", MsgID: "dm-h1",
		Network: desktop.PersonalNetwork.ID, Channel: channel,
		From: "user:alice", Ciphertext: "sealed-history"})
	deskConn.next("mail") // echo confirms the pipeline ran

	// Owner reads the DM history through the same windowed messages view.
	rec := env.do("GET", "/api/channels/"+channel+"/messages", nil, jwt)
	if rec.Code != 200 {
		t.Fatalf("dm history = %d body %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Items []struct {
			ID        string `json:"id"`
			ChannelID string `json:"channelId"`
			Payload   string `json:"payload"`
		} `json:"items"`
	}
	decodeBody(t, rec, &page)
	if len(page.Items) != 1 || page.Items[0].ID != "dm-h1" || page.Items[0].Payload != "sealed-history" {
		t.Fatalf("history items = %+v", page.Items)
	}

	// Foreign users and anonymous callers get the generic 404/401.
	if rec := env.do("GET", "/api/channels/"+channel+"/messages", nil, bobJWT); rec.Code != 404 {
		t.Fatalf("foreign dm history = %d, want 404", rec.Code)
	}
	if rec := env.do("GET", "/api/channels/"+channel+"/messages", nil, ""); rec.Code != 401 {
		t.Fatalf("anonymous dm history = %d, want 401", rec.Code)
	}
}
