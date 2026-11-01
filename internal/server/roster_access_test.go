package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
)

// rosterMember mirrors the snapshot wire for assertions.
type rosterMember struct {
	ID       string            `json:"id"`
	Class    string            `json:"class"`
	Presence string            `json:"presence"`
	Access   *model.AccessWire `json:"access"`
}

func snapshotRoster(t *testing.T, frame wsFrame) map[string]rosterMember {
	t.Helper()
	raw, err := json.Marshal(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Members []rosterMember `json:"members"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("snapshot payload: %v", err)
	}
	out := map[string]rosterMember{}
	for _, m := range payload.Members {
		out[m.ID] = m
	}
	return out
}

func TestAccessForMember(t *testing.T) {
	open := &model.Channel{ID: "c-open"}
	vip := &model.Channel{ID: "c-vip", ACL: []string{"alice"}}
	other := &model.Channel{ID: "c-other", ACL: []string{"bob"}}
	cases := []struct {
		name      string
		member    *model.Member
		channels  []*model.Channel
		scope     string
		accessIDs []string
	}{
		{"owner always network", &model.Member{ID: "x", Class: model.ClassOwner}, []*model.Channel{other}, "network", nil},
		{"no channels is network", &model.Member{ID: "x", Class: model.ClassGuest}, nil, "network", nil},
		{"all open is network", &model.Member{ID: "x", Class: model.ClassGuest}, []*model.Channel{open}, "network", nil},
		{"acl covers member everywhere", &model.Member{ID: "alice", Class: model.ClassAgent}, []*model.Channel{open, vip}, "network", nil},
		{"restricted lists accessible sorted", &model.Member{ID: "alice", Class: model.ClassAgent}, []*model.Channel{other, vip, open}, "channels", []string{"c-open", "c-vip"}},
		{"excluded everywhere", &model.Member{ID: "z", Class: model.ClassGuest}, []*model.Channel{other}, "channels", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			access := accessForMember(tc.member, tc.channels)
			if access.Scope != tc.scope {
				t.Fatalf("scope = %q, want %q", access.Scope, tc.scope)
			}
			if tc.scope == "network" && len(access.ChannelIDs) != 0 {
				t.Fatalf("network scope must omit channelIds: %+v", access)
			}
			if tc.scope == "channels" {
				got := access.ChannelIDs
				if len(got) != len(tc.accessIDs) {
					t.Fatalf("channelIds = %v, want %v", got, tc.accessIDs)
				}
				for i := range got {
					if got[i] != tc.accessIDs[i] {
						t.Fatalf("channelIds = %v, want %v", got, tc.accessIDs)
					}
				}
			}
		})
	}
}

// Roster snapshots carry access for store members AND hub agents; an ACL
// patch pushes a fresh snapshot with the updated scope.
func TestRosterAccessSnapshotAndACLPatch(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, guestSess, channelID, networkID := setupNetwork(t, env)
	_, guestJoin := env.join(t, networkID, "secret123", "watcher2", "")
	guestID := guestJoin["identity"].(map[string]any)["id"].(string)

	rec := env.do("POST", "/api/networks/"+networkID+"/channels", map[string]string{"name": "vip"}, ownerSess)
	var vip map[string]any
	decodeBody(t, rec, &vip)
	vipID, _ := vip["id"].(string)
	rec = env.do("PATCH", "/api/channels/"+vipID, map[string]any{"acl": []string{"someone-else"}}, ownerSess)
	if rec.Code != 200 {
		t.Fatalf("patch vip: %d %s", rec.Code, rec.Body.String())
	}

	if err := env.st.ClaimAgentOwner(context.Background(), networkID, "public-agent"); err != nil {
		t.Fatalf("claim owner: %v", err)
	}
	env.hub.SetPresence([]hub.PresenceInfo{{AgentID: "a1", Name: "public-agent", Online: true}})
	env.hub.SetOnline(false)
	env.hub.SetOnline(true)
	waitForCondition(t, "seed", func() bool { return env.srv.relay.hubAgentName("a1") == "public-agent" })

	browser := dialWS(t, env, guestSess)
	roster := snapshotRoster(t, browser.next("roster.snapshot"))
	guest := roster[guestID]
	if guest.Access == nil || guest.Access.Scope != "channels" || len(guest.Access.ChannelIDs) != 1 || guest.Access.ChannelIDs[0] != channelID {
		t.Fatalf("guest access = %+v (want channels [%s])", guest.Access, channelID)
	}
	if roster["owner1"].Access.Scope != "network" {
		t.Fatalf("owner access = %+v", roster["owner1"].Access)
	}
	agent := roster["a1"]
	if agent.Access == nil || agent.Access.Scope != "channels" || len(agent.Access.ChannelIDs) != 1 {
		t.Fatalf("hub agent access = %+v", agent.Access)
	}

	// REST /members exposes the same scope (roster.rest parity).
	rec = env.do("GET", "/api/networks/"+networkID+"/members", nil, guestSess)
	var wires []rosterMember
	decodeBody(t, rec, &wires)
	found := false
	for _, w := range wires {
		if w.ID == guestID {
			found = true
			if w.Access == nil || w.Access.Scope != "channels" {
				t.Fatalf("REST member access = %+v", w.Access)
			}
		}
	}
	if !found {
		t.Fatal("guest not in REST members")
	}

	// ACL now names the guest: a fresh snapshot arrives with scope network.
	rec = env.do("PATCH", "/api/channels/"+vipID, map[string]any{"acl": []string{guestID}}, ownerSess)
	if rec.Code != 200 {
		t.Fatalf("patch acl guest: %d", rec.Code)
	}
	roster = snapshotRoster(t, browser.next("roster.snapshot"))
	if roster[guestID].Access.Scope != "network" {
		t.Fatalf("after acl patch guest access = %+v", roster[guestID].Access)
	}
}
