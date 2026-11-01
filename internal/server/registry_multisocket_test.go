package server

// registry_multisocket_test.go — regressions for the production incident
// where several concurrent sockets shared one session token (Chrome +
// Safari): the old token→single-conn registry dropped fanout to all but
// the last socket, and an older closing socket unregistered the newer
// one. The registry now keys tokens to connection SETS with
// identity-safe removal.

import (
	"testing"

	"github.com/IstiN/fa_network/internal/model"
)

func testConn(token, networkID, memberID, class string) *wsConn {
	return newWSConn(&model.Session{Token: token, NetworkID: networkID, MemberID: memberID}, class)
}

// Two sockets of one token must BOTH receive every fanout frame.
func TestSameTokenBothSocketsReceiveFanout(t *testing.T) {
	r := NewSessionRegistry()
	first, second := testConn("tok", "n1", "m1", model.ClassMember), testConn("tok", "n1", "m1", model.ClassMember)
	r.Add(first)
	r.Add(second)
	first.setSub("ch1", true)
	second.setSub("ch1", true)

	r.FanoutEnvelope("n1", model.EnvelopeWire{ID: "e1", ChannelID: "ch1"})
	for i, c := range []*wsConn{first, second} {
		select {
		case frame := <-c.send:
			if frame.Type != "envelope" {
				t.Fatalf("socket %d frame = %s", i, frame.Type)
			}
		default:
			t.Fatalf("socket %d missed the fanout", i)
		}
	}
}

// The OLD socket closing must not unregister the NEW one (the closing
// handler used to delete by token, killing its replacement).
func TestOldSocketCloseKeepsNewSocket(t *testing.T) {
	r := NewSessionRegistry()
	first, second := testConn("tok", "n1", "m1", model.ClassMember), testConn("tok", "n1", "m1", model.ClassMember)
	r.Add(first)
	r.Add(second)

	r.Remove(first) // old socket cleanup fires first
	if r.Get("tok") == nil {
		t.Fatal("new socket unregistered by old socket's removal")
	}
	second.setSub("ch1", true)
	r.FanoutEnvelope("n1", model.EnvelopeWire{ID: "e2", ChannelID: "ch1"})
	select {
	case <-second.send:
	default:
		t.Fatal("new socket misses fanout after old socket closed")
	}
	if r.MemberLive("n1", "m1") != true {
		t.Fatal("member must still be live")
	}
	r.Remove(second)
	if r.MemberLive("n1", "m1") {
		t.Fatal("member must be gone after the last socket")
	}
}

// KickMember with several sockets of the same member disconnects them
// all, and other members' sockets stay.
func TestKickMemberAllSockets(t *testing.T) {
	r := NewSessionRegistry()
	a1 := testConn("tok-a1", "n1", "m1", model.ClassMember)
	a2 := testConn("tok-a2", "n1", "m1", model.ClassMember)
	other := testConn("tok-b", "n1", "m2", model.ClassMember)
	r.Add(a1)
	r.Add(a2)
	r.Add(other)

	closed := map[*wsConn]bool{}
	for _, c := range []*wsConn{a1, a2, other} {
		conn := c
		conn.closeConn = func() { closed[conn] = true }
	}
	r.KickMember("n1", "m1")
	if !closed[a1] || !closed[a2] {
		t.Fatalf("kick must close every member socket: %+v", closed)
	}
	if closed[other] {
		t.Fatal("unrelated socket closed")
	}
}
