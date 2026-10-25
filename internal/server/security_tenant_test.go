package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/IstiN/fa_network/internal/model"
)

// Review #1: a session token is network-bound — a low-privilege session
// from network A must never act with the user's class in network B.
func TestSessionBoundToNetwork(t *testing.T) {
	env := newTestEnv(t)
	ownerA := env.authedToken("owner-a", "Owner A")
	netA := env.createNetwork(t, ownerA, "net-a", "secret123")
	user := env.authedToken("user2", "User Two")
	sessA, _ := env.join(t, netA, "secret123", "", user)     // plain member in A
	netB := env.createNetwork(t, user, "net-b", "secret123") // owner in B

	// Management route on B with the A session must fail closed.
	rec := env.do("DELETE", "/api/networks/"+netB+"/members/someone", nil, sessA)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-network session status = %d body %s, want 403", rec.Code, rec.Body.String())
	}
	// Read route too (identity resolution is shared).
	rec = env.do("GET", "/api/networks/"+netB, nil, sessA)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-network read = %d, want 403", rec.Code)
	}
	// The user's own B session still works.
	sessB, _ := env.join(t, netB, "secret123", "", user)
	if rec := env.do("GET", "/api/networks/"+netB, nil, sessB); rec.Code != http.StatusOK {
		t.Fatalf("own-network session = %d, want 200", rec.Code)
	}
}

// Review #3: agent names are first-come owned — only the owning network
// may re-enroll (rotate the name-bound secret).
func TestEnrollOwnershipCrossTenant(t *testing.T) {
	env := newTestEnv(t)
	ownerA := env.authedToken("owner-a", "Owner A")
	netA := env.createNetwork(t, ownerA, "net-a", "secret123")
	ownerB := env.authedToken("owner-b", "Owner B")
	netB := env.createNetwork(t, ownerB, "net-b", "secret123")

	enroll := func(networkID, token string) *int {
		rec := env.do("POST", "/api/networks/"+networkID+"/agents/enroll",
			map[string]string{"name": "shared-agent"}, token)
		return &rec.Code
	}
	if code := enroll(netA, ownerA); *code != http.StatusCreated {
		t.Fatalf("first enroll = %d, want 201", *code)
	}
	if code := enroll(netB, ownerB); *code != http.StatusConflict {
		t.Fatalf("cross-tenant enroll = %d, want 409", *code)
	}
	if code := enroll(netA, ownerA); *code != http.StatusCreated {
		t.Fatalf("same-network re-enroll (rotation) = %d, want 201", *code)
	}
}

// Review #10: promoting a guest must not turn its existing guest token
// into a management token.
func TestGuestCannotBePromotedToAdmin(t *testing.T) {
	env := newTestEnv(t)
	_, ownerSess, _, _, networkID := setupNetwork(t, env)
	_, joined := env.join(t, networkID, "secret123", "guestie", "")
	identity := joined["identity"].(map[string]any)
	guestID := identity["id"].(string)

	rec := env.do("POST", "/api/networks/"+networkID+"/admins",
		map[string]string{"userId": guestID}, ownerSess)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("guest promotion = %d body %s, want 403", rec.Code, rec.Body.String())
	}
	member, err := env.st.Member(context.Background(), networkID, guestID)
	if err != nil || member.Class != model.ClassGuest {
		t.Fatalf("guest class changed: %+v err %v", member, err)
	}
	network, err := env.st.Network(context.Background(), networkID)
	if err != nil {
		t.Fatal(err)
	}
	for _, admin := range network.Admins {
		if admin == guestID {
			t.Fatal("guest appended to network admins despite rejection")
		}
	}
}
