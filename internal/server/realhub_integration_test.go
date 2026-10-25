package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/auth"
	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/store"
	"github.com/IstiN/fa_network/internal/wakeup"
)

// TestRealHubChannelEnrollJoinIntegration reproduces the production
// incident end-to-end against the REAL dap hub binary: create a channel
// via REST, enroll an agent, join with the issued clientSecret (NO
// master) — the join must succeed because createChannel ensured the
// channel on the hub. Runs when the dap source is available
// (DAP_HUB_SRC or /tmp/dap-src/hub); skipped otherwise.
func TestRealHubChannelEnrollJoinIntegration(t *testing.T) {
	src := os.Getenv("DAP_HUB_SRC")
	if src == "" {
		src = "/tmp/dap-src/hub"
	}
	if _, err := os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Skipf("dap hub source unavailable at %s (set DAP_HUB_SRC)", src)
	}
	dir := t.TempDir()
	hubBin := filepath.Join(dir, "daphub")
	build := exec.Command("go", "build", "-o", hubBin, ".")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build hub: %v\n%s", err, out)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	cmd := exec.Command(hubBin, "-addr", addr, "-master-secret", "master", "-admin-token", "adm",
		"-channels-file", filepath.Join(dir, "channels.json"),
		"-secrets-file", filepath.Join(dir, "secrets.json"))
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	hubURL := "ws://" + addr + "/ws"
	relayClient, err := hub.NewDapClient(hub.DapConfig{URL: hubURL, MasterSecret: "master", Name: "fa-network-relay"})
	if err != nil {
		t.Fatal(err)
	}
	go relayClient.Run(ctx)
	waitForCondition(t, "relay online", func() bool { return relayClient.Online() })

	st := store.NewMemStore()
	provider := auth.NewMockProvider([]byte("0123456789abcdef0123456789abcdef"))
	dispatcher := wakeup.NewDispatcher(wakeup.Options{Store: st, Secret: []byte("sec")})
	srv := New(st, provider, relayClient, dispatcher, Config{RetentionInactivityDays: 30, RetentionSweepInterval: time.Hour})
	env := &testEnv{t: t, srv: srv, st: st, auth: provider}
	srv.RunRelay(ctx)
	env.http = httptest.NewServer(srv.Handler())
	t.Cleanup(env.http.Close)

	ownerToken := env.authedToken("owner1", "Owner One")
	networkID := env.createNetwork(t, ownerToken, "istin-network", "secret123")
	ownerSess, _ := env.join(t, networkID, "secret123", "", ownerToken)
	rec := env.do("POST", "/api/networks/"+networkID+"/channels", map[string]string{"name": "kb-private"}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create channel: %d %s", rec.Code, rec.Body.String())
	}
	var channel map[string]any
	decodeBody(t, rec, &channel)
	channelID, _ := channel["id"].(string)

	rec = env.do("POST", "/api/networks/"+networkID+"/agents/enroll", map[string]string{"name": "kb-agent"}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	var enrolled map[string]any
	decodeBody(t, rec, &enrolled)
	secret, _ := enrolled["clientSecret"].(string)
	if secret == "" {
		t.Fatal("no clientSecret issued")
	}

	// The enrolled agent connects with ONLY its clientSecret and joins.
	agent, err := hub.NewDapClient(hub.DapConfig{URL: hubURL, MasterSecret: secret, Name: "kb-agent"})
	if err != nil {
		t.Fatal(err)
	}
	go agent.Run(ctx)
	waitForCondition(t, "agent online", func() bool { return agent.Online() })
	joinCtx, joinCancel := context.WithTimeout(ctx, 5*time.Second)
	defer joinCancel()
	if err := agent.Join(joinCtx, channelID); err != nil {
		t.Fatalf("agent join write: %v", err)
	}

	// The hub registry must show the channel with relay+agent members.
	adminURL := "http://" + addr + "/api/channels"
	deadline := time.Now().Add(5 * time.Second)
	for {
		members := hubChannelMembers(t, adminURL, channelID)
		if members >= 2 {
			t.Logf("OK: channel %s has %d members (relay + enrolled agent, no master)", channelID, members)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent without master never joined %s (members=%d)", channelID, members)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// hubChannelMembers reads the hub admin channel registry.
func hubChannelMembers(t *testing.T, adminURL, channelID string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, adminURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer adm")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var channels []struct {
		Name    string `json:"name"`
		Members int    `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&channels); err != nil {
		return 0
	}
	for _, ch := range channels {
		if ch.Name == channelID {
			return ch.Members
		}
	}
	return 0
}
