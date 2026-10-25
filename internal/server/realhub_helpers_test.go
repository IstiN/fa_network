package server

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/IstiN/fa_network/internal/auth"
	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/store"
	"github.com/IstiN/fa_network/internal/wakeup"
	"time"
)

// startRealDapHub builds and starts the REAL dap hub binary (env-gated on
// DAP_HUB_SRC or /tmp/dap-src/hub) and returns its ws:// URL.
func startRealDapHub(t *testing.T) string {
	t.Helper()
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
	return "ws://" + addr + "/ws"
}

// newRealHubEnv starts a fa_network server whose relay talks to the real
// hub (master-enrolled, like production) and returns the env + client.
func newRealHubEnv(t *testing.T, hubURL string) (*testEnv, *hub.DapClient) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	relayClient, err := hub.NewDapClient(hub.DapConfig{URL: hubURL, MasterSecret: "master", Name: "fa-network-relay"})
	if err != nil {
		t.Fatal(err)
	}
	go relayClient.Run(ctx)
	waitRelayOnline(t, relayClient)

	st := store.NewMemStore()
	provider := auth.NewMockProvider([]byte("0123456789abcdef0123456789abcdef"))
	dispatcher := wakeup.NewDispatcher(wakeup.Options{Store: st, Secret: []byte("sec")})
	srv := New(st, provider, relayClient, dispatcher, Config{RetentionInactivityDays: 30, RetentionSweepInterval: time.Hour})
	env := &testEnv{t: t, srv: srv, st: st, auth: provider}
	srv.RunRelay(ctx)
	env.http = httptest.NewServer(srv.Handler())
	t.Cleanup(env.http.Close)
	return env, relayClient
}

// waitRelayOnline allows for hub-binary startup and dial backoff (the
// shared 2s test condition is too tight under -race).
func waitRelayOnline(t *testing.T, client *hub.DapClient) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if client.Online() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timeout waiting for relay online")
}
