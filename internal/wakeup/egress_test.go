package wakeup

// egress_test.go — review #8: the wake-up dispatcher dials public
// addresses only, on every connection, and never follows redirects.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestControlFuncBlocksNonPublic(t *testing.T) {
	blocked := []string{
		"127.0.0.1:443",          // loopback
		"localhost:80",           // resolves pre-Control? Control sees IP; direct check anyway
		"[::1]:443",              // IPv6 loopback
		"10.0.0.5:80",            // RFC1918
		"192.168.1.10:8080",      // RFC1918
		"172.16.0.1:80",          // RFC1918
		"169.254.169.254:80",     // link-local / cloud metadata
		"fe80::1:80",             // IPv6 link-local
		"0.0.0.0:80",             // unspecified
		"fd00::1:80",             // IPv6 ULA (private)
		"224.0.0.1:80",           // multicast
		"not-an-ip:80",           // non-literal (should never reach Control)
	}
	for _, addr := range blocked {
		if err := controlFunc("tcp", addr, nil); err == nil {
			t.Errorf("controlFunc(%q) allowed", addr)
		}
	}
	if err := controlFunc("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("public IPv4 blocked: %v", err)
	}
	if err := controlFunc("tcp", "[2606:2800:220:1:248:1893:25c8:1946]:443", nil); err != nil {
		t.Errorf("public IPv6 blocked: %v", err)
	}
	if err := controlFunc("udp", "8.8.8.8:53", nil); err == nil {
		t.Error("non-tcp network allowed")
	}
}

func TestBlockedAddrCoversPrivateRanges(t *testing.T) {
	for _, cidr := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
		ip := ipOfCIDR(t, cidr)
		if !blockedAddr(ip) {
			t.Errorf("%s not blocked", ip)
		}
	}
}

func ipOfCIDR(t *testing.T, cidr string) net.IP {
	t.Helper()
	_, netIP, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return netIP.IP
}

// TestGuardedClientRefusesLoopback: an httptest server binds 127.0.0.1 —
// exactly the address class the guard must refuse to dial. The dispatch
// must land as target_down, never reach the handler.
func TestGuardedClientRefusesLoopback(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	defer srv.Close()

	d := NewDispatcher(Options{Store: nil, Secret: []byte("sec")})
	start := time.Now()
	req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := d.http.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	if reached {
		t.Fatal("loopback dial reached the handler")
	}
	if resp != nil {
		t.Fatalf("unexpected response: %d", resp.StatusCode)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("guard must fail fast, not hang")
	}
}

// TestGuardedClientDoesNotFollowRedirects: the default client's policy
// is passthrough — a 302 must never trigger a second request (the
// redirect target is unvetted).
func TestGuardedClientDoesNotFollowRedirects(t *testing.T) {
	d := NewDispatcher(Options{})
	if d.http.CheckRedirect == nil {
		t.Fatal("no CheckRedirect policy installed")
	}
	req, _ := http.NewRequest(http.MethodPost, "https://example.invalid/next", nil)
	if err := d.http.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}
