package wakeup

// egress.go — SSRF egress policy for wake-up dispatch (security review
// item #8). Registration URLs are owner/admin-only input, but that is a
// privilege check, not a network policy: the dispatcher previously
// POSTed anywhere http(s), including loopback, RFC1918 ranges,
// link-local (GCE metadata among them), and followed redirects.
//
// The policy here is enforced on EVERY dial, after DNS resolution (the
// Control hook sees the resolved address), so DNS-rebinding tricks that
// resolve public during registration and private during dispatch are
// still blocked. Redirects are disabled outright (webhooks are
// single-hop machine endpoints; a redirect is indistinguishable from an
// attack path). Registration-time validation (agents.go validWebhookURL)
// stays as the fast UX check; this dial-time guard is the security
// boundary.

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// blockedAddr reports whether an already-resolved address must not be
// dialed: loopback, unspecified, private (RFC1918 + ULA), link-local
// unicast/multicast (169.254.0.0/16 covers cloud metadata endpoints),
// and multicast in general. Public unicast only.
func blockedAddr(ip net.IP) bool {
	return ip == nil ||
		ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast()
}

// controlFunc is the net.Dialer Control hook: network is the dial
// network, address the resolved "ip:port". Non-TCP networks are refused
// (the dispatcher only ever speaks http/s).
func controlFunc(network, address string, _ syscall.RawConn) error {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return fmt.Errorf("wakeup egress: network %q refused", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("wakeup egress: bad address %q", address)
	}
	if ip := net.ParseIP(host); blockedAddr(ip) {
		return fmt.Errorf("wakeup egress: %s is not a public address", host)
	}
	return nil
}

// newGuardedClient builds the default dispatcher client: 10s timeout,
// no redirects, and a transport whose dialer enforces controlFunc on
// every connection attempt.
func newGuardedClient() *http.Client {
	dialer := &net.Dialer{Control: controlFunc}
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{DialContext: dialer.DialContext},
	}
}
