// Package server hosts the fa_network HTTP/WS surface. The service is a
// relay-only edge: it must never hold a key that decrypts channel content
// (relay-only invariant, parent card flutter_agent_harness#913).
package server

import (
	"context"
	"net/http"
	"time"

	"github.com/IstiN/fa_network/internal/auth"
	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/store"
	"github.com/IstiN/fa_network/internal/triggers"
	"github.com/IstiN/fa_network/internal/wakeup"
)

// Config tunes the HTTP surface.
type Config struct {
	// RetentionInactivityDays wipes networks idle longer than this (0=off).
	RetentionInactivityDays int
	// ChannelBytesCap is the per-channel stored-byte abuse guard.
	ChannelBytesCap int64
	// RetentionSweepInterval is the nightly sweep period (tests shrink it).
	RetentionSweepInterval time.Duration
	// Now is the clock (tests pin it).
	Now func() time.Time
	// CORSOrigins allow the browser app hosts (empty = no browser CORS).
	CORSOrigins []string
	// Triggers is the universal SCM/CI webhook ingress bridge (issue #3);
	// nil disables the /api/webhooks/* routes with 503.
	Triggers *triggers.Service
}

// Server is the fa_network edge: REST + WS over one mux.
type Server struct {
	st          store.Store
	auth        auth.Provider
	hub         hub.Client
	wake        *wakeup.Dispatcher
	cfg         Config
	relay       *Relay
	sessions    *SessionRegistry
	limiter     *RateLimiter
	corsOrigins []string
	passwords   *Passwords
	failures    *FailureTracker
	triggers    *triggers.Service
}

// New builds the server and starts its relay loop.
func New(st store.Store, authProvider auth.Provider, hubClient hub.Client, dispatcher *wakeup.Dispatcher, cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RetentionSweepInterval == 0 {
		cfg.RetentionSweepInterval = time.Hour
	}
	if cfg.ChannelBytesCap == 0 {
		cfg.ChannelBytesCap = 256 << 20
	}
	s := &Server{
		st:        st,
		auth:      authProvider,
		hub:       hubClient,
		wake:      dispatcher,
		cfg:       cfg,
		sessions:  NewSessionRegistry(),
		limiter:   NewRateLimiter(),
		passwords: NewPasswords(),
		failures:  NewFailureTracker(),
		triggers:  cfg.Triggers,
	}
	s.relay = NewRelay(st, hubClient, s.sessions, dispatcher, cfg.Now)
	if len(cfg.CORSOrigins) == 0 {
		cfg.CORSOrigins = defaultCORSOrigins()
	}
	s.corsOrigins = cfg.CORSOrigins
	return s
}

// defaultCORSOrigins covers the shipped fa1.dev surfaces plus local dev.
func defaultCORSOrigins() []string {
	return []string{
		"https://fa1.dev",
		"https://network.fa1.dev",
		"http://localhost:3000",
		"http://localhost:5173",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
	}
}

// Handler returns the root mux with every route mounted.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", serveSiteFile("index.html", "text/html"))
	mux.HandleFunc("GET /SKILL.md", serveSiteFile("SKILL.md", "text/markdown"))
	mux.HandleFunc("GET /skill.md", serveSiteFile("SKILL.md", "text/markdown"))
	mux.HandleFunc("GET /llms.txt", serveSiteFile("llms.txt", "text/plain"))
	mux.HandleFunc("GET /healthz", Healthz)
	mux.HandleFunc("POST /api/dev/login", s.devLogin) // mock provider only, 404 in prod
	mux.HandleFunc("GET /openapi.yaml", serveOpenAPI)
	mux.HandleFunc("GET /docs", serveDocs)
	mux.HandleFunc("POST /api/networks", s.createNetwork)
	mux.HandleFunc("GET /api/networks/public", s.listPublicNetworks)
	mux.HandleFunc("GET /api/networks/{networkId}/showcase", s.listShowcase)
	mux.HandleFunc("POST /api/networks/{networkId}/join", s.joinNetwork)
	mux.HandleFunc("GET /api/networks/{networkId}", s.getNetwork)
	mux.HandleFunc("PATCH /api/networks/{networkId}", s.patchNetwork)
	mux.HandleFunc("DELETE /api/networks/{networkId}", s.deleteNetwork)
	mux.HandleFunc("POST /api/networks/{networkId}/admins", s.addAdmin)
	mux.HandleFunc("DELETE /api/networks/{networkId}/admins/{userId}", s.removeAdmin)
	mux.HandleFunc("GET /api/networks/{networkId}/members", s.listMembers)
	mux.HandleFunc("GET /api/networks/{networkId}/channels", s.listChannels)
	mux.HandleFunc("POST /api/networks/{networkId}/channels", s.createChannel)
	mux.HandleFunc("GET /api/channels/{channelId}", s.getChannel)
	mux.HandleFunc("PATCH /api/channels/{channelId}", s.patchChannel)
	mux.HandleFunc("DELETE /api/channels/{channelId}", s.deleteChannel)
	mux.HandleFunc("GET /api/channels/{channelId}/messages", s.getMessages)
	mux.HandleFunc("POST /api/channels/{channelId}/messages", s.sendMessage)
	mux.HandleFunc("GET /api/networks/{networkId}/agents", s.listAgents)
	mux.HandleFunc("POST /api/networks/{networkId}/agents/enroll", s.enrollAgent)
	mux.HandleFunc("DELETE /api/networks/{networkId}/agents/{agentId}", s.dropAgent)
	mux.HandleFunc("GET /api/networks/{networkId}/agents/{agentId}/wakeups", s.getWakeup)
	mux.HandleFunc("POST /api/networks/{networkId}/agents/{agentId}/wakeups", s.registerWakeup)
	mux.HandleFunc("DELETE /api/networks/{networkId}/agents/{agentId}/wakeups", s.removeWakeup)
	mux.HandleFunc("GET /api/networks/{networkId}/wakeups/log", s.wakeupLog)
	mux.HandleFunc("GET /ws", s.serveWS)
	for _, provider := range []string{"github", "gitlab", "bitbucket", "generic"} {
		mux.HandleFunc("POST /api/webhooks/"+provider, s.handleWebhook(provider))
	}
	return newCORS(s.corsOrigins, mux)
}

// RunRelay starts background loops (hub event pump, retention sweeper).
func (s *Server) RunRelay(ctx Ctx) {
	go s.relay.Run(ctx)
	if s.cfg.RetentionInactivityDays > 0 {
		go s.retentionLoop(ctx)
	}
}

// Ctx is context.Context, aliased locally for brevity.
type Ctx = context.Context
