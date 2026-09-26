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
}

// Server is the fa_network edge: REST + WS over one mux.
type Server struct {
	st        store.Store
	auth      auth.Provider
	hub       hub.Client
	wake      *wakeup.Dispatcher
	cfg       Config
	relay     *Relay
	sessions  *SessionRegistry
	limiter   *RateLimiter
	passwords *Passwords
	failures  *FailureTracker
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
	}
	s.relay = NewRelay(st, hubClient, s.sessions, dispatcher, cfg.Now)
	return s
}

// Handler returns the root mux with every route mounted.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
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
	mux.HandleFunc("GET /api/networks/{networkId}/agents/{agentId}/wakeups", s.getWakeup)
	mux.HandleFunc("POST /api/networks/{networkId}/agents/{agentId}/wakeups", s.registerWakeup)
	mux.HandleFunc("DELETE /api/networks/{networkId}/agents/{agentId}/wakeups", s.removeWakeup)
	mux.HandleFunc("GET /api/networks/{networkId}/wakeups/log", s.wakeupLog)
	mux.HandleFunc("GET /ws", s.serveWS)
	return mux
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
