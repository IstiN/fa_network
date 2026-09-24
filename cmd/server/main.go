// Command server runs the fa_network edge service: the people-facing
// REST+WS bridge between browsers and the dap hub (issue #1).
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/IstiN/fa_network/internal/auth"
	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/server"
	"github.com/IstiN/fa_network/internal/store"
	"github.com/IstiN/fa_network/internal/wakeup"
)

func main() {
	addr := flag.String("addr", envOr("FA_NETWORK_ADDR", ":8080"), "listen address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := openStore(ctx)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close(context.Background())

	srv := buildServer(st)
	srv.RunRelay(ctx)
	serveHTTP(ctx, *addr, srv)
}

// buildServer wires stores, auth, hub, and dispatcher from the environment.
func buildServer(st store.Store) *server.Server {
	provider, err := auth.FromEnv()
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	hubClient := openHub()
	go func() {
		if err := hubClient.Run(context.Background()); err != nil {
			log.Printf("hub: %v", err)
		}
	}()
	dispatcher := wakeup.NewDispatcher(wakeup.Options{
		Store:  st,
		Secret: []byte(os.Getenv("FA_NETWORK_WEBHOOK_SECRET")),
	})
	return server.New(st, provider, hubClient, dispatcher, server.Config{
		RetentionInactivityDays: envInt("FA_NETWORK_RETENTION_INACTIVITY_DAYS", 30),
		ChannelBytesCap:         envInt64("FA_NETWORK_RETENTION_CHANNEL_BYTES", 256<<20),
		RetentionSweepInterval:  envDuration("FA_NETWORK_RETENTION_SWEEP_INTERVAL", time.Hour),
	})
}

// serveHTTP runs the listener until ctx is cancelled.
func serveHTTP(ctx context.Context, addr string, srv *server.Server) {
	httpServer := &http.Server{Addr: addr, Handler: srv.Handler()}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	log.Printf("fa_network listening on %s", addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

// openStore picks Postgres when FA_NETWORK_DATABASE_URL is set, else memory.
func openStore(ctx context.Context) (store.Store, error) {
	if url := os.Getenv("FA_NETWORK_DATABASE_URL"); url != "" {
		return store.NewPostgres(ctx, url)
	}
	return store.NewMemStore(), nil
}

// openHub picks the dap client when FA_NETWORK_DAP_URL is set, else a
// permanently-offline stub (REST + WS still work; relay queues until a hub
// is configured).
func openHub() hub.Client {
	url := os.Getenv("FA_NETWORK_DAP_URL")
	if url == "" {
		return hub.NewFakeClient("r_offline")
	}
	client, err := hub.NewDapClient(hub.DapConfig{
		URL:          url,
		MasterSecret: os.Getenv("FA_NETWORK_DAP_SECRET"),
		Name:         envOr("FA_NETWORK_DAP_NAME", "fa-network-relay"),
	})
	if err != nil {
		log.Printf("hub: %v (using offline stub)", err)
		return hub.NewFakeClient("r_offline")
	}
	return client
}

// envOr returns the environment variable value for key, or fallback when
// unset or empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
