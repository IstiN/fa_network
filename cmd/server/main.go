// Command server runs the fa_network edge service: the people-facing
// REST+WS bridge between browsers and the dap hub (issue #1).
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/IstiN/fa_network/internal/server"
)

func main() {
	addr := flag.String("addr", envOr("FA_NETWORK_ADDR", ":8080"), "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.Healthz)

	log.Printf("fa_network listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// envOr returns the environment variable value for key, or fallback when
// unset or empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
