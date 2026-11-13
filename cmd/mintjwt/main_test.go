package main

import (
	"testing"

	"github.com/IstiN/fa_network/internal/auth"
)

// TestMintTokenVerifies: the minted token must validate against a fresh
// MockProvider sharing the secret — exactly what a repro-stand server
// does with FA_NETWORK_MOCK_SECRET.
func TestMintTokenVerifies(t *testing.T) {
	tok, err := mint("alice")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	m := auth.NewMockProvider([]byte(mockSecret))
	if _, err := m.Validate(nil, tok); err != nil {
		t.Fatalf("validate: %v", err)
	}
}
