package store

import (
	"context"
	"os"
	"testing"
)

// TestPostgresStoreContract runs the Store contract against real
// Postgres — opt-in via FA_NETWORK_TEST_PG_URL (integration convention:
// deterministic offline by default, database leg when the env points at
// a throwaway instance). It exists because the memory store cannot
// represent SQL-level constraints: the personal-network enroll 500
// (nil password hash binding as NULL against NOT NULL, SQLSTATE 23502)
// shipped green through the memory-only leg.
func TestPostgresStoreContract(t *testing.T) {
	url := os.Getenv("FA_NETWORK_TEST_PG_URL")
	if url == "" {
		t.Skip("FA_NETWORK_TEST_PG_URL not set; Postgres contract leg skipped")
	}
	ctx := context.Background()
	ContractTest(t, func(t *testing.T) Store {
		t.Helper()
		s, err := NewPostgres(ctx, url)
		if err != nil {
			t.Fatalf("open postgres: %v", err)
		}
		t.Cleanup(func() { _ = s.Close(ctx) })
		// Each contract subtest gets a physically fresh schema state:
		// the contract relies on fixed row ids, so leftovers from a
		// previous run or subtest would surface as bogus conflicts.
		const reset = `TRUNCATE networks, members, channels, envelopes,
			sessions, wakeups, dispatches, agent_drops, agent_owners,
			channel_reads, devices`
		if _, err := s.db.ExecContext(ctx, reset); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return s
	})
}
