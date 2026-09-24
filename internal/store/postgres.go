// Postgres persistence for production (Cloud SQL Postgres). The same
// Store contract as the in-memory dev store; payloads stay opaque here
// too — envelopes.payload is text(base64 ciphertext), never inspected.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver
)

// PGStore is a Postgres-backed Store.
type PGStore struct {
	db *sql.DB
}

const pgSchema = `
CREATE TABLE IF NOT EXISTS networks (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  owner_id TEXT NOT NULL,
  admins JSONB NOT NULL DEFAULT '[]',
  public_channels JSONB NOT NULL DEFAULT '[]',
  password_hash BYTEA NOT NULL,
  password_salt BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  last_activity TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
  network_id TEXT NOT NULL,
  id TEXT NOT NULL,
  class TEXT NOT NULL,
  display_name TEXT NOT NULL,
  presence TEXT NOT NULL,
  PRIMARY KEY (network_id, id)
);
CREATE TABLE IF NOT EXISTS channels (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL,
  name TEXT NOT NULL,
  public BOOLEAN NOT NULL DEFAULT FALSE,
  acl JSONB NOT NULL DEFAULT '[]',
  retention_days INT,
  UNIQUE (network_id, name)
);
CREATE TABLE IF NOT EXISTS envelopes (
  seq BIGSERIAL PRIMARY KEY,
  channel_id TEXT NOT NULL,
  id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  mentions JSONB NOT NULL DEFAULT '[]',
  created_at TIMESTAMPTZ NOT NULL,
  UNIQUE (channel_id, id)
);
CREATE INDEX IF NOT EXISTS envelopes_channel_seq ON envelopes (channel_id, seq);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  network_id TEXT NOT NULL,
  member_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS wakeups (
  network_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret_hash BYTEA NOT NULL,
  debounce_seconds INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (network_id, agent_id)
);
CREATE TABLE IF NOT EXISTS dispatches (
  seq BIGSERIAL PRIMARY KEY,
  network_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  at TIMESTAMPTZ NOT NULL,
  outcome TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS dispatches_network_seq ON dispatches (network_id, seq);
`

// NewPostgres connects, verifies, and migrates a Postgres store.
func NewPostgres(ctx context.Context, databaseURL string) (*PGStore, error) {
	db, err := openPG(databaseURL)
	if err != nil {
		return nil, err
	}
	return pingAndMigrate(ctx, db)
}

func openPG(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	return db, nil
}

func pingAndMigrate(ctx context.Context, db *sql.DB) (*PGStore, error) {
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return migrate(ctx, db)
}

func migrate(ctx context.Context, db *sql.DB) (*PGStore, error) {
	if _, err := db.ExecContext(ctx, pgSchema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &PGStore{db: db}, nil
}

// Close implements Store.
func (p *PGStore) Close(_ context.Context) error { return p.db.Close() }

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return pgConflict(err)
}

func pgConflict(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return err
}

func marshalJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("[]")
	}
	return b
}

func unmarshalJSON(data []byte, v any) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

// intOrNil dereferences a possibly-null retention value.
func intOrNil(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	d := int(n.Int64)
	return &d
}

// nowUTC centralizes timestamps.
func nowUTC() time.Time { return time.Now().UTC() }
