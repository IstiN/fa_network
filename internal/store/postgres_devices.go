package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// Postgres persistence for enrolled connector devices (machine-connector
// contract §1). Only sha256(deviceToken) is stored — the raw bearer is
// returned once at enroll and never persisted anywhere.

var pgDeviceSchema = `
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  token_hash BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS devices_user ON devices (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS devices_token_hash ON devices (token_hash)
  WHERE revoked_at IS NULL;
`

// pgDeviceAlter: idempotent additive migrations for databases created
// before later contract phases (network kind; device friendly names).
var pgDeviceAlter = []string{
	`ALTER TABLE networks ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE devices ADD COLUMN IF NOT EXISTS friendly_name TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE devices ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT ''`,
}

// CreateDevice implements Devices.
func (p *PGStore) CreateDevice(ctx context.Context, d *model.Device) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO devices (id, user_id, name, platform, friendly_name, token_hash, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		d.ID, d.UserID, d.Name, d.Platform, d.FriendlyName, d.TokenHash, d.CreatedAt.UTC())
	return mapErr(err)
}

// Device implements Devices (revoked rows resolve too — callers that
// only need auth use DeviceByTokenHash, which filters them).
func (p *PGStore) Device(ctx context.Context, deviceID string) (*model.Device, error) {
	return pgScanDevice(p.db.QueryRowContext(ctx,
		`SELECT id, user_id, name, platform, friendly_name, token_hash, created_at, revoked_at
		 FROM devices WHERE id = $1`, deviceID))
}

// DeviceByTokenHash implements Devices: revocation == deletion for auth.
func (p *PGStore) DeviceByTokenHash(ctx context.Context, hash []byte) (*model.Device, error) {
	return pgScanDevice(p.db.QueryRowContext(ctx,
		`SELECT id, user_id, name, platform, friendly_name, token_hash, created_at, revoked_at
		 FROM devices WHERE token_hash = $1 AND revoked_at IS NULL`, hash))
}

// DevicesOfUser implements Devices.
func (p *PGStore) DevicesOfUser(ctx context.Context, userID string) ([]*model.Device, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, user_id, name, platform, friendly_name, token_hash, created_at, revoked_at
		 FROM devices WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return scanDevices(rows)
}

func scanDevices(rows *sql.Rows) ([]*model.Device, error) {
	var out []*model.Device
	for rows.Next() {
		d, err := pgScanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, mapErr(rows.Err())
}

// RevokeDevice implements Devices.
func (p *PGStore) RevokeDevice(ctx context.Context, deviceID string, at time.Time) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE devices SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`,
		deviceID, at.UTC())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return notFound("device", deviceID)
	}
	return nil
}

// RenameDevice implements Devices: account-scoped by user_id in the
// WHERE clause — a foreign or revoked device matches zero rows.
func (p *PGStore) RenameDevice(ctx context.Context, userID, deviceID, name string) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE devices SET friendly_name = $3 WHERE id = $2 AND user_id = $1 AND revoked_at IS NULL`,
		userID, deviceID, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return notFound("device", deviceID)
	}
	return nil
}

// PersonalNetwork implements Networks.
func (p *PGStore) PersonalNetwork(ctx context.Context, userID string) (*model.Network, error) {
	return p.scanNetwork(p.db.QueryRowContext(ctx,
		`SELECT `+networkCols+` FROM networks WHERE kind = $1 AND owner_id = $2 ORDER BY created_at, id LIMIT 1`,
		model.NetworkPersonal, userID))
}

func pgScanDevice(row interface{ Scan(...any) error }) (*model.Device, error) {
	var d model.Device
	var revoked sql.NullTime
	err := row.Scan(&d.ID, &d.UserID, &d.Name, &d.Platform, &d.FriendlyName, &d.TokenHash, &d.CreatedAt, &revoked)
	if err != nil {
		return nil, mapErr(err)
	}
	if revoked.Valid {
		t := revoked.Time.UTC()
		d.RevokedAt = &t
	}
	return &d, nil
}
