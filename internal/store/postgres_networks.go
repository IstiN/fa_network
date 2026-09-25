package store

import (
	"context"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// CreateNetwork implements Networks.
func (p *PGStore) CreateNetwork(ctx context.Context, n *model.Network) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO networks (id, name, owner_id, admins, public_channels, password_hash, password_salt, public, created_at, last_activity)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`,
		n.ID, n.Name, n.OwnerID, marshalJSON(n.Admins), marshalJSON(n.PublicChannels),
		n.PasswordHash, n.PasswordSalt, n.Public, n.CreatedAt.UTC())
	return mapErr(err)
}

func (p *PGStore) scanNetwork(row interface{ Scan(...any) error }) (*model.Network, error) {
	var n model.Network
	var admins, public []byte
	err := row.Scan(&n.ID, &n.Name, &n.OwnerID, &admins, &public, &n.PasswordHash, &n.PasswordSalt, &n.Public, &n.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	_ = unmarshalJSON(admins, &n.Admins)
	_ = unmarshalJSON(public, &n.PublicChannels)
	return &n, nil
}

const networkCols = `id, name, owner_id, admins, public_channels, password_hash, password_salt, public, created_at`

// Network implements Networks.
func (p *PGStore) Network(ctx context.Context, id string) (*model.Network, error) {
	return p.scanNetwork(p.db.QueryRowContext(ctx,
		`SELECT `+networkCols+` FROM networks WHERE id=$1`, id))
}

// NetworkByName implements Networks.
func (p *PGStore) NetworkByName(ctx context.Context, name string) (*model.Network, error) {
	return p.scanNetwork(p.db.QueryRowContext(ctx,
		`SELECT `+networkCols+` FROM networks WHERE name=$1`, name))
}

// UpdateNetwork implements Networks.
func (p *PGStore) UpdateNetwork(ctx context.Context, n *model.Network) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE networks SET name=$2, owner_id=$3, admins=$4, public_channels=$5, password_hash=$6, password_salt=$7, public=$8 WHERE id=$1`,
		n.ID, n.Name, n.OwnerID, marshalJSON(n.Admins), marshalJSON(n.PublicChannels), n.PasswordHash, n.PasswordSalt, n.Public)
	return mapExecErr(res, err)
}

// PublicNetworks implements Networks.
func (p *PGStore) PublicNetworks(ctx context.Context, after time.Time, afterID string, limit int) ([]*model.Network, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT `+networkCols+` FROM networks WHERE public AND
		 (created_at > $1 OR (created_at = $1 AND id > $2)) ORDER BY created_at, id LIMIT $3`,
		after.UTC(), afterID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return p.scanNetworks(rows)
}

// MemberCount implements Networks.
func (p *PGStore) MemberCount(ctx context.Context, networkID string) (int, error) {
	var count int
	err := p.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM members WHERE network_id=$1`, networkID).Scan(&count)
	return count, mapErr(err)
}

// DeleteNetwork implements Networks.
func (p *PGStore) DeleteNetwork(ctx context.Context, id string) error {
	res, err := p.db.ExecContext(ctx, `DELETE FROM networks WHERE id=$1`, id)
	return mapExecErr(res, err)
}

// InactiveNetworks implements Networks.
func (p *PGStore) InactiveNetworks(ctx context.Context, cutoff time.Time) ([]string, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT id FROM networks WHERE last_activity < $1`, cutoff.UTC())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return scanIDs(rows)
}

func scanIDs(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]string, error) {
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, id)
	}
	return out, mapErr(rows.Err())
}

// AllNetworks implements Networks.
func (p *PGStore) AllNetworks(ctx context.Context) ([]*model.Network, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT `+networkCols+` FROM networks ORDER BY id`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return p.scanNetworks(rows)
}

func (p *PGStore) scanNetworks(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*model.Network, error) {
	var out []*model.Network
	for rows.Next() {
		n, err := p.scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, mapErr(rows.Err())
}

// TouchActivity implements Store.
func (p *PGStore) TouchActivity(ctx context.Context, networkID string, at time.Time) error {
	res, err := p.db.ExecContext(ctx, `UPDATE networks SET last_activity=$2 WHERE id=$1`, networkID, at.UTC())
	return mapExecErr(res, err)
}

// networkWipeQueries are executed in order by DeleteNetworkData.
var networkWipeQueries = []string{
	`DELETE FROM members WHERE network_id=$1`,
	`DELETE FROM envelopes WHERE channel_id IN (SELECT id FROM channels WHERE network_id=$1)`,
	`DELETE FROM channels WHERE network_id=$1`,
	`DELETE FROM sessions WHERE network_id=$1`,
	`DELETE FROM wakeups WHERE network_id=$1`,
	`DELETE FROM dispatches WHERE network_id=$1`,
}

// DeleteNetworkData implements Store.
func (p *PGStore) DeleteNetworkData(ctx context.Context, networkID string) error {
	if err := p.execAll(ctx, networkWipeQueries, networkID); err != nil {
		return err
	}
	_, err := p.db.ExecContext(ctx,
		`UPDATE networks SET last_activity=$2 WHERE id=$1`, networkID, nowUTC())
	return mapErr(err)
}

func (p *PGStore) execAll(ctx context.Context, queries []string, networkID string) error {
	for _, q := range queries {
		if _, err := p.db.ExecContext(ctx, q, networkID); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

// mapExecErr converts exec results to store errors (rows-affected guard).
func mapExecErr(res interface{ RowsAffected() (int64, error) }, err error) error {
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	return noRowsToNotFound(n)
}

func noRowsToNotFound(n int64) error {
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
