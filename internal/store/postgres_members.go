package store

import (
	"context"
	"database/sql"

	"github.com/IstiN/fa_network/internal/model"
)

// UpsertMember implements Members.
func (p *PGStore) UpsertMember(ctx context.Context, m *model.Member) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO members (network_id, id, class, display_name, presence)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (network_id, id) DO UPDATE SET class=$3, display_name=$4, presence=$5`,
		m.NetworkID, m.ID, m.Class, m.DisplayName, m.Presence)
	return mapErr(err)
}

func scanMember(row interface{ Scan(...any) error }) (*model.Member, error) {
	var m model.Member
	err := row.Scan(&m.NetworkID, &m.ID, &m.Class, &m.DisplayName, &m.Presence)
	if err != nil {
		return nil, mapErr(err)
	}
	return &m, nil
}

const memberCols = `network_id, id, class, display_name, presence`

// Member implements Members.
func (p *PGStore) Member(ctx context.Context, networkID, id string) (*model.Member, error) {
	return scanMember(p.db.QueryRowContext(ctx,
		`SELECT `+memberCols+` FROM members WHERE network_id=$1 AND id=$2`, networkID, id))
}

// MemberByName implements Members.
func (p *PGStore) MemberByName(ctx context.Context, networkID, displayName string) (*model.Member, error) {
	return scanMember(p.db.QueryRowContext(ctx,
		`SELECT `+memberCols+` FROM members WHERE network_id=$1 AND display_name=$2`, networkID, displayName))
}

// Members implements Members.
func (p *PGStore) Members(ctx context.Context, networkID string) ([]*model.Member, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT `+memberCols+` FROM members WHERE network_id=$1 ORDER BY id`, networkID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return scanMembers(rows)
}

func scanMembers(rows *sql.Rows) ([]*model.Member, error) {
	var out []*model.Member
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, mapErr(rows.Err())
}

// UpdateMemberPresence implements Members.
func (p *PGStore) UpdateMemberPresence(ctx context.Context, networkID, id, presence string) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE members SET presence=$3 WHERE network_id=$1 AND id=$2`, networkID, id, presence)
	return mapExecErr(res, err)
}

// DeleteMember implements Members.
func (p *PGStore) DeleteMember(ctx context.Context, networkID, id string) error {
	res, err := p.db.ExecContext(ctx,
		`DELETE FROM members WHERE network_id=$1 AND id=$2`, networkID, id)
	return mapExecErr(res, err)
}

// CreateChannel implements Channels.
func (p *PGStore) CreateChannel(ctx context.Context, c *model.Channel) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO channels (id, network_id, name, public, acl, retention_days) VALUES ($1,$2,$3,$4,$5,$6)`,
		c.ID, c.NetworkID, c.Name, c.Public, marshalJSON(c.ACL), nullableInt(c.RetentionDays))
	return mapErr(err)
}

func nullableInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func scanChannel(row interface{ Scan(...any) error }) (*model.Channel, error) {
	var c model.Channel
	var acl []byte
	var ret sql.NullInt64
	err := row.Scan(&c.ID, &c.NetworkID, &c.Name, &c.Public, &acl, &ret)
	if err != nil {
		return nil, mapErr(err)
	}
	_ = unmarshalJSON(acl, &c.ACL)
	c.RetentionDays = intOrNil(ret)
	return &c, nil
}

// Channel implements Channels.
func (p *PGStore) Channel(ctx context.Context, id string) (*model.Channel, error) {
	return scanChannel(p.db.QueryRowContext(ctx,
		`SELECT id, network_id, name, public, acl, retention_days FROM channels WHERE id=$1`, id))
}

// ChannelByName implements Channels.
func (p *PGStore) ChannelByName(ctx context.Context, networkID, name string) (*model.Channel, error) {
	return scanChannel(p.db.QueryRowContext(ctx,
		`SELECT id, network_id, name, public, acl, retention_days FROM channels WHERE network_id=$1 AND name=$2`,
		networkID, name))
}

// Channels implements Channels.
func (p *PGStore) Channels(ctx context.Context, networkID string) ([]*model.Channel, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, network_id, name, public, acl, retention_days FROM channels WHERE network_id=$1 ORDER BY id`, networkID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return scanChannels(rows)
}

func scanChannels(rows *sql.Rows) ([]*model.Channel, error) {
	var out []*model.Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, mapErr(rows.Err())
}

// UpdateChannel implements Channels.
func (p *PGStore) UpdateChannel(ctx context.Context, c *model.Channel) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE channels SET name=$2, public=$3, acl=$4, retention_days=$5 WHERE id=$1`,
		c.ID, c.Name, c.Public, marshalJSON(c.ACL), nullableInt(c.RetentionDays))
	return mapExecErr(res, err)
}

// DeleteChannel implements Channels.
func (p *PGStore) DeleteChannel(ctx context.Context, id string) error {
	res, err := p.db.ExecContext(ctx, `DELETE FROM channels WHERE id=$1`, id)
	return mapExecErr(res, err)
}

// ChannelsWithRetention implements Channels.
func (p *PGStore) ChannelsWithRetention(ctx context.Context) ([]*model.Channel, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, network_id, name, public, acl, retention_days FROM channels WHERE retention_days IS NOT NULL`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return scanChannels(rows)
}
