package store

import (
	"context"
	"database/sql"
	"time"
)

// DropAgent implements AgentDrops (idempotent, per-network).
func (p *PGStore) DropAgent(ctx context.Context, networkID, agentID string) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO agent_drops (network_id, agent_id, created_at) VALUES ($1, $2, $3)
		 ON CONFLICT (network_id, agent_id) DO NOTHING`, networkID, agentID, time.Now().UTC())
	return err
}

// DroppedAgents implements AgentDrops.
func (p *PGStore) DroppedAgents(ctx context.Context) (map[string][]string, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT network_id, agent_id FROM agent_drops ORDER BY network_id, agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAgentDrops(rows)
}

func scanAgentDrops(rows *sql.Rows) (map[string][]string, error) {
	out := map[string][]string{}
	for rows.Next() {
		var networkID, agentID string
		if err := rows.Scan(&networkID, &agentID); err != nil {
			return nil, err
		}
		out[networkID] = append(out[networkID], agentID)
	}
	return out, rows.Err()
}

// ClaimAgentOwner implements AgentOwnership: the insert is atomic, so two
// networks cannot claim the same agent name concurrently.
func (p *PGStore) ClaimAgentOwner(ctx context.Context, networkID, agentName string) error {
	var owner string
	err := p.db.QueryRowContext(ctx,
		`INSERT INTO agent_owners (agent_name, network_id, created_at) VALUES ($1, $2, $3)
		 ON CONFLICT (agent_name) DO NOTHING RETURNING network_id`,
		agentName, networkID, time.Now().UTC()).Scan(&owner)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	return p.claimConflict(ctx, networkID, agentName)
}

// claimConflict resolves an existing ownership row after a lost insert.
func (p *PGStore) claimConflict(ctx context.Context, networkID, agentName string) error {
	owner, err := p.AgentOwner(ctx, agentName)
	if err != nil {
		return err
	}
	if owner != networkID {
		return ErrConflict
	}
	return nil
}

// AgentOwner implements AgentOwnership.
func (p *PGStore) AgentOwner(ctx context.Context, agentName string) (string, error) {
	var owner string
	err := p.db.QueryRowContext(ctx,
		`SELECT network_id FROM agent_owners WHERE agent_name = $1`, agentName).Scan(&owner)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return owner, nil
}

// NetworkAgentNames implements AgentOwnership.
func (p *PGStore) NetworkAgentNames(ctx context.Context, networkID string) ([]string, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT agent_name FROM agent_owners WHERE network_id = $1 ORDER BY agent_name`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAgentNames(rows)
}

// scanAgentNames drains a single-column string result set.
func scanAgentNames(rows *sql.Rows) ([]string, error) {
	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
