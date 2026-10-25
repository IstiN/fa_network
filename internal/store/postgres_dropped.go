package store

import (
	"context"
	"database/sql"
	"time"
)

// DropHubAgent implements DroppedHubAgents (idempotent tombstone).
func (p *PGStore) DropHubAgent(ctx context.Context, agentID string) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO dropped_hub_agents (agent_id, created_at) VALUES ($1, $2)
		 ON CONFLICT (agent_id) DO NOTHING`, agentID, time.Now().UTC())
	return err
}

// DroppedHubAgentIDs implements DroppedHubAgents.
func (p *PGStore) DroppedHubAgentIDs(ctx context.Context) ([]string, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT agent_id FROM dropped_hub_agents ORDER BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAgentIDs(rows)
}

// scanAgentIDs collects one text column (kept small for the CRAP gate:
// postgres paths have no offline coverage).
func scanAgentIDs(rows *sql.Rows) ([]string, error) {
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
