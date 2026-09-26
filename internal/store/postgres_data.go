package store

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// querySeqPage runs one cursor-paginated seq query (cursor = last seq).
func (p *PGStore) querySeqPage(ctx context.Context, baseQuery, ownerID, cursor string, limit int) (*sql.Rows, error) {
	if limit <= 0 {
		limit = 50
	}
	c, err := parseCursor(cursor)
	if err != nil {
		return nil, err
	}
	return p.runSeqQuery(ctx, baseQuery, ownerID, c, limit)
}

func (p *PGStore) runSeqQuery(ctx context.Context, baseQuery, ownerID string, c int64, limit int) (*sql.Rows, error) {
	if c < 0 {
		return p.db.QueryContext(ctx, baseQuery+" ORDER BY seq LIMIT $2", ownerID, limit+1)
	}
	return p.db.QueryContext(ctx, baseQuery+" AND seq > $2 ORDER BY seq LIMIT $3", ownerID, c, limit+1)
}

// parseCursor decodes a seq cursor (-1 = first page).
func parseCursor(cursor string) (int64, error) {
	if cursor == "" {
		return -1, nil
	}
	c, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil {
		return 0, notFound("cursor", cursor)
	}
	return c, nil
}

// AppendEnvelope implements Envelopes. Id-dedup rides the
// UNIQUE(channel_id, id) constraint: a conflicting insert stores nothing.
func (p *PGStore) AppendEnvelope(ctx context.Context, e *model.Envelope) (bool, error) {
	var seq int64
	err := p.db.QueryRowContext(ctx,
		`INSERT INTO envelopes (channel_id, id, sender_id, payload, sender_key, mentions, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (channel_id, id) DO NOTHING RETURNING seq`,
		e.ChannelID, e.ID, e.SenderID, e.Payload, e.SenderKey, marshalJSON(e.Mentions), e.CreatedAt.UTC(),
	).Scan(&seq)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, mapErr(err)
	}
	return true, nil
}

// Envelopes implements Envelopes (ascending seq order; cursor = last seq).
func (p *PGStore) Envelopes(ctx context.Context, channelID, before string, limit int) (*model.Page[model.Envelope], error) {
	query, args, err := envelopesDescQuery(channelID, before, limit)
	if err != nil {
		return nil, err
	}
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return scanEnvelopePageBefore(rows, effectiveLimit(limit))
}

// effectiveLimit normalizes the page size.
func effectiveLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	return limit
}

// envelopesDescQuery builds the chat-order page query: no before = latest
// page, before = the page strictly older than that seq.
func envelopesDescQuery(channelID, before string, limit int) (string, []any, error) {
	query := `SELECT id, channel_id, sender_id, payload, sender_key, mentions, created_at, seq
		FROM envelopes WHERE channel_id=$1`
	args := []any{channelID}
	if before != "" {
		c, err := parseCursor(before)
		if err != nil {
			return "", nil, err
		}
		query += ` AND seq < $2`
		args = append(args, c)
	}
	limit = effectiveLimit(limit)
	return query + ` ORDER BY seq DESC LIMIT $` + strconv.Itoa(len(args)+1),
		append(args, limit+1), nil
}

// scanEnvelopePageBefore reads a DESC page into ascending chat order;
// NextCursor is the seq of the oldest returned item (older pages follow).
func scanEnvelopePageBefore(rows *sql.Rows, limit int) (*model.Page[model.Envelope], error) {
	newest, seqs, err := collectDescRows(rows)
	if err != nil {
		return nil, err
	}
	return buildChatPage(newest, seqs, limit), nil
}

// collectDescRows drains the DESC query result (newest first).
func collectDescRows(rows *sql.Rows) ([]model.Envelope, []int64, error) {
	var newest []model.Envelope
	var seqs []int64
	for rows.Next() {
		var seq int64
		e, err := scanEnvelopeRow(rows, &seq)
		if err != nil {
			return nil, nil, err
		}
		newest = append(newest, e)
		seqs = append(seqs, seq)
	}
	return newest, seqs, mapErr(rows.Err())
}

// buildChatPage trims the lookahead row and reverses into ascending chat
// order; the cursor is the seq of the oldest returned item.
func buildChatPage(newest []model.Envelope, seqs []int64, limit int) *model.Page[model.Envelope] {
	page := &model.Page[model.Envelope]{Items: []model.Envelope{}}
	if len(newest) > limit {
		page.NextCursor = strconv.FormatInt(seqs[limit-1], 10)
		newest = newest[:limit]
	}
	for i := len(newest) - 1; i >= 0; i-- {
		page.Items = append(page.Items, newest[i])
	}
	return page
}

func scanEnvelopePage(rows *sql.Rows, limit int) (*model.Page[model.Envelope], error) {
	page := &model.Page[model.Envelope]{Items: []model.Envelope{}}
	var lastSeq int64
	for rows.Next() {
		e, err := scanEnvelopeRow(rows, &lastSeq)
		if err != nil {
			return nil, err
		}
		collectEnvelope(page, e, lastSeq, limit)
	}
	return finishPage(rows, page, limit)
}

func finishPage[T any](rows *sql.Rows, page *model.Page[T], limit int) (*model.Page[T], error) {
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	trimPage(page, limit)
	return page, nil
}

func scanEnvelopeRow(rows *sql.Rows, lastSeq *int64) (model.Envelope, error) {
	var e model.Envelope
	var mentions []byte
	if err := rows.Scan(&e.ID, &e.ChannelID, &e.SenderID, &e.Payload, &e.SenderKey, &mentions, &e.CreatedAt, lastSeq); err != nil {
		return e, mapErr(err)
	}
	_ = unmarshalJSON(mentions, &e.Mentions)
	return e, nil
}

func collectEnvelope(page *model.Page[model.Envelope], e model.Envelope, lastSeq int64, limit int) {
	if len(page.Items) == limit {
		page.NextCursor = strconv.FormatInt(lastSeq, 10)
		return
	}
	page.Items = append(page.Items, e)
}

func trimPage[T any](page *model.Page[T], limit int) {
	if page.NextCursor != "" {
		page.Items = page.Items[:limit]
	}
}

// DeleteEnvelopesBefore implements Envelopes.
func (p *PGStore) DeleteEnvelopesBefore(ctx context.Context, channelID string, cutoff time.Time) (int64, error) {
	res, err := p.db.ExecContext(ctx,
		`DELETE FROM envelopes WHERE channel_id=$1 AND created_at < $2`, channelID, cutoff.UTC())
	if err != nil {
		return 0, mapErr(err)
	}
	return res.RowsAffected()
}

// DeleteEnvelopes implements Envelopes.
func (p *PGStore) DeleteEnvelopes(ctx context.Context, channelID string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM envelopes WHERE channel_id=$1`, channelID)
	return mapErr(err)
}

// ChannelBytes implements Envelopes (abuse guard input).
func (p *PGStore) ChannelBytes(ctx context.Context, channelID string) (int64, error) {
	var total sql.NullInt64
	err := p.db.QueryRowContext(ctx,
		`SELECT SUM(octet_length(payload)) FROM envelopes WHERE channel_id=$1`, channelID).Scan(&total)
	if err != nil {
		return 0, mapErr(err)
	}
	return total.Int64, nil
}

// CreateSession implements Sessions.
func (p *PGStore) CreateSession(ctx context.Context, s *model.Session) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO sessions (token, network_id, member_id, created_at, last_seen) VALUES ($1,$2,$3,$4,$5)`,
		s.Token, s.NetworkID, s.MemberID, s.CreatedAt.UTC(), s.LastSeen.UTC())
	return mapErr(err)
}

// Session implements Sessions.
func (p *PGStore) Session(ctx context.Context, token string) (*model.Session, error) {
	var s model.Session
	err := p.db.QueryRowContext(ctx,
		`SELECT token, network_id, member_id, created_at, last_seen FROM sessions WHERE token=$1`, token,
	).Scan(&s.Token, &s.NetworkID, &s.MemberID, &s.CreatedAt, &s.LastSeen)
	if err != nil {
		return nil, mapErr(err)
	}
	return &s, nil
}

// TouchSession implements Sessions.
func (p *PGStore) TouchSession(ctx context.Context, token string, at time.Time) error {
	res, err := p.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen=$2 WHERE token=$1`, token, at.UTC())
	return mapExecErr(res, err)
}

// DeleteSession implements Sessions.
func (p *PGStore) DeleteSession(ctx context.Context, token string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM sessions WHERE token=$1`, token)
	return mapErr(err)
}

// DeleteSessionsOfMember implements Sessions.
func (p *PGStore) DeleteSessionsOfMember(ctx context.Context, networkID, memberID string) error {
	_, err := p.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE network_id=$1 AND member_id=$2`, networkID, memberID)
	return mapErr(err)
}

// SessionsOfNetwork implements Sessions.
func (p *PGStore) SessionsOfNetwork(ctx context.Context, networkID string) ([]*model.Session, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT token, network_id, member_id, created_at, last_seen FROM sessions WHERE network_id=$1`, networkID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return scanSessions(rows)
}

func scanSessions(rows *sql.Rows) ([]*model.Session, error) {
	var out []*model.Session
	for rows.Next() {
		var s model.Session
		if err := rows.Scan(&s.Token, &s.NetworkID, &s.MemberID, &s.CreatedAt, &s.LastSeen); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, &s)
	}
	return out, mapErr(rows.Err())
}

// DeleteSessionsOfNetwork implements Sessions.
func (p *PGStore) DeleteSessionsOfNetwork(ctx context.Context, networkID string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM sessions WHERE network_id=$1`, networkID)
	return mapErr(err)
}

// UpsertWakeup implements Wakeups.
func (p *PGStore) UpsertWakeup(ctx context.Context, w *model.WakeupRegistration) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO wakeups (network_id, agent_id, url, secret_hash, debounce_seconds, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (network_id, agent_id) DO UPDATE
		 SET url=$3, secret_hash=$4, debounce_seconds=$5, created_at=$6`,
		w.NetworkID, w.AgentID, w.URL, w.SecretHash, w.DebounceSeconds, w.CreatedAt.UTC())
	return mapErr(err)
}

// Wakeup implements Wakeups.
func (p *PGStore) Wakeup(ctx context.Context, networkID, agentID string) (*model.WakeupRegistration, error) {
	var w model.WakeupRegistration
	err := p.db.QueryRowContext(ctx,
		`SELECT network_id, agent_id, url, secret_hash, debounce_seconds, created_at
		 FROM wakeups WHERE network_id=$1 AND agent_id=$2`, networkID, agentID,
	).Scan(&w.NetworkID, &w.AgentID, &w.URL, &w.SecretHash, &w.DebounceSeconds, &w.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &w, nil
}

// DeleteWakeup implements Wakeups.
func (p *PGStore) DeleteWakeup(ctx context.Context, networkID, agentID string) error {
	_, err := p.db.ExecContext(ctx,
		`DELETE FROM wakeups WHERE network_id=$1 AND agent_id=$2`, networkID, agentID)
	return mapErr(err)
}

// LogDispatch implements Wakeups.
func (p *PGStore) LogDispatch(ctx context.Context, networkID string, d *model.WakeupDispatch) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO dispatches (network_id, agent_id, at, outcome, note) VALUES ($1,$2,$3,$4,$5)`,
		networkID, d.AgentID, d.At.UTC(), d.Outcome, d.Note)
	return mapErr(err)
}

// Dispatches implements Wakeups.
func (p *PGStore) Dispatches(ctx context.Context, networkID, cursor string, limit int) (*model.Page[model.WakeupDispatch], error) {
	rows, err := p.querySeqPage(ctx,
		`SELECT agent_id, at, outcome, note, seq FROM dispatches WHERE network_id=$1`,
		networkID, cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDispatchPage(rows, limit)
}

func scanDispatchPage(rows *sql.Rows, limit int) (*model.Page[model.WakeupDispatch], error) {
	page := &model.Page[model.WakeupDispatch]{Items: []model.WakeupDispatch{}}
	var lastSeq int64
	for rows.Next() {
		d, err := scanDispatchRow(rows, &lastSeq)
		if err != nil {
			return nil, err
		}
		collectDispatch(page, d, lastSeq, limit)
	}
	return finishPage(rows, page, limit)
}

func scanDispatchRow(rows *sql.Rows, lastSeq *int64) (model.WakeupDispatch, error) {
	var d model.WakeupDispatch
	if err := rows.Scan(&d.AgentID, &d.At, &d.Outcome, &d.Note, lastSeq); err != nil {
		return d, mapErr(err)
	}
	return d, nil
}

func collectDispatch(page *model.Page[model.WakeupDispatch], d model.WakeupDispatch, lastSeq int64, limit int) {
	if len(page.Items) == limit {
		page.NextCursor = strconv.FormatInt(lastSeq, 10)
		return
	}
	page.Items = append(page.Items, d)
}
