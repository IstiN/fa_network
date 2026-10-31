package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/IstiN/fa_network/internal/model"
)

// EnvelopeByID implements Envelopes (ErrNotFound for unknown ids —
// read cursors reject foreign envelope ids with a 4xx).
func (p *PGStore) EnvelopeByID(ctx context.Context, channelID, id string) (*model.Envelope, error) {
	var e model.Envelope
	var mentions []byte
	err := p.db.QueryRowContext(ctx, `
		SELECT id, channel_id, sender_id, payload, sender_key, sender_name, mentions, created_at, seq
		FROM envelopes WHERE channel_id=$1 AND id=$2`,
		channelID, id).Scan(
		&e.ID, &e.ChannelID, &e.SenderID, &e.Payload, &e.SenderKey, &e.SenderName,
		&mentions, &e.CreatedAt, &e.Seq)
	if err != nil {
		return nil, mapErr(err)
	}
	_ = unmarshalJSON(mentions, &e.Mentions)
	return &e, nil
}

// ReadCursor implements ReadState.
func (p *PGStore) ReadCursor(ctx context.Context, userID, channelID string) (int64, error) {
	var seq int64
	err := p.db.QueryRowContext(ctx,
		`SELECT seq FROM channel_reads WHERE user_id=$1 AND channel_id=$2`,
		userID, channelID).Scan(&seq)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	return seq, mapErr(err)
}

// ChannelMaxSeq implements ReadState.
func (p *PGStore) ChannelMaxSeq(ctx context.Context, channelID string) (int64, error) {
	var seq int64
	err := p.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), 0) FROM envelopes WHERE channel_id=$1`,
		channelID).Scan(&seq)
	return seq, mapErr(err)
}

// channelMaxSeqExpr is the clamp subquery shared by the read upserts:
// a client can never push its cursor beyond the channel's newest seq.
const channelMaxSeqExpr = `(SELECT COALESCE(MAX(seq), 0) FROM envelopes WHERE channel_id = $2)`

// MarkRead implements ReadState. The upsert is monotonic — GREATEST
// never moves the position backwards — and the incoming seq is clamped
// to the channel's current max.
func (p *PGStore) MarkRead(ctx context.Context, userID, channelID string, seq int64) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO channel_reads (user_id, channel_id, seq)
		VALUES ($1, $2, LEAST($3, `+channelMaxSeqExpr+`))
		ON CONFLICT (user_id, channel_id) DO UPDATE
		  SET seq = GREATEST(channel_reads.seq, EXCLUDED.seq), updated_at = now()`,
		userID, channelID, seq)
	return mapErr(err)
}

// BaselineRead implements ReadState: INSERT … ON CONFLICT DO NOTHING —
// the first aggregate fetch anchors unread at the current max (no
// historical unread flood for a new device); an existing row wins and
// is returned unchanged.
func (p *PGStore) BaselineRead(ctx context.Context, userID, channelID string) (int64, error) {
	var seq int64
	err := p.db.QueryRowContext(ctx, `
		INSERT INTO channel_reads (user_id, channel_id, seq)
		VALUES ($1, $2, `+channelMaxSeqExpr+`)
		ON CONFLICT (user_id, channel_id) DO NOTHING
		RETURNING seq`,
		userID, channelID).Scan(&seq)
	if errors.Is(err, ErrNotFound) {
		// Conflict path (a row existed): read it back.
		return p.ReadCursor(ctx, userID, channelID)
	}
	return seq, mapErr(err)
}

// inboxEntryQuery joins the caller's membership networks to their
// channels, the newest envelope (LATERAL), and the per-user read
// cursor; unread counts envelopes strictly beyond the cursor. LATERAL
// columns are COALESCEd (empty channel → ''/0) so the scan needs no
// pointer juggling. Payload columns ride along opaquely — nothing is
// decoded.
const inboxEntryQuery = `
	SELECT c.network_id, c.id, c.name, c.public, c.acl, c.retention_days,
	       COALESCE(e.id, ''), COALESCE(e.sender_id, ''), COALESCE(e.payload, ''),
	       COALESCE(e.sender_key, ''), COALESCE(e.sender_name, ''),
	       COALESCE(e.mentions, '[]'::jsonb), COALESCE(e.created_at, 'epoch'::timestamptz),
	       COALESCE(e.seq, 0),
	       COALESCE(r.seq, 0),
	       (SELECT COUNT(*) FROM envelopes n
	         WHERE n.channel_id = c.id AND n.seq > COALESCE(r.seq, 0)) AS unread
	FROM members m
	JOIN channels c ON c.network_id = m.network_id
	LEFT JOIN channel_reads r ON r.channel_id = c.id AND r.user_id = m.id
	LEFT JOIN LATERAL (
		SELECT id, sender_id, payload, sender_key, sender_name,
		       mentions, created_at, seq
		FROM envelopes WHERE channel_id = c.id
		ORDER BY seq DESC LIMIT 1
	) e ON true
	WHERE m.id = $1
	LIMIT $2`

// baselineAllReads anchors the caller's read cursor at each channel's
// current max when no row exists yet (unread-0 history on a first
// aggregate fetch — no historical unread flood for a new device).
const baselineAllReads = `
	INSERT INTO channel_reads (user_id, channel_id, seq)
	SELECT $1, c.id, COALESCE((SELECT MAX(seq) FROM envelopes e WHERE e.channel_id = c.id), 0)
	FROM members m
	JOIN channels c ON c.network_id = m.network_id
	WHERE m.id = $1
	ON CONFLICT (user_id, channel_id) DO NOTHING`

// InboxEntries implements Inbox (baselines first, then the join — the
// returned unread counts are final).
func (p *PGStore) InboxEntries(ctx context.Context, userID string) ([]*model.InboxEntry, error) {
	rows, err := p.queryInboxRows(ctx, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return scanInboxRows(rows)
}

// scanInboxRows decodes the aggregate join rows.
func scanInboxRows(rows *sql.Rows) ([]*model.InboxEntry, error) {
	out := []*model.InboxEntry{}
	for rows.Next() {
		entry, err := scanInboxRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, mapErr(rows.Err())
}

// queryInboxRows materializes the first-touch baselines, then runs the
// aggregate join.
func (p *PGStore) queryInboxRows(ctx context.Context, userID string) (*sql.Rows, error) {
	if _, err := p.db.ExecContext(ctx, baselineAllReads, userID); err != nil {
		return nil, err
	}
	return p.db.QueryContext(ctx, inboxEntryQuery, userID, inboxMaxEntries)
}

// scanInboxRow decodes one aggregate row; an empty envelope id means
// the channel has no messages yet.
func scanInboxRow(rows *sql.Rows) (*model.InboxEntry, error) {
	ch := &model.Channel{}
	entry := &model.InboxEntry{Channel: ch}
	var chACL, mentions []byte
	env := model.Envelope{ChannelID: ch.ID}
	var cursorSeq int64
	if err := rows.Scan(
		&ch.NetworkID, &ch.ID, &ch.Name, &ch.Public, &chACL, &ch.RetentionDays,
		&env.ID, &env.SenderID, &env.Payload, &env.SenderKey, &env.SenderName,
		&mentions, &env.CreatedAt, &env.Seq,
		&cursorSeq, &entry.UnreadCount,
	); err != nil {
		return nil, err
	}
	_ = unmarshalJSON(chACL, &ch.ACL)
	if env.ID != "" {
		_ = unmarshalJSON(mentions, &env.Mentions)
		entry.LastEnvelope = &env
	}
	return entry, nil
}
