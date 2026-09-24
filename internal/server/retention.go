package server

import (
	"context"
	"log"
	"time"
)

// retentionLoop sweeps on the configured interval (AC-B12):
//   - envelopes older than their channel's retentionDays are deleted,
//   - networks with no member-session activity for the inactivity window
//     are wiped entirely (envelopes + metadata; open channels too).
func (s *Server) retentionLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.RetentionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepOnce(ctx)
		}
	}
}

// sweepOnce performs one retention pass (exported for tests via Server).
func (s *Server) sweepOnce(ctx context.Context) {
	if err := s.sweepEnvelopeRetention(ctx); err != nil {
		log.Printf("retention: envelope sweep: %v", err)
	}
	if err := s.sweepInactiveNetworks(ctx); err != nil {
		log.Printf("retention: network sweep: %v", err)
	}
}

// sweepEnvelopeRetention deletes expired envelopes per channel (AC-B12).
func (s *Server) sweepEnvelopeRetention(ctx context.Context) error {
	channels, err := s.st.ChannelsWithRetention(ctx)
	if err != nil {
		return err
	}
	now := s.cfg.Now()
	for _, c := range channels {
		if c.RetentionDays == nil {
			continue
		}
		if *c.RetentionDays == 0 {
			// retentionDays: 0 keeps nothing beyond live relay.
			if err := s.st.DeleteEnvelopes(ctx, c.ID); err != nil {
				return err
			}
			continue
		}
		cutoff := now.Add(-time.Duration(*c.RetentionDays) * 24 * time.Hour)
		if _, err := s.st.DeleteEnvelopesBefore(ctx, c.ID, cutoff); err != nil {
			return err
		}
	}
	return nil
}

// sweepInactiveNetworks wipes networks idle past the inactivity window.
func (s *Server) sweepInactiveNetworks(ctx context.Context) error {
	if s.cfg.RetentionInactivityDays <= 0 {
		return nil
	}
	cutoff := s.cfg.Now().Add(-time.Duration(s.cfg.RetentionInactivityDays) * 24 * time.Hour)
	ids, err := s.st.InactiveNetworks(ctx, cutoff)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.st.DeleteNetworkData(ctx, id); err != nil {
			return err
		}
		log.Printf("retention: wiped inactive network %s", id)
	}
	return nil
}
