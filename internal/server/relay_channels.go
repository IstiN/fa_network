package server

import (
	"context"
	"log"
)

// EnsureChannel joins (and thereby creates, when the relay is
// master-enrolled) a channel on the dap hub immediately after its
// fa_network creation. Without this, channels created between relay
// reconnects existed only in the store and enrolled agents got
// access_denied ("channel creation requires the master secret") on join.
// Failures are non-fatal: joinAllChannels covers the channel on the next
// hub (re)connect.
func (r *Relay) EnsureChannel(ctx context.Context, channelID string) {
	if err := r.hub.Join(ctx, channelID); err != nil {
		log.Printf("relay: ensure channel %s: %v (retry on reconnect)", channelID, err)
	}
}
