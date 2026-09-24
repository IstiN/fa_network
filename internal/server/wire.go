package server

import (
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// WS event payload shapes (docs/openapi.yaml /ws event catalog). Envelopes
// and members reuse the model wire projections — one source of truth.

type rosterSnapshotWire struct {
	Members []model.MemberWire `json:"members"`
}

type presenceChangedWire struct {
	MemberID string `json:"memberId"`
	Presence string `json:"presence"`
}

type networkOfflineWire struct {
	Reason string `json:"reason"`
}

type networkDrainWire struct {
	Count int `json:"count"`
}

type wakeupDispatchedWire struct {
	AgentID string    `json:"agentId"`
	At      time.Time `json:"at"`
}

// wsFrame is one server→client event frame: {type, payload}.
type wsFrame struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}
