package server

import (
	"context"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// Device-WS machine roster + presence fanout (machine-connector
// contract §4/§5): the roster snapshot carries the machines of the
// device's networks (REST parity with GET /api/networks/{id}/devices),
// and every machine-state flip is pushed incrementally to the live
// sibling sockets sharing a network with the flipped device.

// snapshotDeviceMachines returns the machine entries for one network —
// the same read model as the REST machine roster.
func (s *Server) snapshotDeviceMachines(ctx context.Context, networkID string) []networkDeviceRosterWire {
	members, err := s.st.Members(ctx, networkID)
	if err != nil {
		return nil
	}
	return s.machineRosterOf(ctx, networkID, members)
}

// setMachineAndFanout records a server-inferred machine state and
// pushes the flip to live sibling devices sharing a network with the
// device (the flipping device itself knows its own state first).
func (s *Server) setMachineAndFanout(device *model.Device, machine string) {
	s.deviceExposure.SetMachine(device.ID, machine, s.cfg.Now())
	s.machineFanout(device, machine)
}

// eachSharedNetworkSocket runs fn for every live sibling socket per
// shared account network. Targeting is user-based: the shared-network
// check walks both users' account networks (small N). The originator
// device is skipped — it knows its own state first.
func (s *Server) eachSharedNetworkSocket(device *model.Device, fn func(dc *deviceConn, networkID string)) {
	if s.deviceConns == nil {
		return
	}
	ctx := context.Background()
	mine, err := s.st.AccountNetworks(ctx, device.UserID)
	if err != nil {
		return
	}
	for _, dc := range s.deviceConns.All() {
		if dc.device.ID == device.ID {
			continue
		}
		theirs, err := s.st.AccountNetworks(ctx, dc.device.UserID)
		if err != nil {
			continue
		}
		for _, an := range mine {
			if accountNetworkIDs(theirs).contains(an.Network.ID) {
				fn(dc, an.Network.ID)
			}
		}
	}
}

// machineFanout sends one presence frame per live sibling socket per
// shared network (the flip cadence is connect/disconnect, not
// per-message; the frame carries devices[].presence only).
func (s *Server) machineFanout(device *model.Device, machine string) {
	entry := networkDeviceRosterWire{
		DeviceID: device.ID, Name: device.Name, FriendlyName: device.FriendlyName,
		UserID: device.UserID, Presence: machine,
	}
	s.eachSharedNetworkSocket(device, func(dc *deviceConn, networkID string) {
		s.deviceSend(dc, deviceFrame{
			V: 1, Kind: kindPresence, MsgID: newToken(),
			Network: networkID, TS: s.cfg.Now().UTC().Format(time.RFC3339),
			Devices: []networkDeviceRosterWire{entry},
		})
	})
}

// agentsFanout pushes the catalog delta after a connector presence
// update (WS kindPresence or REST roster patch): one presence frame
// per live sibling socket per shared network, carrying the device's
// exposed agents and per-network sessions — the same read model as
// GET /api/networks/{id}/devices (contract §8: additive devices[]
// keys on the presence frame; older clients ignore them). Idempotent
// for clients; the cadence is the connector's presence cadence.
func (s *Server) agentsFanout(device *model.Device) {
	now := s.cfg.Now()
	s.eachSharedNetworkSocket(device, func(dc *deviceConn, networkID string) {
		machine, agents, sessions := s.deviceExposure.Roster(device.ID, networkID, now)
		s.deviceSend(dc, deviceFrame{
			V: 1, Kind: kindPresence, MsgID: newToken(),
			Network: networkID, TS: now.UTC().Format(time.RFC3339),
			Devices: []networkDeviceRosterWire{{
				DeviceID: device.ID, Name: device.Name, Platform: device.Platform,
				FriendlyName: device.FriendlyName, UserID: device.UserID,
				Presence: machine, Agents: agents, Sessions: sessions,
			}},
		})
	})
}

// sweeperOfflineFanout pushes offline flips produced by the degraded →
// offline sweeper (device ids only — the device row is re-resolved).
func (s *Server) sweeperOfflineFanout(flipIDs []string) {
	for _, id := range flipIDs {
		device, err := s.st.Device(context.Background(), id)
		if err != nil {
			continue
		}
		s.machineFanout(device, MachineOffline)
	}
}

// accountNetworkIDs is a tiny set over AccountNetwork rows.
type accountNetworkIDs []*model.AccountNetwork

func (ids accountNetworkIDs) contains(id string) bool {
	for _, an := range ids {
		if an.Network.ID == id {
			return true
		}
	}
	return false
}
