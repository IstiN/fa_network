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

// machineFanout sends one presence frame per live sibling socket per
// shared network. Targeting is user-based: the shared-network check
// walks both users' account networks (small N; the flip cadence is
// connect/disconnect, not per-message).
func (s *Server) machineFanout(device *model.Device, machine string) {
	if s.deviceConns == nil {
		return
	}
	ctx := context.Background()
	mine, err := s.st.AccountNetworks(ctx, device.UserID)
	if err != nil || len(mine) == 0 {
		return
	}
	entry := networkDeviceRosterWire{
		DeviceID: device.ID, Name: device.Name, FriendlyName: device.FriendlyName,
		UserID: device.UserID, Presence: machine,
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
			if !accountNetworkIDs(theirs).contains(an.Network.ID) {
				continue
			}
			s.deviceSend(dc, deviceFrame{
				V: 1, Kind: kindPresence, MsgID: newToken(),
				Network: an.Network.ID, TS: s.cfg.Now().UTC().Format(time.RFC3339),
				Devices: []networkDeviceRosterWire{entry},
			})
		}
	}
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
