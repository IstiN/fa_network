package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/IstiN/fa_network/internal/model"
)

// Roster patch + network device roster (machine-connector contract §9).
//
// Exposure flags live locally on the connector; these routes let the
// connector (deviceToken) and the owner (JWT) push/patch the server-side
// projection that the roster read model serves. Exposure per device:
// agents (one flag, dmPub) apply across networks; sessions carry their
// own per-network exposure lists (personal default ON, shared OFF).

// rosterPatch is the request body of PATCH /api/devices/{id}/roster.
type rosterPatch struct {
	Agents   []deviceAgentWire   `json:"agents"`
	Sessions []deviceSessionWire `json:"sessions"`
}

// patchDeviceRoster implements PATCH /api/devices/{deviceId}/roster:
// exposure flags + dmPub per agent + exposed session leases. Auth: the
// device's own deviceToken or the owner's JWT.
func (s *Server) patchDeviceRoster(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	// Chunked projection pushes (clients split large session lists) are
	// bounded per device, not per user: a compromised token cannot
	// churn the projection store faster than this.
	if !s.limiter.Allow("roster-patch|"+deviceID, deviceRosterPatchRateN, deviceRosterPatchRatePer) {
		writeError(w, http.StatusTooManyRequests, CodeThrottled, "too many roster patches")
		return
	}
	if device := s.deviceByToken(r.Context(), bearerToken(r)); device != nil {
		if device.ID != deviceID {
			writeError(w, http.StatusForbidden, CodeForbiddenClass, "device token patches only itself")
			return
		}
	} else if principal := s.requireAuthed(w, r); principal != nil {
		device, err := s.st.Device(r.Context(), deviceID)
		if err != nil || device.UserID != principal.UserID {
			writeError(w, http.StatusNotFound, CodeNotFound, "no such device")
			return
		}
	} else {
		return
	}
	var patch rosterPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "invalid roster patch")
		return
	}
	if len(patch.Agents) > 256 || len(patch.Sessions) > 256 {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "roster patch too large")
		return
	}
	s.deviceExposure.ApplyPresence(deviceID, patch.Agents, patch.Sessions, s.cfg.Now())
	writeJSON(w, http.StatusOK, map[string]any{"patched": deviceID})
}

// networkDeviceRosterWire is one device's exposed-only roster entry.
type networkDeviceRosterWire struct {
	DeviceID string `json:"deviceId"`
	Name     string `json:"name"`
	// Platform and FriendlyName are display metadata ('' omitted —
	// additive, older clients ignore unknown fields).
	Platform     string              `json:"platform,omitempty"`
	FriendlyName string              `json:"friendlyName,omitempty"`
	Presence     string              `json:"presence"`
	UserID       string              `json:"userId"`
	Agents       []deviceAgentWire   `json:"agents,omitempty"`
	Sessions     []deviceSessionWire `json:"sessions,omitempty"`
}

// listNetworkDevices implements GET /api/networks/{id}/devices: the
// machines of the network's members with their exposed agents (dmPub
// included — public directory material) and sessions exposed to THIS
// network. Read for every member (showcase rule); exposure filtering is
// the deny-by-default boundary (AC3: shared networks publish zero
// sessions unless the owner opts in per network).
func (s *Server) listNetworkDevices(w http.ResponseWriter, r *http.Request) {
	networkID := r.PathValue("networkId")
	if idn := s.resolveIdentity(w, r, networkID); idn == nil {
		return
	}
	members, err := s.st.Members(r.Context(), networkID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": s.machineRosterOf(r.Context(), networkID, members)})
}

// machineRosterOf builds the network's machine roster (the read model
// behind both GET /api/networks/{id}/devices and the device-WS roster
// snapshot): every member user's enrolled devices with server-inferred
// machine presence and their exposed agents / sessions exposed to THIS
// network.
func (s *Server) machineRosterOf(ctx context.Context, networkID string, members []*model.Member) []networkDeviceRosterWire {
	out := make([]networkDeviceRosterWire, 0, 4)
	for _, m := range members {
		devices, err := s.st.DevicesOfUser(ctx, m.ID)
		if err != nil {
			continue
		}
		for _, d := range devices {
			machine, agents, sessions := s.deviceExposure.Roster(d.ID, networkID)
			out = append(out, networkDeviceRosterWire{
				DeviceID: d.ID, Name: d.Name, Platform: d.Platform,
				FriendlyName: d.FriendlyName,
				UserID:       d.UserID, Presence: machine, Agents: agents, Sessions: sessions,
			})
		}
	}
	return out
}
