package server

import (
	"encoding/json"
	"net/http"
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
	DeviceID string              `json:"deviceId"`
	Name     string              `json:"name"`
	Presence string              `json:"presence"`
	UserID   string              `json:"userId"`
	Agents   []deviceAgentWire   `json:"agents,omitempty"`
	Sessions []deviceSessionWire `json:"sessions,omitempty"`
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
	out := make([]networkDeviceRosterWire, 0, 4)
	for _, m := range members {
		devices, err := s.st.DevicesOfUser(r.Context(), m.ID)
		if err != nil {
			continue
		}
		for _, d := range devices {
			machine, agents, sessions := s.deviceExposure.Roster(d.ID, networkID)
			out = append(out, networkDeviceRosterWire{
				DeviceID: d.ID, Name: d.Name, UserID: d.UserID,
				Presence: machine, Agents: agents, Sessions: sessions,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}
