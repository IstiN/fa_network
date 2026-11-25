package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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
		writeErrorRetry(w, http.StatusTooManyRequests, CodeThrottled, "too many roster patches", 60)
		return
	}
	device, ok := s.resolvePatchDevice(w, r, deviceID)
	if !ok {
		return
	}
	body, ok := readPatchBody(w, r)
	if !ok {
		return
	}
	// Identical body for the same device = no-op (contract §8): the
	// projection already matches, so skip the merge and the sibling
	// fanout — repeated catalog pushes stay free of side effects.
	sum := sha256.Sum256(body)
	if s.rosterPatchSeen(deviceID, sum) {
		writeJSON(w, http.StatusOK, map[string]any{"patched": deviceID})
		return
	}
	patch, ok := decodePatch(w, body)
	if !ok {
		return
	}
	if msg := rosterPatchProblem(patch); msg != "" {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, msg)
		return
	}
	s.deviceExposure.ApplyPresence(deviceID, patch.Agents, patch.Sessions, s.cfg.Now())
	s.agentsFanout(device)
	writeJSON(w, http.StatusOK, map[string]any{"patched": deviceID})
}

// rosterPatchProblem returns the reason the patch is invalid (” when
// it is acceptable): size caps and display-string hygiene.
func rosterPatchProblem(patch rosterPatch) string {
	if len(patch.Agents) > 256 || len(patch.Sessions) > 256 {
		return "roster patch too large"
	}
	for _, a := range patch.Agents {
		if a.Name == "" || !validDisplay(a.Name) {
			return "agent name missing or carries control characters"
		}
	}
	for _, ses := range patch.Sessions {
		if ses.ID == "" || !validDisplay(ses.Title) || !validDisplay(ses.Path) {
			return "session id/title/path missing or carries control characters"
		}
	}
	return ""
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
			if d.RevokedAt != nil {
				continue // contract §8.2: revocation removes from rosters
			}
			machine, agents, sessions := s.deviceExposure.Roster(d.ID, networkID, s.cfg.Now())
			out = append(out, networkDeviceRosterWire{
				DeviceID: d.ID, Name: d.Name, Platform: d.Platform,
				FriendlyName: d.FriendlyName,
				UserID:       d.UserID, Presence: machine, Agents: agents, Sessions: sessions,
			})
		}
	}
	return out
}

// deviceRosterPatchMaxBytes caps the patch body (matches the global
// 1MiB request cap; the hash no-op reads the body before decoding).
const deviceRosterPatchMaxBytes = 1 << 20

// readPatchBody reads a bounded roster patch body.
func readPatchBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, deviceRosterPatchMaxBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "invalid roster patch")
		return nil, false
	}
	return body, true
}

// decodePatch parses a roster patch body.
func decodePatch(w http.ResponseWriter, body []byte) (rosterPatch, bool) {
	var patch rosterPatch
	if err := json.Unmarshal(body, &patch); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "invalid roster patch")
		return rosterPatch{}, false
	}
	return patch, true
}

// rosterPatchSeen records sum as device's latest patch body and reports
// whether it equals the previously accepted one.
func (s *Server) rosterPatchSeen(deviceID string, sum [32]byte) bool {
	key := hex.EncodeToString(sum[:])
	s.rosterHashMu.Lock()
	defer s.rosterHashMu.Unlock()
	if s.rosterHashes == nil {
		s.rosterHashes = map[string]string{}
	}
	if s.rosterHashes[deviceID] == key {
		return true
	}
	s.rosterHashes[deviceID] = key
	return false
}

// resolvePatchDevice authenticates a roster patch: the device's own
// device token (patches only itself) or the owner's JWT (own devices).
func (s *Server) resolvePatchDevice(w http.ResponseWriter, r *http.Request, deviceID string) (*model.Device, bool) {
	if device := s.deviceByToken(r.Context(), bearerToken(r)); device != nil {
		if device.ID != deviceID {
			writeError(w, http.StatusForbidden, CodeForbiddenClass, "device token patches only itself")
			return nil, false
		}
		return device, true
	}
	principal := s.requireAuthed(w, r)
	if principal == nil {
		return nil, false
	}
	device, err := s.st.Device(r.Context(), deviceID)
	if err != nil || device.UserID != principal.UserID {
		writeError(w, http.StatusNotFound, CodeNotFound, "no such device")
		return nil, false
	}
	return device, true
}
