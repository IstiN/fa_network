package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"time"

	"github.com/IstiN/fa_network/internal/auth"
	"github.com/IstiN/fa_network/internal/model"
	"github.com/IstiN/fa_network/internal/store"
)

// Device enrollment (machine-connector contract §1/§2).
//
// deviceToken hygiene: minted here, returned ONCE in the enroll
// response, persisted only as sha256. Enrollment rate-limits token
// churn per user; revocation closes live sockets and rejects tickets.
const deviceEnrollRateN = 10

// deviceEnrollRatePer bounds enroll calls per user.
const deviceEnrollRatePer = time.Minute

// deviceEnrollRequest carries an optional display name for the host.
type deviceEnrollRequest struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

// enrollDevice implements POST /api/devices/enroll: ai-native JWT in,
// {deviceId, deviceToken, personalNetwork} out. The user's personal
// network is auto-provisioned on first enroll (contract §2): owner =
// the user, private, no join password (membership = owner devices and
// viewers, join-by-password semantics do not apply).
func (s *Server) enrollDevice(w http.ResponseWriter, r *http.Request) {
	principal := s.requireAuthed(w, r)
	if principal == nil {
		return
	}
	if !s.limiter.Allow("enroll|"+principal.UserID, deviceEnrollRateN, deviceEnrollRatePer) {
		writeError(w, http.StatusTooManyRequests, CodeThrottled, "too many enroll requests")
		return
	}
	var req deviceEnrollRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // empty body allowed
	if len([]rune(req.Name)) > deviceNameLimit {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "device name too long")
		return
	}
	if len([]rune(req.Platform)) > devicePlatformLimit {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "platform too long")
		return
	}
	if !validDisplay(req.Name) || !validDisplay(req.Platform) {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "device name/platform: control characters not allowed")
		return
	}

	network, err := s.personalNetworkOf(r, principal)
	if err != nil {
		writeStoreErr(w, err, "personal network")
		return
	}

	token := newToken()
	hash := sha256.Sum256([]byte(token))
	device := &model.Device{
		ID:        newToken(),
		UserID:    principal.UserID,
		Name:      deviceNameOr(req.Name),
		Platform:  req.Platform,
		TokenHash: hash[:],
		CreatedAt: s.cfg.Now(),
	}
	if err := s.st.CreateDevice(r.Context(), device); err != nil {
		writeStoreErr(w, err, "device")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"deviceId":        device.ID,
		"deviceToken":     token,
		"personalNetwork": model.NetworkWireOf(network),
		"platform":        device.Platform,
	})
}

// personalNetworkOf returns the user's personal network, provisioning
// it on first call. The display name embeds a user-keyed suffix so
// concurrent first-enrolls of different users never collide on the
// globally-unique network name.
func (s *Server) personalNetworkOf(r *http.Request, principal *auth.Principal) (*model.Network, error) {
	network, err := s.st.PersonalNetwork(r.Context(), principal.UserID)
	if !store.IsNotFound(err) {
		return network, err
	}
	network = &model.Network{
		ID:        newToken(),
		Name:      personalNetworkName(principal.UserID),
		OwnerID:   principal.UserID,
		Kind:      model.NetworkPersonal,
		CreatedAt: s.cfg.Now(),
	}
	if err := s.st.CreateNetwork(r.Context(), network); err != nil {
		return nil, err
	}
	s.seedOwnerMember(r, network, principal)
	return network, nil
}

// personalNetworkName derives a stable, collision-free name:
// "personal" + first 12 hex of sha256(userID).
func personalNetworkName(userID string) string {
	sum := sha256.Sum256([]byte(userID))
	const digits = "0123456789abcdef"
	suffix := make([]byte, 12)
	for i := range suffix {
		suffix[i] = digits[sum[i]>>4]
	}
	return "personal-" + string(suffix)
}

// deviceNameOr defaults an empty display name.
func deviceNameOr(name string) string {
	if name == "" {
		return "device"
	}
	return name
}

// revokeDevice implements DELETE /api/devices/{deviceId}: the owner's
// JWT or the device's own token. Revocation kicks live sockets, rejects
// future tickets, and removes the token from the auth index.
func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	// Auth path 1: the device's own token revokes itself.
	if device := s.deviceByToken(r.Context(), bearerToken(r)); device != nil {
		if device.ID != deviceID {
			writeError(w, http.StatusForbidden, CodeForbiddenClass, "device token revokes only itself")
			return
		}
		s.revoke(w, r, deviceID)
		return
	}
	// Auth path 2: the owner's ai-native JWT.
	principal := s.requireAuthed(w, r)
	if principal == nil {
		return
	}
	device, err := s.st.Device(r.Context(), deviceID)
	if err != nil || device.UserID != principal.UserID {
		// No existence oracle: foreign devices read as missing.
		writeError(w, http.StatusNotFound, CodeNotFound, "no such device")
		return
	}
	s.revoke(w, r, deviceID)
}

// deviceFriendlyNameLimit bounds friendly names (owner UX, contract
// §10): rune-counted so CJK names are not silently truncated mid-char.
const deviceFriendlyNameLimit = 64

// deviceNameLimit bounds the enroll-time host name (rune-counted like
// every other display cap).
const deviceNameLimit = 128

// devicePlatformLimit bounds the client-declared platform tag.
const devicePlatformLimit = 32

// Roster-patch budget per device: chunked projection pushes (~40
// sessions per chunk) stay far below it, while a runaway connector
// cannot churn the projection store.
const (
	deviceRosterPatchRateN   = 60
	deviceRosterPatchRatePer = time.Minute
)

// renameDevice implements PATCH /api/devices/{deviceId}/name: the
// account sets/clears its own device's friendly display name. Auth:
// ai-native JWT only (management route — device tokens cannot rename).
// {name: ""} clears; >64 runes → 400; foreign/revoked/unknown → 404
// (no existence oracle).
func (s *Server) renameDevice(w http.ResponseWriter, r *http.Request) {
	principal := s.requireAuthed(w, r)
	if principal == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "invalid rename body")
		return
	}
	if len([]rune(req.Name)) > deviceFriendlyNameLimit {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "friendly name too long")
		return
	}
	if !validDisplay(req.Name) {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "friendly name: control characters not allowed")
		return
	}
	deviceID := r.PathValue("deviceId")
	if err := s.st.RenameDevice(r.Context(), principal.UserID, deviceID, req.Name); err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, CodeNotFound, "no such device")
			return
		}
		writeStoreErr(w, err, "device")
		return
	}
	// Rename fans out to live siblings as a presence frame (machine
	// state unchanged — metadata-only flip), so open UIs update without
	// a roster re-GET.
	if device, err := s.st.Device(r.Context(), deviceID); err == nil {
		s.machineFanout(device, s.deviceExposure.StateOf(deviceID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"deviceId": deviceID, "friendlyName": req.Name})
}

// deviceWire is one account device as seen by its owner (GET
// /api/devices): machine name + friendly display name. Token hashes and
// raw tokens never appear.
type deviceWire struct {
	DeviceID     string     `json:"deviceId"`
	Name         string     `json:"name"`
	Platform     string     `json:"platform,omitempty"`
	FriendlyName string     `json:"friendlyName,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
}

// listAccountDevices implements GET /api/devices: the caller's own
// enrolled machines, oldest first (UI device lists + rename targets).
func (s *Server) listAccountDevices(w http.ResponseWriter, r *http.Request) {
	principal := s.requireAuthed(w, r)
	if principal == nil {
		return
	}
	devices, err := s.st.DevicesOfUser(r.Context(), principal.UserID)
	if err != nil {
		writeStoreErr(w, err, "device")
		return
	}
	out := make([]deviceWire, 0, len(devices))
	for _, d := range devices {
		out = append(out, deviceWire{
			DeviceID: d.ID, Name: d.Name, Platform: d.Platform,
			FriendlyName: d.FriendlyName,
			CreatedAt:    d.CreatedAt.UTC(), RevokedAt: d.RevokedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// revoke performs the shared revocation tail (store + socket kick).
func (s *Server) revoke(w http.ResponseWriter, r *http.Request, deviceID string) {
	if err := s.st.RevokeDevice(r.Context(), deviceID, s.cfg.Now()); err != nil {
		writeStoreErr(w, err, "device")
		return
	}
	s.deviceConns.Kick(deviceID)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": deviceID})
}

// deviceByToken is the pure device-token lookup: nil when the token is
// empty or unknown/revoked (no response written).
func (s *Server) deviceByToken(ctx context.Context, token string) *model.Device {
	if token == "" {
		return nil
	}
	hash := sha256.Sum256([]byte(token))
	device, err := s.st.DeviceByTokenHash(ctx, hash[:])
	if err != nil {
		return nil
	}
	return device
}

// resolveDevice authenticates the caller as a device: Bearer
// <deviceToken> resolved through its sha256 (revoked = 401). Returns
// nil having written the response when authentication fails.
func (s *Server) resolveDevice(w http.ResponseWriter, r *http.Request) *model.Device {
	device := s.deviceByToken(r.Context(), bearerToken(r))
	if device == nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "device token required")
		return nil
	}
	return device
}
