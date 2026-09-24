package server

import (
	"encoding/json"
	"net/http"

	"github.com/IstiN/fa_network/internal/model"
	"github.com/IstiN/fa_network/internal/store"
)

type channelCreateRequest struct {
	Name          string `json:"name"`
	Public        bool   `json:"public"`
	RetentionDays *int   `json:"retentionDays,omitempty"`
}

// listChannels implements GET /api/networks/{id}/channels (member).
func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) {
	networkID := r.PathValue("networkId")
	if s.resolveIdentity(w, r, networkID) == nil {
		return
	}
	channels, err := s.st.Channels(r.Context(), networkID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	wires := make([]model.ChannelWire, 0, len(channels))
	for _, c := range channels {
		wires = append(wires, model.ChannelWireOf(c))
	}
	writeJSON(w, http.StatusOK, wires)
}

// createChannel implements POST (authed members; public channels need
// owner/admin — AC-B5 setup).
func (s *Server) createChannel(w http.ResponseWriter, r *http.Request) {
	networkID := r.PathValue("networkId")
	idn := s.resolveIdentity(w, r, networkID)
	if idn == nil {
		return
	}
	if !canCreateChannel(idn) {
		writeError(w, http.StatusForbidden, CodeForbiddenClass, "guests cannot create channels")
		return
	}
	var req channelCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validChannelCreate(&req) {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "invalid channel request")
		return
	}
	if req.Public && !isManagerClass(idn.class()) {
		writeError(w, http.StatusForbidden, CodeForbiddenClass, "public channels need owner/admin")
		return
	}
	channel, err := s.insertChannel(r, networkID, &req)
	if err != nil {
		writeStoreErr(w, err, "channel name taken")
		return
	}
	if req.Public {
		s.addPublicChannel(r, networkID, channel.ID)
	}
	writeJSON(w, http.StatusCreated, model.ChannelWireOf(channel))
}

// canCreateChannel: every authed member may create regular channels.
func canCreateChannel(idn *identity) bool {
	return !(idn.session != nil && idn.isGuest)
}

func validChannelCreate(req *channelCreateRequest) bool {
	if req.Name == "" || len(req.Name) > 64 {
		return false
	}
	return req.RetentionDays == nil || *req.RetentionDays >= 0
}

func (s *Server) insertChannel(r *http.Request, networkID string, req *channelCreateRequest) (*model.Channel, error) {
	if _, err := s.st.ChannelByName(r.Context(), networkID, req.Name); err == nil {
		return nil, store.ErrConflict
	} else if !store.IsNotFound(err) {
		return nil, err
	}
	channel := &model.Channel{
		ID:            newToken(),
		NetworkID:     networkID,
		Name:          req.Name,
		Public:        req.Public,
		RetentionDays: req.RetentionDays,
	}
	if err := s.st.CreateChannel(r.Context(), channel); err != nil {
		return nil, err
	}
	return channel, nil
}

// addPublicChannel records a public channel on the network wire.
func (s *Server) addPublicChannel(r *http.Request, networkID, channelID string) {
	network, err := s.st.Network(r.Context(), networkID)
	if err != nil {
		return
	}
	for _, id := range network.PublicChannels {
		if id == channelID {
			return
		}
	}
	network.PublicChannels = append(network.PublicChannels, channelID)
	_ = s.st.UpdateNetwork(r.Context(), network)
}

// loadChannel resolves a channel or writes the generic 404.
func (s *Server) loadChannel(w http.ResponseWriter, r *http.Request) *model.Channel {
	channel, err := s.st.Channel(r.Context(), r.PathValue("channelId"))
	if err != nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown channel")
		return nil
	}
	return channel
}

// getChannel implements GET /api/channels/{id} (member).
func (s *Server) getChannel(w http.ResponseWriter, r *http.Request) {
	channel := s.loadChannel(w, r)
	if channel == nil {
		return
	}
	if s.resolveIdentity(w, r, channel.NetworkID) == nil {
		return
	}
	writeJSON(w, http.StatusOK, model.ChannelWireOf(channel))
}

type channelUpdateRequest struct {
	Name           *string  `json:"name"`
	Public         *bool    `json:"public"`
	ACL            []string `json:"acl"`
	RetentionDays  *int     `json:"retentionDays"`
	ClearRetention bool     `json:"clearRetention"`
}

// patchChannel implements PATCH (owner/admin, authed).
func (s *Server) patchChannel(w http.ResponseWriter, r *http.Request) {
	channel := s.loadChannel(w, r)
	if channel == nil {
		return
	}
	if s.requireManager(w, r, channel.NetworkID) == nil {
		return
	}
	var req channelUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !applyChannelUpdate(channel, &req) {
		writeError(w, http.StatusBadRequest, CodeInvalidCreds, "invalid channel update")
		return
	}
	if err := s.st.UpdateChannel(r.Context(), channel); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	writeJSON(w, http.StatusOK, model.ChannelWireOf(channel))
}

// applyChannelUpdate mutates the channel from the request (false = invalid).
func applyChannelUpdate(channel *model.Channel, req *channelUpdateRequest) bool {
	if req.Name != nil {
		if *req.Name == "" || len(*req.Name) > 64 {
			return false
		}
		channel.Name = *req.Name
	}
	if req.Public != nil {
		channel.Public = *req.Public
	}
	if req.ACL != nil {
		channel.ACL = req.ACL
	}
	return applyRetention(channel, req)
}

func applyRetention(channel *model.Channel, req *channelUpdateRequest) bool {
	if req.ClearRetention {
		channel.RetentionDays = nil
		return true
	}
	if req.RetentionDays == nil {
		return true
	}
	if *req.RetentionDays < 0 {
		return false
	}
	channel.RetentionDays = req.RetentionDays
	return true
}

// deleteChannel implements DELETE (owner/admin, authed).
func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	channel := s.loadChannel(w, r)
	if channel == nil {
		return
	}
	if s.requireManager(w, r, channel.NetworkID) == nil {
		return
	}
	if err := s.st.DeleteChannel(r.Context(), channel.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeStoreErr maps a store error to the HTTP response.
func writeStoreErr(w http.ResponseWriter, err error, conflictMsg string) {
	if store.IsConflict(err) {
		writeError(w, http.StatusConflict, CodeConflict, conflictMsg)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal", "store error")
}
