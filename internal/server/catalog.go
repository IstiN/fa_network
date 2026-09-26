package server

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/IstiN/fa_network/internal/model"
)

// Catalog read limits: anonymous endpoint, so it is rate-limited and
// hard-capped per page.
const (
	catalogMaxPerPage  = 200
	catalogDefaultPage = 50
	catalogRateMax     = 30
	catalogRateWindow  = time.Minute
)

// listPublicNetworks implements GET /api/networks/public — the opt-in
// discovery catalog. Anonymous, metadata only: no passwords, no owner
// identity, no membership material. Listing a network never relaxes its
// join password (E1 throttling story stays intact).
func (s *Server) listPublicNetworks(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	if !s.limiter.Allow("catalog:"+ip, catalogRateMax, catalogRateWindow) {
		writeErrorRetry(w, http.StatusTooManyRequests, CodeThrottled, "slow down", 60)
		return
	}
	limit := queryInt(r, "limit", catalogDefaultPage)
	if limit < 1 || limit > catalogMaxPerPage {
		limit = catalogDefaultPage
	}
	after, afterID := decodeCatalogCursor(r.URL.Query().Get("cursor"))
	networks, err := s.st.PublicNetworks(r.Context(), after, afterID, limit+1)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	page := model.Page[model.PublicNetworkWire]{Items: []model.PublicNetworkWire{}}
	var last *model.Network
	for i, n := range networks {
		if i >= limit {
			// Keyset cursor points at the last returned item so the
			// next page starts strictly after it.
			page.NextCursor = encodeCatalogCursor(last)
			break
		}
		page.Items = append(page.Items, s.catalogWire(r, n))
		last = n
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": page.Items, "nextCursor": page.NextCursor})
}

// listShowcase implements GET /api/networks/{networkId}/showcase — the
// anonymous browsing entry of a public network: its showcase channels.
// Non-public (or unknown) networks return the generic 404 — no oracle (E1).
func (s *Server) listShowcase(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	if !s.limiter.Allow("showcase:"+ip, catalogRateMax, catalogRateWindow) {
		writeErrorRetry(w, http.StatusTooManyRequests, CodeThrottled, "slow down", 60)
		return
	}
	network, err := s.st.Network(r.Context(), r.PathValue("networkId"))
	if err != nil || !network.Public {
		writeError(w, http.StatusNotFound, CodeNotFound, "unknown network")
		return
	}
	channels, err := s.st.Channels(r.Context(), network.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "store error")
		return
	}
	items := make([]map[string]string, 0, len(channels))
	for _, c := range channels {
		if c.Public {
			items = append(items, map[string]string{"id": c.ID, "name": c.Name})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       network.ID,
		"name":     network.Name,
		"channels": items,
	})
}

// catalogWire projects one network into its catalog entry. The member
// count is best-effort: a store hiccup on the stat yields 0, never a 500.
func (s *Server) catalogWire(r *http.Request, n *model.Network) model.PublicNetworkWire {
	count, err := s.st.MemberCount(r.Context(), n.ID)
	if err != nil {
		count = 0
	}
	return model.PublicNetworkWire{
		ID:             n.ID,
		Name:           n.Name,
		PublicChannels: len(n.PublicChannels),
		MemberCount:    count,
	}
}

// encodeCatalogCursor mints an opaque keyset cursor for the catalog page.
func encodeCatalogCursor(n *model.Network) string {
	raw := n.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + n.ID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCatalogCursor parses a keyset cursor; malformed cursors degrade to
// the first page instead of erroring (catalog is public-by-design data).
func decodeCatalogCursor(cursor string) (time.Time, string) {
	if cursor == "" {
		return time.Time{}, ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, ""
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, ""
	}
	after, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, ""
	}
	return after, parts[1]
}
