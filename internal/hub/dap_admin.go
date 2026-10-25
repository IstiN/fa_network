package hub

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// EvictAgent implements Client via the hub admin REST API
// (DELETE /api/agents/{agentId}). 404 counts as success (already gone);
// 409 (agent still online) and other statuses are reported to the caller,
// whose persistent tombstone keeps the roster exclusion regardless.
func (d *DapClient) EvictAgent(ctx context.Context, agentID string) error {
	if d.adminToken == "" {
		return ErrAdminTokenMissing
	}
	base, err := d.adminBase()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, base+"/api/agents/"+url.PathEscape(agentID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound:
		return nil
	case resp.StatusCode == http.StatusConflict:
		return fmt.Errorf("hub: agent %s still online (evict refused)", agentID)
	default:
		return fmt.Errorf("hub: evict status %d", resp.StatusCode)
	}
}

// adminBase derives the hub HTTP origin from the WS endpoint.
func (d *DapClient) adminBase() (string, error) {
	u, err := url.Parse(d.url)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	u.Path = strings.TrimSuffix(u.Path, "/ws")
	u.RawQuery = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}
