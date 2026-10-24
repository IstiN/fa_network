package triggers

import (
	"encoding/json"
	"errors"
)

// genericPayload is the authenticated direct-trigger JSON contract of
// POST /api/webhooks/generic (issue #3).
type genericPayload struct {
	Provider    string         `json:"provider"`
	TargetRepo  string         `json:"targetRepo"`
	SessionKey  string         `json:"sessionKey"`
	IssueNumber string         `json:"issueNumber"`
	CommentID   string         `json:"commentId"`
	Author      string         `json:"author"`
	Prompt      string         `json:"prompt"`
	Runner      string         `json:"runner"`
	Metadata    map[string]any `json:"metadata"`
}

// parseGeneric accepts an explicit trigger: no mention filter (the
// caller already authenticated with a shared secret). A session key or
// repo+issue coordinates are required.
func parseGeneric(body []byte) (*Event, error) {
	var p genericPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	provider := p.Provider
	if provider == "" {
		provider = "custom"
	}
	key := p.SessionKey
	if key != "" {
		key = NormalizeSessionKey(key)
	} else {
		if p.TargetRepo == "" || p.IssueNumber == "" {
			return nil, errors.New("generic trigger requires sessionKey or targetRepo+issueNumber")
		}
		key = SessionKey(ProviderKeyPrefix(provider), p.TargetRepo, p.IssueNumber)
	}
	return &Event{Kind: KindTrigger, Trigger: &Trigger{
		Provider:    provider,
		TargetRepo:  p.TargetRepo,
		SessionKey:  key,
		IssueNumber: p.IssueNumber,
		CommentID:   p.CommentID,
		Author:      p.Author,
		Prompt:      p.Prompt,
		Runner:      p.Runner,
		Metadata:    p.Metadata,
	}}, nil
}
