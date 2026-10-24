package triggers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// dispatchBitrise starts a Bitrise build of the fa-universal workflow
// with the normalized trigger exposed as environment variables.
func (s *Service) dispatchBitrise(ctx context.Context, t *Trigger) error {
	if !s.cfg.bitriseConfigured() {
		return fmt.Errorf("%w: bitrise token/app slug unset", ErrNoBackend)
	}
	envs := []map[string]string{}
	for key, value := range map[string]string{
		"TARGET_REPO":  t.TargetRepo,
		"SESSION_KEY":  t.SessionKey,
		"ISSUE_NUMBER": t.IssueNumber,
		"COMMENT_ID":   t.CommentID,
		"PROMPT":       t.Prompt,
	} {
		envs = append(envs, map[string]string{"mapped_to": key, "value": value})
	}
	payload := map[string]any{
		"hook_info": map[string]string{
			"type":                "bitrise",
			"build_trigger_token": s.cfg.BitriseToken,
		},
		"build_params": map[string]any{
			"workflow_id":  s.cfg.BitriseWorkflowID,
			"environments": envs,
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/apps/%s/builds", s.cfg.BitriseURL, s.cfg.BitriseAppSlug)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bitrise build trigger: status %d: %s", resp.StatusCode, truncate(body, 300))
	}
	return nil
}
