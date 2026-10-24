package triggers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// dispatchGitLab fires the CI pipeline trigger with the normalized
// trigger as pipeline variables.
func (s *Service) dispatchGitLab(ctx context.Context, t *Trigger) error {
	if !s.cfg.gitlabConfigured() {
		return fmt.Errorf("%w: gitlab token/project unset", ErrNoBackend)
	}
	form := url.Values{
		"token":                   {s.cfg.GitLabToken},
		"ref":                     {s.cfg.GitLabRef},
		"variables[TARGET_REPO]":  {t.TargetRepo},
		"variables[SESSION_KEY]":  {t.SessionKey},
		"variables[ISSUE_NUMBER]": {t.IssueNumber},
		"variables[COMMENT_ID]":   {t.CommentID},
		"variables[PROMPT]":       {t.Prompt},
	}
	endpoint := fmt.Sprintf("%s/api/v4/projects/%s/trigger/pipeline", s.cfg.GitLabURL, s.cfg.GitLabProjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gitlab pipeline trigger: status %d: %s", resp.StatusCode, truncate(body, 300))
	}
	return nil
}
