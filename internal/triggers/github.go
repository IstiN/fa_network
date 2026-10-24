package triggers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// githubAPI performs one authenticated GitHub REST call. out may be nil
// (fire-and-read-status) or a decode target.
func githubAPI(ctx context.Context, client *http.Client, method, url, token string, payload, out any) error {
	var reader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github %s %s: status %d: %s", method, url, resp.StatusCode, truncate(body, 300))
	}
	if out != nil && len(body) > 0 {
		return json.Unmarshal(body, out)
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

// githubToken returns a credential for the repo: PAT when configured,
// otherwise a GitHub App installation token.
func (s *Service) githubToken(ctx context.Context, repo string) (string, error) {
	if s.cfg.GitHubToken != "" {
		return s.cfg.GitHubToken, nil
	}
	if s.app == nil {
		return "", ErrNoBackend
	}
	return s.app.token(ctx, s.http, s.cfg.GitHubAPIURL, repo)
}

// dispatchGitHub fires workflow_dispatch on fa-universal.yml (or the
// configured workflow) with the normalized trigger inputs.
func (s *Service) dispatchGitHub(ctx context.Context, t *Trigger) error {
	repo := s.cfg.GitHubRepo
	if s.cfg.GitHubUseTargetRepo || repo == "" {
		repo = t.TargetRepo
	}
	if repo == "" {
		return fmt.Errorf("%w: github runner repository unset", ErrNoBackend)
	}
	token, err := s.githubToken(ctx, repo)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"ref": s.cfg.GitHubRef,
		"inputs": map[string]string{
			"target_repo":  t.TargetRepo,
			"session_key":  t.SessionKey,
			"issue_number": t.IssueNumber,
			"comment_id":   t.CommentID,
			"prompt":       t.Prompt,
			"provider":     t.Provider,
		},
	}
	url := fmt.Sprintf("%s/repos/%s/actions/workflows/%s/dispatches", s.cfg.GitHubAPIURL, repo, s.cfg.GitHubWorkflow)
	return githubAPI(ctx, s.http, http.MethodPost, url, token, payload, nil)
}

// ReactEyes adds the 👀 reaction to the originating comment (issues or
// pulls reaction API depending on Reaction.Kind). Best-effort by caller.
func (s *Service) ReactEyes(ctx context.Context, reaction Reaction) error {
	if reaction.Repo == "" || reaction.CommentID == "" {
		return errors.New("reaction target incomplete")
	}
	token, err := s.githubToken(ctx, reaction.Repo)
	if err != nil {
		return err
	}
	kind := reaction.Kind
	if kind == "" {
		kind = "issues"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/comments/%s/reactions", s.cfg.GitHubAPIURL, reaction.Repo, kind, reaction.CommentID)
	return githubAPI(ctx, s.http, http.MethodPost, url, token, map[string]string{"content": "eyes"}, nil)
}
