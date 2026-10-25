package triggers

import (
	"context"
	"strings"
	"testing"
)

// Outbound repo paths must never carry traversal/extra segments/query
// smuggling, even when a generic caller supplies targetRepo.
func TestGitHubRepoSlugGuard(t *testing.T) {
	bad := []string{
		"evil/../x", "owner/repo/extra", "owner//repo", "owner/repo?x=1",
		"owner\\repo", "-bad/repo", "owner/", "/repo", "owner/re po",
		"owner/repo#frag", "owner/%2e%2e",
	}
	s := NewService(Config{GitHubToken: "x", GitHubUseTargetRepo: true}, nil)
	for _, repo := range bad {
		if validRepoSlug(repo) {
			t.Errorf("slug accepted: %q", repo)
			continue
		}
		err := s.dispatchGitHub(context.Background(), &Trigger{Provider: "github", TargetRepo: repo, SessionKey: "gh-o-r-1"})
		if err == nil || !strings.Contains(err.Error(), "invalid github repo slug") {
			t.Errorf("dispatch(%q) err = %v, want slug rejection", repo, err)
		}
	}
	good := []string{"IstiN/fa_network", "dmtools-agentic-workflows/x.y", "a/b", "org-name/repo_name.js"}
	for _, repo := range good {
		if !validRepoSlug(repo) {
			t.Errorf("valid slug rejected: %q", repo)
		}
	}
	// The reaction path shares the same guard via githubToken.
	if _, err := s.githubToken(context.Background(), "bad/../repo"); err == nil {
		t.Error("githubToken accepted a traversal repo")
	}
}
