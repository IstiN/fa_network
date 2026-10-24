package triggers

import (
	"testing"
	"time"
)

func TestFromEnvDefaults(t *testing.T) {
	for _, key := range []string{
		"FA_WEBHOOK_GITHUB_SECRET", "FA_WEBHOOK_GITLAB_SECRET", "FA_WEBHOOK_BITBUCKET_SECRET",
		"FA_WEBHOOK_GENERIC_SECRET", "FA_NETWORK_WEBHOOK_SECRET", "FA_TRIGGER_MENTION",
		"FA_TRIGGER_BOT_LOGINS", "FA_TRIGGER_ALLOW_BOTS", "FA_TRIGGER_ALWAYS_DISPATCH_FALLBACK",
		"FA_TRIGGER_GRACE_PERIOD", "FA_TRIGGER_GITHUB_REPO", "FA_TRIGGER_GITHUB_WORKFLOW",
		"FA_TRIGGER_GITHUB_REF", "FA_TRIGGER_GITHUB_USE_TARGET_REPO", "FA_TRIGGER_GITHUB_TOKEN",
		"FA_GITHUB_API_URL", "FA_GITHUB_APP_ID", "FA_GITHUB_APP_PRIVATE_KEY",
		"FA_GITHUB_APP_INSTALLATION_ID", "FA_TRIGGER_GITLAB_URL", "FA_TRIGGER_GITLAB_PROJECT_ID",
		"FA_TRIGGER_GITLAB_REF", "FA_TRIGGER_GITLAB_TOKEN", "FA_TRIGGER_BITRISE_URL",
		"FA_TRIGGER_BITRISE_APP_SLUG", "FA_TRIGGER_BITRISE_TOKEN", "FA_TRIGGER_BITRISE_WORKFLOW_ID",
	} {
		t.Setenv(key, "")
	}
	cfg := FromEnv()
	if cfg.Mention != "@fa" || cfg.GitHubWorkflow != "fa-universal.yml" || cfg.GitHubRef != "main" {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.GitHubAPIURL != "https://api.github.com" || cfg.GitLabURL != "https://gitlab.com" ||
		cfg.BitriseURL != "https://api.bitrise.io/v0.1" || cfg.BitriseWorkflowID != "fa-universal" {
		t.Fatalf("url defaults = %+v", cfg)
	}
	if cfg.GracePeriod != 5*time.Second || cfg.GitLabRef != "main" {
		t.Fatalf("grace/ref defaults = %+v", cfg)
	}
	if len(cfg.BotLogins) != len(DefaultBotLogins) || cfg.AllowBots || cfg.AlwaysFallback {
		t.Fatalf("bot defaults = %+v", cfg)
	}
	if cfg.githubConfigured() || cfg.gitlabConfigured() || cfg.bitriseConfigured() {
		t.Fatal("empty env must mean unconfigured backends")
	}
}

func TestFromEnvSecretsAndOverrides(t *testing.T) {
	t.Setenv("FA_NETWORK_WEBHOOK_SECRET", "shared")
	t.Setenv("FA_WEBHOOK_GITHUB_SECRET", "gh-specific")
	t.Setenv("FA_TRIGGER_MENTION", "@helper")
	t.Setenv("FA_TRIGGER_BOT_LOGINS", "a, b , ,")
	t.Setenv("FA_TRIGGER_ALLOW_BOTS", "true")
	t.Setenv("FA_TRIGGER_ALWAYS_DISPATCH_FALLBACK", "1")
	t.Setenv("FA_TRIGGER_GRACE_PERIOD", "250ms")
	t.Setenv("FA_TRIGGER_GITHUB_TOKEN", "pat")
	t.Setenv("FA_TRIGGER_GITLAB_PROJECT_ID", "9")
	t.Setenv("FA_TRIGGER_GITLAB_TOKEN", "glt")
	t.Setenv("FA_TRIGGER_BITRISE_APP_SLUG", "slug")
	t.Setenv("FA_TRIGGER_BITRISE_TOKEN", "bt")
	t.Setenv("FA_TRIGGER_GITHUB_USE_TARGET_REPO", "yes")
	cfg := FromEnv()
	if cfg.GitHubSecret != "gh-specific" || cfg.GitLabSecret != "shared" ||
		cfg.BitbucketSecret != "shared" || cfg.GenericSecret != "shared" {
		t.Fatalf("secret fallback = %+v", cfg)
	}
	if cfg.Mention != "@helper" || len(cfg.BotLogins) != 2 || cfg.BotLogins[1] != "b" {
		t.Fatalf("mention/bots = %+v", cfg)
	}
	if !cfg.AllowBots || !cfg.AlwaysFallback || !cfg.GitHubUseTargetRepo || cfg.GracePeriod != 250*time.Millisecond {
		t.Fatalf("flags = %+v", cfg)
	}
	if !cfg.githubConfigured() || !cfg.gitlabConfigured() || !cfg.bitriseConfigured() {
		t.Fatal("configured backends not detected")
	}
	opts := cfg.ParseOptions()
	if opts.Mention != "@helper" || !opts.AllowBots || len(opts.BotLogins) != 2 {
		t.Fatalf("parse options = %+v", opts)
	}
}
