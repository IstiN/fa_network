package triggers

import (
	"os"
	"strings"
	"time"
)

// Config carries every FA_WEBHOOK_* / FA_TRIGGER_* / FA_GITHUB_APP_*
// setting of the ingress bridge (see .env.example).
type Config struct {
	GitHubSecret    string
	GitLabSecret    string
	BitbucketSecret string
	GenericSecret   string

	Mention        string
	BotLogins      []string
	AllowBots      bool
	AlwaysFallback bool
	GracePeriod    time.Duration

	GitHubRepo            string
	GitHubWorkflow        string
	GitHubRef             string
	GitHubUseTargetRepo   bool
	GitHubToken           string
	GitHubAPIURL          string
	GitHubAppID           string
	GitHubAppPrivateKey   string
	GitHubAppInstallation string

	GitLabURL       string
	GitLabProjectID string
	GitLabRef       string
	GitLabToken     string

	BitriseURL        string
	BitriseAppSlug    string
	BitriseToken      string
	BitriseWorkflowID string
}

// FromEnv reads the bridge configuration from the environment.
func FromEnv() Config {
	shared := os.Getenv("FA_NETWORK_WEBHOOK_SECRET")
	return Config{
		GitHubSecret:    secretOr("FA_WEBHOOK_GITHUB_SECRET", shared),
		GitLabSecret:    secretOr("FA_WEBHOOK_GITLAB_SECRET", shared),
		BitbucketSecret: secretOr("FA_WEBHOOK_BITBUCKET_SECRET", shared),
		GenericSecret:   secretOr("FA_WEBHOOK_GENERIC_SECRET", shared),
		Mention:         envOr("FA_TRIGGER_MENTION", "@fa"),
		BotLogins:       botLogins(),
		AllowBots:       envBool("FA_TRIGGER_ALLOW_BOTS"),
		AlwaysFallback:  envBool("FA_TRIGGER_ALWAYS_DISPATCH_FALLBACK"),
		GracePeriod:     envDuration("FA_TRIGGER_GRACE_PERIOD", 5*time.Second),

		GitHubRepo:            os.Getenv("FA_TRIGGER_GITHUB_REPO"),
		GitHubWorkflow:        envOr("FA_TRIGGER_GITHUB_WORKFLOW", "fa-universal.yml"),
		GitHubRef:             envOr("FA_TRIGGER_GITHUB_REF", "main"),
		GitHubUseTargetRepo:   envBool("FA_TRIGGER_GITHUB_USE_TARGET_REPO"),
		GitHubToken:           os.Getenv("FA_TRIGGER_GITHUB_TOKEN"),
		GitHubAPIURL:          envOr("FA_GITHUB_API_URL", "https://api.github.com"),
		GitHubAppID:           os.Getenv("FA_GITHUB_APP_ID"),
		GitHubAppPrivateKey:   os.Getenv("FA_GITHUB_APP_PRIVATE_KEY"),
		GitHubAppInstallation: os.Getenv("FA_GITHUB_APP_INSTALLATION_ID"),

		GitLabURL:       envOr("FA_TRIGGER_GITLAB_URL", "https://gitlab.com"),
		GitLabProjectID: os.Getenv("FA_TRIGGER_GITLAB_PROJECT_ID"),
		GitLabRef:       envOr("FA_TRIGGER_GITLAB_REF", "main"),
		GitLabToken:     os.Getenv("FA_TRIGGER_GITLAB_TOKEN"),

		BitriseURL:        envOr("FA_TRIGGER_BITRISE_URL", "https://api.bitrise.io/v0.1"),
		BitriseAppSlug:    os.Getenv("FA_TRIGGER_BITRISE_APP_SLUG"),
		BitriseToken:      os.Getenv("FA_TRIGGER_BITRISE_TOKEN"),
		BitriseWorkflowID: envOr("FA_TRIGGER_BITRISE_WORKFLOW_ID", "fa-universal"),
	}
}

// ParseOptions exposes the mention/bot filtering settings.
func (c Config) ParseOptions() ParseOptions {
	return ParseOptions{Mention: c.Mention, BotLogins: c.BotLogins, AllowBots: c.AllowBots}
}

// githubConfigured reports whether any GitHub credential mode is usable.
func (c Config) githubConfigured() bool {
	return c.GitHubToken != "" || (c.GitHubAppID != "" && c.GitHubAppPrivateKey != "")
}

func (c Config) gitlabConfigured() bool {
	return c.GitLabToken != "" && c.GitLabProjectID != ""
}

func (c Config) bitriseConfigured() bool {
	return c.BitriseToken != "" && c.BitriseAppSlug != ""
}

func secretOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes"
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func botLogins() []string {
	if v := os.Getenv("FA_TRIGGER_BOT_LOGINS"); v != "" {
		out := []string{}
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return append([]string(nil), DefaultBotLogins...)
}
