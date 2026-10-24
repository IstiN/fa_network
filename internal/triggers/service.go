package triggers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// ErrNoBackend marks a wake-up that no configured CI backend can serve.
var ErrNoBackend = errors.New("no ci wakeup backend configured")

// Service is the ingress bridge: authentication + parsing of provider
// webhooks, CI wake-up dispatch, and best-effort comment reactions.
type Service struct {
	cfg  Config
	http *http.Client
	app  *appTokens
}

// NewService builds the bridge. A bad GitHub App key is logged and the
// app mode disabled (token mode, when configured, keeps working).
func NewService(cfg Config, httpClient *http.Client) *Service {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	s := &Service{cfg: cfg, http: httpClient}
	if cfg.GitHubAppID != "" && cfg.GitHubAppPrivateKey != "" {
		app, err := newAppTokens(cfg)
		if err != nil {
			log.Printf("triggers: github app auth disabled: %v", err)
		} else {
			s.app = app
		}
	}
	return s
}

// GracePeriod is the online-agent grace window before the CI fallback.
func (s *Service) GracePeriod() time.Duration { return s.cfg.GracePeriod }

// AlwaysFallback reports FA_TRIGGER_ALWAYS_DISPATCH_FALLBACK.
func (s *Service) AlwaysFallback() bool { return s.cfg.AlwaysFallback }

// CanReact reports whether GitHub credentials allow 👀 reactions.
func (s *Service) CanReact() bool { return s.cfg.githubConfigured() }

// Parse authenticates the payload shape into a normalized event. The
// caller must have Authenticate()d the delivery first.
func (s *Service) Parse(provider string, header http.Header, body []byte) (*Event, error) {
	opts := s.cfg.ParseOptions()
	switch provider {
	case "github":
		return parseGitHub(header, body, opts)
	case "gitlab":
		return parseGitLab(header, body, opts)
	case "bitbucket":
		return parseBitbucket(header, body, opts)
	case "generic":
		return parseGeneric(body)
	}
	return nil, fmt.Errorf("unknown webhook provider %q", provider)
}

// Dispatch wakes the universal CI worker for the trigger and returns the
// backend used ("github" | "gitlab" | "bitrise").
func (s *Service) Dispatch(ctx context.Context, t *Trigger) (string, error) {
	backend := s.backendFor(t)
	switch backend {
	case "github":
		return backend, s.dispatchGitHub(ctx, t)
	case "gitlab":
		return backend, s.dispatchGitLab(ctx, t)
	case "bitrise":
		return backend, s.dispatchBitrise(ctx, t)
	case "":
		return "", ErrNoBackend
	}
	return "", fmt.Errorf("%w: runner %q", ErrNoBackend, backend)
}

// backendFor picks the CI backend: explicit runner first, then the SCM's
// natural backend, then the first configured one.
func (s *Service) backendFor(t *Trigger) string {
	if t.Runner != "" {
		return t.Runner
	}
	if backend := naturalBackend(t.Provider); backend != "" && s.configured(backend) {
		return backend
	}
	for _, backend := range []string{"github", "gitlab", "bitrise"} {
		if s.configured(backend) {
			return backend
		}
	}
	return ""
}

// naturalBackend maps an SCM provider to its usual CI backend. Bitbucket
// triggers ride Bitrise (no Bitbucket Pipelines adapter yet).
func naturalBackend(provider string) string {
	switch provider {
	case "github":
		return "github"
	case "gitlab":
		return "gitlab"
	case "bitbucket":
		return "bitrise"
	}
	return ""
}

func (s *Service) configured(backend string) bool {
	switch backend {
	case "github":
		return s.cfg.githubConfigured()
	case "gitlab":
		return s.cfg.gitlabConfigured()
	case "bitrise":
		return s.cfg.bitriseConfigured()
	}
	return false
}
