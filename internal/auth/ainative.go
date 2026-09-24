package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AINativeProvider validates dmtools-compatible JWTs from ai-native.cloud
// (IstiN/auth). It discovers the JWKS URL from the service's public config
// endpoint and accepts both RS256 (prod) and HS256 (dev instances) tokens.
type AINativeProvider struct {
	baseURL string
	http    *http.Client
	jwks    *jwksCache
	mu      sync.Mutex
	once    bool
	cfgErr  error
}

// NewAINativeProvider builds the provider for an auth service base URL.
func NewAINativeProvider(baseURL string) *AINativeProvider {
	return &AINativeProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
		jwks:    newJWKSCache("", nil),
	}
}

type authConfig struct {
	JWKSURL   string `json:"jwksUrl"`
	JwksURL   string `json:"jwks_url"`
	DevSecret string `json:"devSecret"`
}

// ensureConfigured lazily discovers the verification material (once).
func (a *AINativeProvider) ensureConfigured(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.once {
		return a.cfgErr
	}
	a.once = true
	a.cfgErr = a.discover(ctx)
	return a.cfgErr
}

// discover fetches /api/auth/config for the JWKS URL (or dev secret).
func (a *AINativeProvider) discover(ctx context.Context) error {
	cfg, err := a.fetchConfig(ctx)
	if err != nil {
		return err
	}
	return a.applyConfig(cfg)
}

func (a *AINativeProvider) fetchConfig(ctx context.Context) (*authConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		a.baseURL+"/api/auth/config", nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth config: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var cfg authConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("auth config parse: %w", err)
	}
	return &cfg, nil
}

func (a *AINativeProvider) applyConfig(cfg *authConfig) error {
	jwks := cfg.JWKSURL
	if jwks == "" {
		jwks = cfg.JwksURL
	}
	if jwks == "" && cfg.DevSecret == "" {
		return fmt.Errorf("auth config: no jwksUrl or devSecret")
	}
	a.jwks.url = jwks
	if cfg.DevSecret != "" {
		a.jwks.hsFallback = []byte(cfg.DevSecret)
	}
	return nil
}

// Validate implements Provider.
func (a *AINativeProvider) Validate(ctx context.Context, token string) (*Principal, error) {
	if err := a.ensureConfigured(ctx); err != nil {
		return nil, err
	}
	keys, err := a.jwks.rsaKeys(ctx)
	if err != nil && len(a.jwks.hsFallback) == 0 {
		return nil, err
	}
	var hs [][]byte
	if len(a.jwks.hsFallback) > 0 {
		hs = [][]byte{a.jwks.hsFallback}
	}
	claims, verr := validateToken(token, keys, hs)
	if verr != nil {
		return nil, verr
	}
	return claimsToPrincipal(claims)
}
