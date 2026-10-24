package triggers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// appTokens mints GitHub App RS256 JWTs and caches per-installation
// access tokens until one minute before expiry.
type appTokens struct {
	appID          string
	key            *rsa.PrivateKey
	installationID string // optional FA_GITHUB_APP_INSTALLATION_ID override

	mu            sync.Mutex
	installations map[string]string // repo -> installation id
	tokens        map[string]cachedAppToken
	now           func() time.Time
}

type cachedAppToken struct {
	token   string
	expires time.Time
}

func newAppTokens(cfg Config) (*appTokens, error) {
	key, err := parsePrivateKey(cfg.GitHubAppPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse FA_GITHUB_APP_PRIVATE_KEY: %w", err)
	}
	return &appTokens{
		appID:          cfg.GitHubAppID,
		key:            key,
		installationID: cfg.GitHubAppInstallation,
		installations:  map[string]string{},
		tokens:         map[string]cachedAppToken{},
		now:            time.Now,
	}, nil
}

// parsePrivateKey accepts PEM or base64-encoded PEM (PKCS#1 / PKCS#8).
func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	data := []byte(strings.TrimSpace(raw))
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("not PEM and not base64: %w", err)
		}
		data = decoded
	}
	return jwt.ParseRSAPrivateKeyFromPEM(data)
}

// jwt mints the short-lived app assertion (10-min cap, clock-skew margin).
func (a *appTokens) jwt() (string, error) {
	now := a.now()
	claims := jwt.RegisteredClaims{
		Issuer:    a.appID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(a.key)
}

// installation resolves the installation id for a repo (cached).
func (a *appTokens) installation(ctx context.Context, client *http.Client, api, repo string) (string, error) {
	if a.installationID != "" {
		return a.installationID, nil
	}
	a.mu.Lock()
	id := a.installations[repo]
	a.mu.Unlock()
	if id != "" {
		return id, nil
	}
	assertion, err := a.jwt()
	if err != nil {
		return "", err
	}
	var out struct {
		ID json.Number `json:"id"`
	}
	err = githubAPI(ctx, client, http.MethodGet, api+"/repos/"+repo+"/installation", assertion, nil, &out)
	if err != nil {
		return "", fmt.Errorf("lookup installation for %s: %w", repo, err)
	}
	a.mu.Lock()
	a.installations[repo] = out.ID.String()
	a.mu.Unlock()
	return out.ID.String(), nil
}

// token returns a valid installation access token for the repo.
func (a *appTokens) token(ctx context.Context, client *http.Client, api, repo string) (string, error) {
	id, err := a.installation(ctx, client, api, repo)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	cached := a.tokens[id]
	a.mu.Unlock()
	if cached.token != "" && a.now().Before(cached.expires.Add(-time.Minute)) {
		return cached.token, nil
	}
	assertion, err := a.jwt()
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	url := fmt.Sprintf("%s/app/installations/%s/access_tokens", api, id)
	if err := githubAPI(ctx, client, http.MethodPost, url, assertion, struct{}{}, &out); err != nil {
		return "", fmt.Errorf("mint installation token: %w", err)
	}
	a.mu.Lock()
	a.tokens[id] = cachedAppToken{token: out.Token, expires: out.ExpiresAt}
	a.mu.Unlock()
	return out.Token, nil
}
