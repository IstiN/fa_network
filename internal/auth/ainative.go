package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AINativeProvider validates dmtools-compatible JWTs from an IstiN/auth
// deployment (github.com/IstiN/auth, e.g. https://ai-native.cloud). The
// contract is symmetric HS256 with the deployment's shared JWT_SECRET —
// there is no JWKS. iss must match the auth base host (tokens without iss
// are accepted for legacy deployments, mirroring the issuer itself). The
// locked display name is resolved from GET /api/auth/user and cached
// briefly; on a lookup failure it degrades to the email subject.
type AINativeProvider struct {
	baseURL string
	issuers []string
	secret  []byte
	http    *http.Client

	mu    sync.Mutex
	names map[string]aiName
}

type aiName struct {
	name  string
	until time.Time
}

// aiNameTTL caps how stale a cached display name may be.
const aiNameTTL = 5 * time.Minute

// NewAINativeProvider builds the provider for an auth service base URL and
// its shared JWT secret (exact bytes of the deployment's JWT_SECRET).
// extraIssuers optionally extends the accepted iss set (env override).
func NewAINativeProvider(baseURL string, secret []byte, extraIssuers ...string) *AINativeProvider {
	baseURL = strings.TrimRight(baseURL, "/")
	u, _ := url.Parse(baseURL)
	return &AINativeProvider{
		baseURL: baseURL,
		// Every IstiN/auth build mints iss="ai-native" (the jwtutil.Issuer
		// constant); the auth host is accepted forward-compat. Empty iss is
		// always accepted (legacy deployments).
		issuers: append([]string{"ai-native", u.Host}, extraIssuers...),
		secret:  secret,
		http:    &http.Client{Timeout: 10 * time.Second},
		names:   map[string]aiName{},
	}
}

// Validate implements Provider.
func (a *AINativeProvider) Validate(ctx context.Context, token string) (*Principal, error) {
	parsed, err := validateToken(token, nil, [][]byte{a.secret})
	if err != nil {
		return nil, err
	}
	claims := parsed
	if !a.issuerOK(claims.Issuer) {
		return nil, invalid("issuer mismatch %q", claims.Issuer)
	}
	id := claims.UserID
	if id == "" {
		id = claims.Subject
	}
	if id == "" {
		return nil, invalid("missing sub claim")
	}
	return &Principal{UserID: id, DisplayName: a.displayName(ctx, token, id, claims.Subject)}, nil
}

// issuerOK reports whether iss is in the accept-set; empty iss is
// accepted for legacy tokens (the issuer itself does the same).
func (a *AINativeProvider) issuerOK(iss string) bool {
	if iss == "" {
		return true
	}
	for _, want := range a.issuers {
		if iss == want {
			return true
		}
	}
	return false
}

// displayName resolves the locked auth-service name, cached per user.
func (a *AINativeProvider) displayName(ctx context.Context, token, id, fallback string) string {
	a.mu.Lock()
	cached, ok := a.names[id]
	a.mu.Unlock()
	if ok && time.Now().Before(cached.until) {
		return cached.name
	}
	name := a.fetchUserName(ctx, token)
	if name == "" {
		name = fallback
	}
	a.mu.Lock()
	a.names[id] = aiName{name: name, until: time.Now().Add(aiNameTTL)}
	a.mu.Unlock()
	return name
}

// fetchUserName reads GET /api/auth/user; empty on any failure (the name
// cache degrades to the email subject, never to a hard failure).
func (a *AINativeProvider) fetchUserName(ctx context.Context, token string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/api/auth/user", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.http.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	var profile struct {
		Authenticated bool   `json:"authenticated"`
		Name          string `json:"name"`
	}
	if err := json.Unmarshal(body, &profile); err != nil || !profile.Authenticated {
		return ""
	}
	return profile.Name
}
