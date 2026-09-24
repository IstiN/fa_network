package auth

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// MockUser is one login/pass entry of the dev provider.
type MockUser struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// mockUsersFile is the optional local login/pass store (dev default).
const mockUsersFile = "mock_users.json"

// MockProvider is the fully-offline dev provider: login/pass users from an
// optional local file, HS256 dev JWTs, pluggable clock (AC-B10).
type MockProvider struct {
	secret  []byte
	issuer  string
	users   map[string]MockUser
	mu      sync.RWMutex
	now     func() time.Time
	fileMod time.Time
}

// NewMockProvider loads users from file (when present) and secrets the
// issuer key. With empty devSecret a stable random key is generated.
func NewMockProvider(devSecret []byte) *MockProvider {
	if len(devSecret) == 0 {
		devSecret = randomKey(32)
	}
	m := &MockProvider{
		secret: devSecret,
		issuer: "fa-network-mock",
		users:  map[string]MockUser{},
		now:    time.Now,
	}
	m.reload()
	return m
}

// SetClock swaps the clock (tests).
func (m *MockProvider) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

func (m *MockProvider) clock() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.now()
}

// reload re-reads the users file when it changed on disk.
func (m *MockProvider) reload() {
	info, err := os.Stat(mockUsersFile)
	if err != nil || !info.ModTime().After(m.fileMod) {
		return
	}
	m.loadUsers(info.ModTime())
}

func (m *MockProvider) loadUsers(mod time.Time) {
	data, err := os.ReadFile(mockUsersFile)
	if err != nil {
		return
	}
	m.storeUsers(parseUsers(data), mod)
}

func parseUsers(data []byte) []MockUser {
	var users []MockUser
	if err := json.Unmarshal(data, &users); err != nil {
		return nil
	}
	return users
}

func (m *MockProvider) storeUsers(users []MockUser, mod time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users = map[string]MockUser{}
	for _, u := range users {
		m.users[u.Login] = u
	}
	m.fileMod = mod
}

// AddUser registers a login/pass user at runtime (tests and bootstrap).
func (m *MockProvider) AddUser(login, password, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[login] = MockUser{Login: login, Password: password, Name: name}
}

// IssueToken is the dev login endpoint backing: login+password → JWT.
func (m *MockProvider) IssueToken(login, password string) (string, error) {
	m.reload()
	m.mu.RLock()
	u, ok := m.users[login]
	m.mu.RUnlock()
	if !ok || bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) != nil {
		return "", ErrInvalidToken
	}
	now := m.clock()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   login,
			Issuer:    m.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
		Name: displayNameOf(u, login),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

func displayNameOf(u MockUser, login string) string {
	if u.Name != "" {
		return u.Name
	}
	return login
}

// Validate implements Provider.
func (m *MockProvider) Validate(_ context.Context, token string) (*Principal, error) {
	parsed, err := verifyHS(token, [][]byte{m.secret})
	if err != nil {
		return nil, invalid("mock: %v", err)
	}
	claims := parsed.Claims.(*Claims)
	if claims.Issuer != m.issuer {
		return nil, invalid("mock: wrong issuer %q", claims.Issuer)
	}
	// Expiry is checked against the provider clock so tests control time.
	if claims.ExpiresAt != nil && m.clock().After(claims.ExpiresAt.Time) {
		return nil, invalid("mock: token expired")
	}
	return claimsToPrincipal(claims)
}

// randomKey returns n random bytes (best effort — math/rand fallback).
func randomKey(n int) []byte {
	b := make([]byte, n)
	if _, err := randRead(b); err != nil {
		for i := range b {
			b[i] = byte(i*31 + 7)
		}
	}
	return b
}

// logins lists current logins (deterministic order; tests).
func (m *MockProvider) logins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.users))
	for login := range m.users {
		out = append(out, login)
	}
	sort.Strings(out)
	return out
}
