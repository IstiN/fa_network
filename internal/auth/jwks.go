package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksCache fetches and caches a provider's JWKS, refreshing on demand.
type jwksCache struct {
	url     string
	http    *http.Client
	mu      sync.RWMutex
	keys    []any
	fetched time.Time
	ttl     time.Duration
	// hsFallback is an optional shared HMAC secret (dev auth instances).
	hsFallback []byte
}

func newJWKSCache(url string, client *http.Client) *jwksCache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &jwksCache{url: url, http: client, ttl: time.Hour}
}

type jwksDocument struct {
	Keys []json.RawMessage `json:"keys"`
}

// rsaKeys returns the currently cached RSA public keys, fetching when stale.
func (c *jwksCache) rsaKeys(ctx context.Context) ([]any, error) {
	c.mu.RLock()
	fresh := len(c.keys) > 0 && time.Since(c.fetched) < c.ttl
	keys := append([]any(nil), c.keys...)
	c.mu.RUnlock()
	if fresh {
		return keys, nil
	}
	return c.refresh(ctx)
}

func (c *jwksCache) refresh(ctx context.Context) ([]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.keys) > 0 && time.Since(c.fetched) < c.ttl {
		return append([]any(nil), c.keys...), nil
	}
	doc, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	keys := doc.rsaKeys()
	if len(keys) == 0 {
		return nil, errors.New("jwks fetch: no usable RSA keys")
	}
	c.keys = keys
	c.fetched = time.Now()
	return append([]any(nil), keys...), nil
}

func (c *jwksCache) fetch(ctx context.Context) (*jwksDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("jwks parse: %w", err)
	}
	return &doc, nil
}

func (d *jwksDocument) rsaKeys() []any {
	var keys []any
	for _, raw := range d.Keys {
		if key := rsaKeyOf(raw); key != nil {
			keys = append(keys, key)
		}
	}
	return keys
}

// rsaKeyOf parses one JWK into an RSA public key (nil when unusable).
func rsaKeyOf(raw json.RawMessage) *rsa.PublicKey {
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil || jwk["kty"] != "RSA" {
		return nil
	}
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)
	if nStr == "" || eStr == "" {
		return nil
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
}
