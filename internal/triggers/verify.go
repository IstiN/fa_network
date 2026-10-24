package triggers

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
)

// Authenticate verifies the delivery's signature/token for the provider.
// A missing configured secret fails closed (401), never open.
func (s *Service) Authenticate(provider string, header http.Header, body []byte) bool {
	switch provider {
	case "github":
		return validHMAC(s.cfg.GitHubSecret, header.Get("X-Hub-Signature-256"), body)
	case "gitlab":
		return tokenEqual(s.cfg.GitLabSecret, header.Get("X-Gitlab-Token"))
	case "bitbucket":
		return validHMAC(s.cfg.BitbucketSecret, header.Get("X-Hub-Signature"), body)
	case "generic":
		return s.genericAuth(header, body)
	}
	return false
}

// genericAuth accepts a Bearer token, X-Fa-Webhook-Token, or an
// X-Fa-Network-Signature HMAC of the raw body.
func (s *Service) genericAuth(header http.Header, body []byte) bool {
	secret := s.cfg.GenericSecret
	bearer := strings.TrimPrefix(header.Get("Authorization"), "Bearer ")
	if tokenEqual(secret, bearer) {
		return true
	}
	if tokenEqual(secret, header.Get("X-Fa-Webhook-Token")) {
		return true
	}
	return validHMAC(secret, header.Get("X-Fa-Network-Signature"), body)
}

// validHMAC checks a sha256=<hex|base64> signature header against the
// HMAC-SHA256 of body (base64 accepted for dispatcher compatibility).
func validHMAC(secret, signature string, body []byte) bool {
	if secret == "" || signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sum := mac.Sum(nil)
	wantHex := "sha256=" + hex.EncodeToString(sum)
	wantB64 := "sha256=" + base64.StdEncoding.EncodeToString(sum)
	return constantTimeEqual(signature, wantHex) || constantTimeEqual(signature, wantB64)
}

// tokenEqual compares a shared token in constant time; empty never passes.
func tokenEqual(secret, got string) bool {
	if secret == "" || got == "" {
		return false
	}
	return constantTimeEqual(secret, got)
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
