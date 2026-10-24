package triggers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
)

func signHex(t *testing.T, secret string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func signB64(t *testing.T, secret string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestAuthenticateProviders(t *testing.T) {
	svc := NewService(Config{
		GitHubSecret: "ghs", GitLabSecret: "gls", BitbucketSecret: "bbs", GenericSecret: "gen",
	}, nil)
	body := []byte(`{"a":1}`)

	h := http.Header{"X-Hub-Signature-256": []string{signHex(t, "ghs", body)}}
	if !svc.Authenticate("github", h, body) {
		t.Error("valid github HMAC rejected")
	}
	h.Set("X-Hub-Signature-256", signHex(t, "wrong", body))
	if svc.Authenticate("github", h, body) {
		t.Error("wrong github HMAC accepted")
	}
	h.Set("X-Hub-Signature-256", signB64(t, "ghs", body))
	if !svc.Authenticate("github", h, body) {
		t.Error("base64 HMAC variant rejected")
	}

	h = http.Header{"X-Gitlab-Token": []string{"gls"}}
	if !svc.Authenticate("gitlab", h, body) {
		t.Error("gitlab token rejected")
	}
	h.Set("X-Gitlab-Token", "no")
	if svc.Authenticate("gitlab", h, body) {
		t.Error("bad gitlab token accepted")
	}

	h = http.Header{"X-Hub-Signature": []string{signHex(t, "bbs", body)}}
	if !svc.Authenticate("bitbucket", h, body) {
		t.Error("bitbucket HMAC rejected")
	}
	if svc.Authenticate("unknown", h, body) {
		t.Error("unknown provider must fail closed")
	}
}

func TestAuthenticateGeneric(t *testing.T) {
	svc := NewService(Config{GenericSecret: "gen"}, nil)
	body := []byte(`{}`)
	for name, h := range map[string]http.Header{
		"bearer":   {"Authorization": []string{"Bearer gen"}},
		"fa token": {"X-Fa-Webhook-Token": []string{"gen"}},
		"hmac":     {"X-Fa-Network-Signature": []string{signB64(t, "gen", body)}},
	} {
		if !svc.Authenticate("generic", h, body) {
			t.Errorf("%s rejected", name)
		}
	}
	if svc.Authenticate("generic", http.Header{"Authorization": []string{"Bearer nope"}}, body) {
		t.Error("bad bearer accepted")
	}
}

func TestAuthenticateFailsClosedWithoutSecret(t *testing.T) {
	svc := NewService(Config{}, nil)
	body := []byte(`{}`)
	h := http.Header{"X-Hub-Signature-256": []string{signHex(t, "", body)}}
	if svc.Authenticate("github", h, body) {
		t.Error("empty secret must never authenticate")
	}
	if svc.Authenticate("generic", http.Header{}, body) {
		t.Error("empty generic secret must never authenticate")
	}
	if tokenEqual("", "") || validHMAC("", "sha256=xx", body) {
		t.Error("empty secrets must fail")
	}
}
