package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/auth"
	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/store"
	"github.com/IstiN/fa_network/internal/triggers"
	"github.com/IstiN/fa_network/internal/wakeup"
)

// ciRecorder fakes the CI wake-up target (workflow_dispatch + reactions).
type ciRecorder struct {
	*httptest.Server
	mu         sync.Mutex
	dispatches int
	reactions  int
	lastInputs map[string]string
	fail       bool
}

func newCIRecorder(t *testing.T) *ciRecorder {
	t.Helper()
	ci := &ciRecorder{}
	ci.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ci.mu.Lock()
		defer ci.mu.Unlock()
		switch {
		case strings.Contains(r.URL.Path, "/dispatches"):
			ci.dispatches++
			var body struct {
				Inputs map[string]string `json:"inputs"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			ci.lastInputs = body.Inputs
		case strings.HasSuffix(r.URL.Path, "/reactions"):
			ci.reactions++
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if ci.fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ci.Close)
	return ci
}

func (ci *ciRecorder) counts() (dispatches, reactions int) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	return ci.dispatches, ci.reactions
}

func (ci *ciRecorder) setFail(v bool) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.fail = v
}

func (ci *ciRecorder) inputs() map[string]string {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	out := map[string]string{}
	for k, v := range ci.lastInputs {
		out[k] = v
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// newTriggerEnv builds a full server with the webhook bridge configured
// against the fake CI recorder (offline agent presence by default).
func newTriggerEnv(t *testing.T, mutate func(*triggers.Config)) (*testEnv, *ciRecorder) {
	t.Helper()
	ci := newCIRecorder(t)
	cfg := triggers.Config{
		GitHubSecret: "whsec", GitLabSecret: "glsec", BitbucketSecret: "bbsec", GenericSecret: "gensec",
		Mention: "@fa", BotLogins: triggers.DefaultBotLogins,
		GitHubToken: "pat", GitHubAPIURL: ci.URL, GitHubWorkflow: "fa-universal.yml", GitHubRef: "main",
		GitHubRepo:  "IstiN/dmtools-agentic-workflows",
		GracePeriod: 30 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	st := store.NewMemStore()
	fakeHub := hub.NewFakeClient("r_test")
	provider := auth.NewMockProvider([]byte("0123456789abcdef0123456789abcdef"))
	dispatcher := wakeup.NewDispatcher(wakeup.Options{Store: st, Secret: []byte("sec")})
	srv := New(st, provider, fakeHub, dispatcher, Config{
		RetentionSweepInterval: time.Hour,
		Triggers:               triggers.NewService(cfg, ci.Client()),
	})
	env := &testEnv{t: t, srv: srv, st: st, hub: fakeHub, auth: provider}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	srv.RunRelay(ctx)
	env.http = httptest.NewServer(srv.Handler())
	t.Cleanup(env.http.Close)
	return env, ci
}

func postWebhook(t *testing.T, env *testEnv, provider string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/"+provider, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	env.http.Config.Handler.ServeHTTP(rec, req)
	return rec
}

func ghHeaders(t *testing.T, secret, event string, body []byte) map[string]string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return map[string]string{
		"X-Hub-Signature-256": "sha256=" + hex.EncodeToString(mac.Sum(nil)),
		"X-GitHub-Event":      event,
	}
}

const webhookComment = `{"action":"created","repository":{"full_name":"Owner/Repo"},"issue":{"number":42},"comment":{"id":123,"body":"@fa please fix","user":{"login":"human","type":"User"}}}`

func TestWebhookDisabled(t *testing.T) {
	env := newTestEnv(t)
	rec := postWebhook(t, env, "github", []byte(`{}`), nil)
	if rec.Code != http.StatusServiceUnavailable || errCode(t, rec) != CodeWebhookNotConfigured {
		t.Fatalf("disabled = %d %s", rec.Code, rec.Body.String())
	}
}

func TestWebhookGitHubOfflineDispatch(t *testing.T) {
	env, ci := newTriggerEnv(t, nil)
	body := []byte(webhookComment)
	rec := postWebhook(t, env, "github", body, ghHeaders(t, "whsec", "issue_comment", body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("dispatch = %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	decodeBody(t, rec, &out)
	if out["status"] != "dispatched" || out["sessionKey"] != "gh-owner-repo-42" ||
		out["mode"] != "ci_wakeup" || out["backend"] != "github" {
		t.Fatalf("out = %+v", out)
	}
	dispatches, _ := ci.counts()
	if dispatches != 1 {
		t.Fatalf("ci dispatches = %d", dispatches)
	}
	if ci.inputs()["session_key"] != "gh-owner-repo-42" || ci.inputs()["comment_id"] != "123" ||
		ci.inputs()["prompt"] != "@fa please fix" {
		t.Fatalf("inputs = %+v", ci.inputs())
	}
	// Best-effort 👀 is asynchronous; it must arrive without blocking.
	waitFor(t, "eyes reaction", func() bool {
		_, reactions := ci.counts()
		return reactions == 1
	})
}

func TestWebhookAuthAndParsing(t *testing.T) {
	env, ci := newTriggerEnv(t, nil)
	body := []byte(webhookComment)
	rec := postWebhook(t, env, "github", body, ghHeaders(t, "wrong", "issue_comment", body))
	if rec.Code != http.StatusUnauthorized || errCode(t, rec) != CodeUnauthorized {
		t.Fatalf("bad signature = %d", rec.Code)
	}
	ping := []byte(`{"zen":"hi"}`)
	rec = postWebhook(t, env, "github", ping, ghHeaders(t, "whsec", "ping", ping))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"event":"ping"`) {
		t.Fatalf("ping = %d %s", rec.Code, rec.Body.String())
	}
	noMention := []byte(`{"action":"created","repository":{"full_name":"o/r"},"issue":{"number":1},"comment":{"id":1,"body":"hello","user":{"login":"human"}}}`)
	rec = postWebhook(t, env, "github", noMention, ghHeaders(t, "whsec", "issue_comment", noMention))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"reason":"no_mention"`) {
		t.Fatalf("no mention = %d %s", rec.Code, rec.Body.String())
	}
	bot := []byte(`{"action":"created","repository":{"full_name":"o/r"},"issue":{"number":1},"comment":{"id":1,"body":"@fa loop","user":{"login":"fa-bot","type":"Bot"}}}`)
	rec = postWebhook(t, env, "github", bot, ghHeaders(t, "whsec", "issue_comment", bot))
	if !strings.Contains(rec.Body.String(), `"reason":"bot_author"`) {
		t.Fatalf("bot = %s", rec.Body.String())
	}
	bad := []byte(`{`)
	rec = postWebhook(t, env, "github", bad, ghHeaders(t, "whsec", "issue_comment", bad))
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != CodeInvalidPayload {
		t.Fatalf("malformed = %d %s", rec.Code, rec.Body.String())
	}
	if dispatches, _ := ci.counts(); dispatches != 0 {
		t.Fatalf("ignored events caused %d dispatches", dispatches)
	}
}

func TestWebhookOnlineLiveThenGraceFallback(t *testing.T) {
	env, ci := newTriggerEnv(t, nil)
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "agent1", Name: "gh-owner-repo-42", Online: true})
	waitFor(t, "agent online in relay", func() bool {
		_, online := env.srv.relay.AgentOnlineByNameOrID("gh-owner-repo-42")
		return online
	})
	body := []byte(webhookComment)
	rec := postWebhook(t, env, "github", body, ghHeaders(t, "whsec", "issue_comment", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("live = %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	decodeBody(t, rec, &out)
	if out["mode"] != "live" || out["status"] != "accepted" || out["agentId"] != "agent1" {
		t.Fatalf("live out = %+v", out)
	}
	if dispatches, _ := ci.counts(); dispatches != 0 {
		t.Fatal("online agent must not trigger immediate CI wakeup")
	}
	// The agent drops offline inside the grace window -> CI wake-up fires.
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "agent1", Name: "gh-owner-repo-42", Online: false})
	waitFor(t, "grace-window CI wakeup", func() bool {
		dispatches, _ := ci.counts()
		return dispatches == 1
	})
}

func TestWebhookAlwaysFallback(t *testing.T) {
	env, ci := newTriggerEnv(t, func(cfg *triggers.Config) { cfg.AlwaysFallback = true })
	env.hub.EmitPresence(hub.PresenceInfo{AgentID: "agent1", Name: "gh-owner-repo-42", Online: true})
	waitFor(t, "agent online", func() bool {
		_, online := env.srv.relay.AgentOnlineByNameOrID("gh-owner-repo-42")
		return online
	})
	body := []byte(webhookComment)
	rec := postWebhook(t, env, "github", body, ghHeaders(t, "whsec", "issue_comment", body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("always fallback = %d %s", rec.Code, rec.Body.String())
	}
	if dispatches, _ := ci.counts(); dispatches != 1 {
		t.Fatalf("dispatches = %d", dispatches)
	}
}

func TestWebhookBackendOutcomes(t *testing.T) {
	env, _ := newTriggerEnv(t, func(cfg *triggers.Config) { cfg.GitHubToken = "" })
	body := []byte(webhookComment)
	rec := postWebhook(t, env, "github", body, ghHeaders(t, "whsec", "issue_comment", body))
	if rec.Code != http.StatusServiceUnavailable || errCode(t, rec) != CodeWakeupNotConfigured {
		t.Fatalf("no backend = %d %s", rec.Code, rec.Body.String())
	}
	env2, ci2 := newTriggerEnv(t, nil)
	ci2.setFail(true)
	rec = postWebhook(t, env2, "github", body, ghHeaders(t, "whsec", "issue_comment", body))
	if rec.Code != http.StatusBadGateway || errCode(t, rec) != CodeWakeupFailed {
		t.Fatalf("backend failure = %d %s", rec.Code, rec.Body.String())
	}
}

func TestWebhookGenericAndGitLab(t *testing.T) {
	env, ci := newTriggerEnv(t, nil)
	generic := []byte(`{"sessionKey":"My Session","prompt":"@fa custom","provider":"custom"}`)
	rec := postWebhook(t, env, "generic", generic, map[string]string{"Authorization": "Bearer gensec"})
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"sessionKey":"my-session"`) {
		t.Fatalf("generic = %d %s", rec.Code, rec.Body.String())
	}
	note := []byte(`{"user":{"username":"human"},"project":{"path_with_namespace":"g/p"},"object_attributes":{"id":5,"note":"@fa go","noteable_type":"Issue"},"issue":{"id":4}}`)
	rec = postWebhook(t, env, "gitlab", note, map[string]string{"X-Gitlab-Token": "glsec", "X-Gitlab-Event": "Note Hook"})
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"sessionKey":"gl-g-p-4"`) {
		t.Fatalf("gitlab = %d %s", rec.Code, rec.Body.String())
	}
	if dispatches, _ := ci.counts(); dispatches != 2 {
		t.Fatalf("dispatches = %d", dispatches)
	}
}
