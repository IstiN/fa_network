package triggers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testTrigger() *Trigger {
	return &Trigger{
		Provider: "github", TargetRepo: "o/r", SessionKey: "gh-o-r-42",
		IssueNumber: "42", CommentID: "123", Prompt: "@fa fix", Author: "human",
	}
}

// githubStub fakes the GitHub REST surface: workflow dispatches,
// reactions, and (optionally) the App installation token flow.
type githubStub struct {
	*httptest.Server
	dispatches   atomic.Int64
	reactions    atomic.Int64
	appTokens    atomic.Int64
	lookups      atomic.Int64
	lastInputs   map[string]string
	lastReaction string
	failStatus   int
}

func newGitHubStub(t *testing.T, app bool) *githubStub {
	t.Helper()
	g := &githubStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/o/r/actions/workflows/fa-universal.yml/dispatches", func(w http.ResponseWriter, r *http.Request) {
		g.dispatches.Add(1)
		if r.Header.Get("Authorization") == "" {
			t.Error("dispatch without auth")
		}
		var body struct {
			Ref    string            `json:"ref"`
			Inputs map[string]string `json:"inputs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.lastInputs = body.Inputs
		if body.Ref != "main" {
			t.Errorf("ref = %q", body.Ref)
		}
		w.WriteHeader(g.failStatusOr(http.StatusNoContent))
	})
	mux.HandleFunc("POST /repos/o/r/issues/comments/123/reactions", func(w http.ResponseWriter, r *http.Request) {
		g.reactions.Add(1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.lastReaction = body["content"]
		w.WriteHeader(g.failStatusOr(http.StatusCreated))
	})
	if app {
		mux.HandleFunc("GET /repos/o/r/installation", func(w http.ResponseWriter, r *http.Request) {
			g.lookups.Add(1)
			assertAppJWT(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 123})
		})
		mux.HandleFunc("POST /app/installations/123/access_tokens", func(w http.ResponseWriter, r *http.Request) {
			g.appTokens.Add(1)
			assertAppJWT(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token": "installation-token", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		})
	}
	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Close)
	return g
}

func (g *githubStub) failStatusOr(ok int) int {
	if g.failStatus != 0 {
		return g.failStatus
	}
	return ok
}

// assertAppJWT checks the request carries a three-part RS256 assertion.
func assertAppJWT(t *testing.T, r *http.Request) {
	t.Helper()
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(strings.Split(auth, ".")) != 3 {
		t.Errorf("expected JWT assertion, got %q", auth)
	}
}

func TestDispatchGitHubToken(t *testing.T) {
	stub := newGitHubStub(t, false)
	svc := NewService(Config{
		GitHubToken: "pat", GitHubAPIURL: stub.URL,
		GitHubWorkflow: "fa-universal.yml", GitHubRef: "main",
	}, stub.Client())
	backend, err := svc.Dispatch(context.Background(), testTrigger())
	if err != nil || backend != "github" {
		t.Fatalf("dispatch = %q, %v", backend, err)
	}
	if stub.dispatches.Load() != 1 {
		t.Fatalf("dispatches = %d", stub.dispatches.Load())
	}
	in := stub.lastInputs
	if in["session_key"] != "gh-o-r-42" || in["issue_number"] != "42" || in["comment_id"] != "123" ||
		in["prompt"] != "@fa fix" || in["provider"] != "github" || in["target_repo"] != "o/r" {
		t.Fatalf("inputs = %+v", in)
	}
}

func TestDispatchGitHubErrors(t *testing.T) {
	stub := newGitHubStub(t, false)
	stub.failStatus = http.StatusInternalServerError
	svc := NewService(Config{GitHubToken: "pat", GitHubAPIURL: stub.URL, GitHubWorkflow: "fa-universal.yml", GitHubRef: "main"}, stub.Client())
	if _, err := svc.Dispatch(context.Background(), testTrigger()); err == nil {
		t.Fatal("backend 500 must surface an error")
	}
	svc = NewService(Config{GitHubToken: "pat", GitHubAPIURL: stub.URL}, stub.Client())
	if _, err := svc.Dispatch(context.Background(), &Trigger{Provider: "github"}); err == nil {
		t.Fatal("missing repository must error")
	}
	stub2 := newGitHubStub(t, false)
	svc = NewService(Config{GitHubToken: "pat", GitHubAPIURL: "http://127.0.0.1:1", GitHubRepo: "o/r"}, stub2.Client())
	if _, err := svc.Dispatch(context.Background(), testTrigger()); err == nil {
		t.Fatal("connection error must surface")
	}
}

func TestReactEyes(t *testing.T) {
	stub := newGitHubStub(t, false)
	svc := NewService(Config{GitHubToken: "pat", GitHubAPIURL: stub.URL}, stub.Client())
	if !svc.CanReact() {
		t.Fatal("token mode must allow reactions")
	}
	if err := svc.ReactEyes(context.Background(), Reaction{Repo: "o/r", CommentID: "123", Kind: "issues"}); err != nil {
		t.Fatalf("react: %v", err)
	}
	if stub.lastReaction != "eyes" {
		t.Fatalf("reaction = %q", stub.lastReaction)
	}
	if err := svc.ReactEyes(context.Background(), Reaction{}); err == nil {
		t.Fatal("incomplete reaction target must error")
	}
	if (NewService(Config{}, nil)).CanReact() {
		t.Fatal("no credentials => no reactions")
	}
}

func appKeyPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, string(raw)
}

func TestDispatchGitHubApp(t *testing.T) {
	_, pemKey := appKeyPEM(t)
	stub := newGitHubStub(t, true)
	svc := NewService(Config{
		GitHubAppID: "12345", GitHubAppPrivateKey: pemKey,
		GitHubAPIURL: stub.URL, GitHubWorkflow: "fa-universal.yml", GitHubRef: "main",
	}, stub.Client())
	for i := 0; i < 2; i++ {
		if _, err := svc.Dispatch(context.Background(), testTrigger()); err != nil {
			t.Fatalf("app dispatch %d: %v", i, err)
		}
	}
	if stub.lookups.Load() != 1 || stub.appTokens.Load() != 1 {
		t.Fatalf("installation/token caching broken: lookups=%d tokens=%d", stub.lookups.Load(), stub.appTokens.Load())
	}
	if stub.dispatches.Load() != 2 {
		t.Fatalf("dispatches = %d", stub.dispatches.Load())
	}
}

func TestGitHubAppInstallationOverrideAndBase64(t *testing.T) {
	_, pemKey := appKeyPEM(t)
	stub := newGitHubStub(t, true)
	svc := NewService(Config{
		GitHubAppID: "1", GitHubAppPrivateKey: base64.StdEncoding.EncodeToString([]byte(pemKey)),
		GitHubAppInstallation: "123", GitHubAPIURL: stub.URL,
		GitHubWorkflow: "fa-universal.yml", GitHubRef: "main",
	}, stub.Client())
	if _, err := svc.Dispatch(context.Background(), testTrigger()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if stub.lookups.Load() != 0 {
		t.Fatal("installation id override must skip the lookup")
	}
	if svc.app == nil {
		t.Fatal("base64 PEM must parse")
	}
}

func TestNewServiceBadAppKey(t *testing.T) {
	svc := NewService(Config{GitHubAppID: "1", GitHubAppPrivateKey: "not-a-key"}, nil)
	if svc.app != nil {
		t.Fatal("bad key must disable app mode")
	}
	if _, err := svc.githubToken(context.Background(), "o/r"); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("githubToken = %v", err)
	}
	if _, err := parsePrivateKey("%%%"); err == nil {
		t.Fatal("garbage key must error")
	}
}

func TestDispatchGitLab(t *testing.T) {
	var got map[string][]string
	var status atomic.Int64
	status.Store(http.StatusCreated)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/projects/77/trigger/pipeline" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = r.ParseForm()
		got = r.PostForm
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	svc := NewService(Config{GitLabURL: srv.URL, GitLabProjectID: "77", GitLabToken: "glt", GitLabRef: "main"}, srv.Client())
	backend, err := svc.Dispatch(context.Background(), &Trigger{Provider: "gitlab", SessionKey: "gl-g-p-1", Prompt: "@fa go"})
	if err != nil || backend != "gitlab" {
		t.Fatalf("gitlab = %q, %v", backend, err)
	}
	if got["variables[SESSION_KEY]"][0] != "gl-g-p-1" || got["token"][0] != "glt" || got["ref"][0] != "main" {
		t.Fatalf("form = %+v", got)
	}
	status.Store(http.StatusBadRequest)
	if _, err := svc.Dispatch(context.Background(), &Trigger{Provider: "gitlab"}); err == nil {
		t.Fatal("gitlab error status must surface")
	}
	unconfigured := NewService(Config{}, nil)
	if _, err := unconfigured.Dispatch(context.Background(), &Trigger{Provider: "gitlab", Runner: "gitlab"}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("unconfigured gitlab = %v", err)
	}
}

func TestDispatchBitrise(t *testing.T) {
	var payload struct {
		HookInfo struct {
			Token string `json:"build_trigger_token"`
		} `json:"hook_info"`
		BuildParams struct {
			WorkflowID  string              `json:"workflow_id"`
			Environment []map[string]string `json:"environments"`
		} `json:"build_params"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apps/slug/builds" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	svc := NewService(Config{BitriseURL: srv.URL, BitriseAppSlug: "slug", BitriseToken: "bt", BitriseWorkflowID: "fa-universal"}, srv.Client())
	backend, err := svc.Dispatch(context.Background(), &Trigger{Provider: "bitbucket", SessionKey: "bb-w-r-1"})
	if err != nil || backend != "bitrise" {
		t.Fatalf("bitrise = %q, %v", backend, err)
	}
	if payload.HookInfo.Token != "bt" || payload.BuildParams.WorkflowID != "fa-universal" {
		t.Fatalf("payload = %+v", payload)
	}
	found := false
	for _, env := range payload.BuildParams.Environment {
		if env["mapped_to"] == "SESSION_KEY" && env["value"] == "bb-w-r-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("environments = %+v", payload.BuildParams.Environment)
	}
	unconfigured := NewService(Config{}, nil)
	if _, err := unconfigured.Dispatch(context.Background(), &Trigger{Runner: "bitrise"}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("unconfigured bitrise = %v", err)
	}
}

func TestBackendSelection(t *testing.T) {
	none := NewService(Config{}, nil)
	if _, err := none.Dispatch(context.Background(), testTrigger()); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("no backend = %v", err)
	}
	if _, err := none.Dispatch(context.Background(), &Trigger{Runner: "webhook"}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("unknown runner = %v", err)
	}
	if got := none.backendFor(&Trigger{Provider: "custom"}); got != "" {
		t.Fatalf("empty config backend = %q", got)
	}
	gl := NewService(Config{GitLabProjectID: "1", GitLabToken: "t"}, nil)
	if got := gl.backendFor(&Trigger{Provider: "custom"}); got != "gitlab" {
		t.Fatalf("fallback backend = %q", got)
	}
	if got := gl.backendFor(&Trigger{Provider: "github", Runner: "gitlab"}); got != "gitlab" {
		t.Fatalf("explicit runner = %q", got)
	}
	br := NewService(Config{BitriseAppSlug: "s", BitriseToken: "t"}, nil)
	if got := br.backendFor(&Trigger{Provider: "bitbucket"}); got != "bitrise" {
		t.Fatalf("bitbucket natural backend = %q", got)
	}
	if got := br.backendFor(&Trigger{Provider: "github"}); got != "bitrise" {
		t.Fatalf("first configured fallback = %q", got)
	}
}

func TestGraceAccessors(t *testing.T) {
	svc := NewService(Config{GracePeriod: 5 * time.Second, AlwaysFallback: true}, nil)
	if svc.GracePeriod() != 5*time.Second || !svc.AlwaysFallback() {
		t.Fatal("accessors broken")
	}
	if fmt.Sprint(ErrNoBackend) == "" {
		t.Fatal("sentinel error must have a message")
	}
}
