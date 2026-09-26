package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IstiN/fa_network/internal/spec"
)

func TestServeOpenAPI(t *testing.T) {
	rec := httptest.NewRecorder()
	serveOpenAPI(rec, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.Bytes(); string(got) != string(spec.OpenAPIYAML()) {
		t.Fatalf("body diverges from embedded spec (%d vs %d bytes)", len(got), len(spec.OpenAPIYAML()))
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Fatalf("Content-Type = %q, want yaml", ct)
	}
}

func TestServeDocs(t *testing.T) {
	rec := httptest.NewRecorder()
	serveDocs(rec, httptest.NewRequest(http.MethodGet, "/docs", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	for _, want := range []string{"SwaggerUIBundle", `url: "/openapi.yaml"`, "swagger-ui.css"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("docs page missing %q", want)
		}
	}
}

func TestDocsRoutesMounted(t *testing.T) {
	env := newTestEnv(t)

	for _, path := range []string{"/docs", "/openapi.yaml"} {
		rec := env.do(http.MethodGet, path, nil, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

func TestSiteSurface(t *testing.T) {
	env := newTestEnv(t)

	cases := []struct {
		path        string
		contentType string
		needle      string
	}{
		{"/", "text/html", "SKILL.md"},
		{"/SKILL.md", "text/markdown", "Agent quickstart"},
		{"/skill.md", "text/markdown", "Agent quickstart"},
		{"/llms.txt", "text/plain", "# fa_network"},
	}
	for _, tc := range cases {
		rec := env.do(http.MethodGet, tc.path, nil, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", tc.path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tc.contentType) {
			t.Fatalf("GET %s Content-Type = %q, want %s", tc.path, ct, tc.contentType)
		}
		if !strings.Contains(rec.Body.String(), tc.needle) {
			t.Fatalf("GET %s missing %q", tc.path, tc.needle)
		}
	}
}
