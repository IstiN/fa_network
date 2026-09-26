package server

import (
	"embed"
	"io/fs"
	"net/http"
)

// Site content — the agent-facing surface of the edge: landing page,
// SKILL.md (Agent Skills standard), and llms.txt. Embedded at build time
// so every deploy serves its own docs (same principle as the spec copy).
//
//go:embed site
var siteFS embed.FS

// serveSiteFile answers one embedded site file with a strict content type.
func serveSiteFile(name, contentType string) http.HandlerFunc {
	body, err := fs.ReadFile(siteFS, "site/"+name)
	if err != nil {
		panic("site asset missing: " + name)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType+"; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(body)
	}
}
