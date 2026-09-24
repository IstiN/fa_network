package server

import (
	"net/http"

	"github.com/IstiN/fa_network/internal/spec"
)

// serveOpenAPI serves the embedded OpenAPI document — the same commit's
// contract, reachable from any deployed instance.
func serveOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(spec.OpenAPIYAML())
}

// docsPage is Swagger UI bootstrapped from a CDN against /openapi.yaml.
// The UI is static-only; the spec travels with the binary, so the page
// works on every deploy (Cloud Run URL, custom domain, localhost).
const docsPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>fa_network API — Swagger UI</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => window.ui = SwaggerUIBundle({
      url: "/openapi.yaml",
      dom_id: "#ui",
      deepLinking: true,
      persistAuthorization: true,
    });
  </script>
</body>
</html>
`

// serveDocs serves the Swagger UI page (public; UI assets come from CDN).
func serveDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(docsPage))
}
