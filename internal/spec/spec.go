// Package spec embeds the OpenAPI contract into the binary so a deployed
// service can serve it (and Swagger UI on top of it) without the repo.
// The canonical source of truth is ../../docs/openapi.yaml; regenerate the
// copy with `go generate ./...` and let the drift test keep them honest.
package spec

import (
	"bytes"
	_ "embed"
)

//go:generate cp ../../../docs/openapi.yaml openapi.yaml

// OpenAPI is the embedded copy of docs/openapi.yaml.
//
//go:embed openapi.yaml
var openapi []byte

// OpenAPIYAML returns the embedded OpenAPI document bytes.
func OpenAPIYAML() []byte {
	return bytes.Clone(openapi)
}
