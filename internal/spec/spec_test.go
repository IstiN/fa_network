// Drift guard: the embedded spec copy must match the canonical
// docs/openapi.yaml exactly, so /openapi.yaml and Swagger UI always reflect
// the committed contract.
package spec_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/IstiN/fa_network/internal/spec"
)

func TestEmbeddedSpecMatchesCanonical(t *testing.T) {
	canonical, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatalf("read canonical spec: %v", err)
	}
	if !bytes.Equal(canonical, spec.OpenAPIYAML()) {
		t.Fatal("internal/spec/openapi.yaml is stale — run: go generate ./...")
	}
}
