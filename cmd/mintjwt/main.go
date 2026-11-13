// Command mintjwt mints a mock-provider JWT for local repro stands
// (server run with FA_NETWORK_AUTH_PROVIDER=mock and the same secret).
// Dev tooling only: never built into the server image, and the mock
// provider refuses to authenticate against the real auth service.
package main

import (
	"fmt"
	"os"

	"github.com/IstiN/fa_network/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

// mockSecret mirrors the deterministic test secret (testenv_test.go).
const mockSecret = "0123456789abcdef0123456789abcdef"

// mint issues a mock JWT for login with the deterministic test password.
func mint(login string) (string, error) {
	m := auth.NewMockProvider([]byte(mockSecret))
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	m.AddUser(login, string(hash), "Repro "+login)
	return m.IssueToken(login, "secret123")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mintjwt <login>")
		os.Exit(2)
	}
	tok, err := mint(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint:", err)
		os.Exit(1)
	}
	fmt.Print(tok)
}
