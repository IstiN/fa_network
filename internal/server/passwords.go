package server

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/scrypt"
)

// scrypt parameters for network join-password hashing (N=32768, r=8, p=1).
const (
	scryptN   = 32768
	scryptR   = 8
	scryptP   = 1
	scryptLen = 32
	saltLen   = 16
	// fastScryptN backs newFastPasswords: the KDF round-trip in tests
	// needs correctness, not cost — ~40x faster than prod N.
	fastScryptN = 1024
)

// Passwords hashes and verifies network join passwords. The work factor
// is fixed at construction so tests can run the cheap variant.
type Passwords struct{ n int }

// NewPasswords returns the hasher with production cost (N=32768, the
// top of the OWASP-recommended scrypt band; ~40ms per call).
func NewPasswords() *Passwords { return &Passwords{n: scryptN} }

// newFastPasswords returns the cheap test hasher (identical round-trip
// semantics, negligible cost).
func newFastPasswords() *Passwords { return &Passwords{n: fastScryptN} }

// Hash derives the stored password hash with a fresh random salt.
func (p *Passwords) Hash(password string) (hash, salt []byte, err error) {
	salt = make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	hash, err = scrypt.Key([]byte(password), salt, p.n, scryptR, scryptP, scryptLen)
	return hash, salt, err
}

// Verify compares a candidate password against the stored hash+salt in
// constant time.
func (p *Passwords) Verify(password string, hash, salt []byte) bool {
	candidate, err := scrypt.Key([]byte(password), salt, p.n, scryptR, scryptP, scryptLen)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(candidate, hash) == 1
}
