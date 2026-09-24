package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// rsaKey wraps a test RSA keypair with JWK-friendly accessors.
type rsaKey struct {
	priv *rsa.PrivateKey
}

func newRSAKey(t *testing.T) *rsaKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return &rsaKey{priv: priv}
}

func (k *rsaKey) nBytes() []byte { return k.priv.PublicKey.N.Bytes() }

func (k *rsaKey) eBytes() []byte {
	e := k.priv.PublicKey.E
	var out []byte
	for e > 0 {
		out = append([]byte{byte(e)}, out...)
		e >>= 8
	}
	return out
}
