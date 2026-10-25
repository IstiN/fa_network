package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// fanet1 is the app's self-describing dap/1 channel frame:
// base64( 0x01 || senderX(32) || nonce(12) || ct||tag ).
// Crypto is exactly dap/1 (mcp-bridge/src/crypto.ts):
// ECDH(sender x25519 priv, channel pub) on send /
// ECDH(channel priv, embedded senderX) on receive,
// HKDF-SHA256(ikm=ecdh, salt=utf8(frameId), info="dap1/v1"),
// AAD "dap1|<frameId>|<channelId>", ChaCha20-Poly1305.
// These helpers are TEST-ONLY: production fa_network never touches keys.

const fanet1Version = 0x01

func fanet1SharedKey(shared, frameID []byte) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, shared, []byte(frameID), []byte("dap1/v1")).Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func fanet1AAD(frameID, channelID string) []byte {
	return []byte(fmt.Sprintf("dap1|%s|%s", frameID, channelID))
}

// fanet1Seal encrypts with a caller-supplied nonce (deterministic vectors).
func fanet1Seal(plaintext, frameID, channelID string, senderPriv, senderPub, channelPub, nonce []byte) (string, error) {
	shared, err := curve25519.X25519(senderPriv, channelPub)
	if err != nil {
		return "", err
	}
	key, err := fanet1SharedKey(shared, []byte(frameID))
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	if len(nonce) != 12 || len(senderPub) != 32 {
		return "", errors.New("bad nonce/sender size")
	}
	ct := aead.Seal(nil, nonce, []byte(plaintext), fanet1AAD(frameID, channelID))
	frame := append([]byte{fanet1Version}, senderPub...)
	frame = append(frame, nonce...)
	frame = append(frame, ct...)
	return base64.StdEncoding.EncodeToString(frame), nil
}

// fanet1Open decrypts with the channel private key + embedded senderX.
func fanet1Open(payloadB64, frameID, channelID string, channelPriv []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", err
	}
	if len(raw) < 1+32+12+16 || raw[0] != fanet1Version {
		return "", errors.New("not a fanet1 frame")
	}
	senderPub := raw[1:33]
	nonce := raw[33:45]
	ct := raw[45:]
	shared, err := curve25519.X25519(channelPriv, senderPub)
	if err != nil {
		return "", err
	}
	key, err := fanet1SharedKey(shared, []byte(frameID))
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	pt, err := aead.Open(nil, nonce, ct, fanet1AAD(frameID, channelID))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

type fanetVector struct {
	FrameID     string `json:"frameId"`
	ChannelID   string `json:"channelId"`
	Plaintext   string `json:"plaintext"`
	Ciphertext  string `json:"ciphertext"`
	SenderPriv  string `json:"senderPriv"`  // hex
	SenderPub   string `json:"senderPub"`   // base64
	ChannelPriv string `json:"channelPriv"` // base64
	ChannelPub  string `json:"channelPub"`  // base64
}

func loadFanetVectors(t *testing.T) []fanetVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/fanet1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []fanetVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 2 {
		t.Fatalf("want 2 vectors, got %d", len(vectors))
	}
	return vectors
}

// Known-answer interop against the REAL dap/1 reference implementation:
// testdata/fanet1_vectors.json was generated AND accepted by
// mcp-bridge/src/crypto.ts open() (generator: testdata/gen-fanet-vectors.mjs).
// Go must reproduce the reference ciphertext byte-for-byte (fixed nonce)
// and decrypt it — in both directions, for an app and a DAP-agent sender.
func TestFanet1KnownAnswerVectors(t *testing.T) {
	for _, v := range loadFanetVectors(t) {
		senderPriv, _ := hex.DecodeString(v.SenderPriv)
		senderPub, _ := base64.StdEncoding.DecodeString(v.SenderPub)
		channelPriv, _ := base64.StdEncoding.DecodeString(v.ChannelPriv)
		channelPub, _ := base64.StdEncoding.DecodeString(v.ChannelPub)
		rawCT, _ := base64.StdEncoding.DecodeString(v.Ciphertext)
		nonce := rawCT[:12]
		// The app frame wraps the reference dap ciphertext with 0x01||senderX.
		wantFrame := base64.StdEncoding.EncodeToString(append(append([]byte{fanet1Version}, senderPub...), rawCT...))

		got, err := fanet1Seal(v.Plaintext, v.FrameID, v.ChannelID, senderPriv, senderPub, channelPub, nonce)
		if err != nil {
			t.Fatal(err)
		}
		if got != wantFrame {
			t.Fatalf("%s: ciphertext mismatch with the dap/1 reference\ngot  %s\nwant %s", v.FrameID, got, wantFrame)
		}
		pt, err := fanet1Open(wantFrame, v.FrameID, v.ChannelID, channelPriv)
		if err != nil {
			t.Fatalf("%s: cannot decrypt reference ciphertext: %v", v.FrameID, err)
		}
		if pt != v.Plaintext {
			t.Fatalf("%s: plaintext = %q, want %q", v.FrameID, pt, v.Plaintext)
		}
		// AAD binds decryption to the ENVELOPE ID: any id rewrite by the
		// relay must break decryption (this is the incident tripwire).
		if _, err := fanet1Open(wantFrame, v.FrameID+"-rewritten", v.ChannelID, channelPriv); err == nil {
			t.Fatalf("%s: decryption must fail under a rewritten frame id", v.FrameID)
		}
		if _, err := fanet1Open(wantFrame, v.FrameID, v.ChannelID[:8], channelPriv); err == nil {
			t.Fatalf("%s: decryption must fail under a different channel id", v.FrameID)
		}
	}
}

func fanet1RandomKeys(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func fanet1RandomNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}
