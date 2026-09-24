package hub

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
)

// canonicalJSON marshals with sorted keys and no HTML escaping — the exact
// shape dap/1 signs (docs/protocol.md).
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// frameHash is hex(sha256(canonicalJSON(frameWithoutSigField))).
func frameHash(frame map[string]any) (string, error) {
	raw, err := canonicalJSON(frame)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// sigPayload is "dap1|op|ts|hex(sha256(canonicalJSON(frame)))".
func sigPayload(op string, ts int64, frame map[string]any) (string, error) {
	h, err := frameHash(frame)
	if err != nil {
		return "", err
	}
	return "dap1|" + op + "|" + strconv.FormatInt(ts, 10) + "|" + h, nil
}

// sign signs a frame per the canonical signing payload.
func sign(priv ed25519.PrivateKey, op string, ts int64, frame map[string]any) (string, error) {
	payload, err := sigPayload(op, ts, frame)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, []byte(payload))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// frame is a generic JSON frame with convenient accessors.
type frame map[string]any

func (f frame) str(key string) string {
	s, _ := f[key].(string)
	return s
}

// nonce16 is a fresh 16+ hex nonce.
func nonce16() string {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		for i := range b {
			b[i] = byte(i*17 + 3)
		}
	}
	return hex.EncodeToString(b)
}

// sortedKeys helps deterministic frame construction in tests.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
