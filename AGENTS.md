# fa_network — Agent Guide

Go REST+WS edge service: the people-facing bridge between browsers/apps and
the dap hub's E2E-encrypted channels. Product card:
[flutter_agent_harness#913](https://github.com/IstiN/flutter_agent_harness/issues/913);
build spec: [issue #1](../issues/1); **API contract:
[`docs/openapi.yaml`](docs/openapi.yaml) is law — deviations are bugs, and
endpoint/schema changes land in the spec in the same commit.**

## Laws (owner-set)

1. **Relay-only.** fa_network never holds a key that decrypts channel
   content. Ciphertext-only in stores, logs, and RAM — a test proves it.
2. **Two-class access.** Create/manage routes require an ai-native JWT
   (github.com/IstiN/auth, dmtools-compatible). Join takes network
   id/name + password with auth OPTIONAL: authed joiners carry a locked
   auth-service name; guests ride as agent-class identities. No management
   route accepts a guest token — impossible-by-construction.
3. **Wake-ups are identity-only.** The webhook payload carries the target
   agent identity, never message content; dispatch is presence-gated and
   debounced.
4. **Public channels are showcases.** Read for every member; write for
   network owners/admins only (`403 channel_read_only` otherwise).

## Quality gates (pre-commit + CI, never `--no-verify`)

- `go vet ./...` clean; `go test ./...` green.
- **CRAP ≤ 12 per function** — `./bin/crap4go --run-tests --threshold 12 .`
  (pre-commit enforced once `git config core.hooksPath .githooks` is set).
- File size guard: no `*.go` file over 500 lines.

## Environment

Go ≥ 1.22. Once per clone:

```sh
git config core.hooksPath .githooks
mkdir -p bin .tools
git clone --depth 1 https://github.com/vabhzw17eg2qu4m9-bit/crap4go .tools/crap4go
(cd .tools/crap4go && go build -o ../../bin/crap4go .)
```

Push note: the cached git credential may lack write access to this repo
(403). If so, push with the gh token one-off:
`git push "https://x-access-token:$(gh auth token)@github.com/IstiN/fa_network.git" HEAD:main`.

## Test conventions

Deterministic offline, no sleep-sync: `httptest` for HTTP; a fake dap hub
(WS server stub) and a fake ai-native auth provider for integration tests;
deadline reads on WS assertions; ciphertext-only property test over captured
store state.

## References

- dap hub + wire contract: https://github.com/vabhzw17eg2qu4m9-bit/dap (`docs/protocol.md`)
- auth service: https://github.com/IstiN/auth (deploy https://ai-native.cloud)
- Flutter network UI (three hosts): flutter_agent_harness repo, `flutter_app` + `site/`
