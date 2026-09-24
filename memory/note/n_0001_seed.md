# fa_network — project seed

- What: Go REST+WS edge (`IstiN/fa_network`, Cloud Run) bridging people
  (fa1.dev/network web embed, Fa macOS/iOS app embed) to dap's
  E2E-encrypted channels. Parent card flutter_agent_harness#913; build
  spec fa_network#1; `docs/openapi.yaml` = source of truth for the API.
- Invariants (owner rulings): relay-only (never a decryption key —
  ciphertext-only in stores/logs/RAM, proven by test); two-class access
  (create/manage = ai-native JWT, join = network id+password auth-optional,
  guests = agent-class identities, name locked for authed joiners); public
  channels read-only showcases (write = owners/admins only); wake-up
  webhooks identity-only, presence-gated, debounced.
- Gates: go vet + go test green, crap4go ≤ 12 (pre-commit via
  `git config core.hooksPath .githooks`), no *.go over 500 lines.
- Gotcha: cached git credential (uladzimir-klyshevich-epam) has 403 on this
  repo — push via one-off gh token URL (see AGENTS.md).
