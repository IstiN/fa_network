# Security review — 2026-10-25

Independent read-only review of `main` (16 findings) and the dispositions.
PRs: #11 (WS shutdown), #12 (tenant isolation), #13 (request hardening).

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | Session token not bound to its network | High | **Fixed** (#12): `resolveIdentity` requires `sess.NetworkID == networkID`; read+manage tests. |
| 2 | Cross-tenant agent drop / global tombstone + hub evict | High | **Fixed** (#12): per-network `agent_drops`; unknown id → 404 no-op; idempotent 204; hub evict only for agents enrolled by the same network. |
| 3 | Cross-tenant enroll / secret rotation | High | **Fixed** (#12): first-come `agent_owners` registry (atomic in Postgres); foreign re-enroll → 409. |
| 4 | WS shutdown vs broadcast panic | High | **Fixed** (#11): per-conn `done` + `closeOnce`, `send` never closed; socket close unblocks the writer. |
| 5 | Unbounded JSON bodies, no HTTP timeouts | High | **Fixed** (#13): 1 MiB `MaxBytesReader` on API mutations; `ReadHeaderTimeout` 10s + `IdleTimeout` 120s (no read/write deadlines — would kill WebSockets). |
| 6 | WS sends bypass rate limit + channel byte cap | High | **Fixed** (#13): `wsSendAllowed` shares the REST guards; error frame `throttled`. |
| 7 | Long-lived session bearer in WS `?token=` URL | Medium | **Fixed server-side (2026-11-01):** `POST /api/ws-ticket` mints single-use 60s tickets (rate-limited 30/min/member, consumed even on failed upgrade); `/ws?ticket=` is the documented browser path, `?token=` deprecated but still accepted until clients (app/CLI/site) migrate. Absolute/idle session expiry still worth a follow-up. |
| 8 | Manager-registered wake-up URL → blind SSRF | Medium | **Fixed (2026-11-01):** dial-time egress guard in the wake-up dispatcher (post-DNS `Control` hook: loopback, unspecified, RFC1918/ULA, link-local incl. cloud metadata, multicast, non-TCP all refused — defeats DNS rebinding) and redirects disabled (`ErrUseLastResponse`); registration scheme check kept as fast UX feedback. |
| 9 | Webhook replay / duplicate deliveries | Medium | **Fixed** (#13) for id-bearing deliveries: 24h dedupe after auth, before side effects (`200 duplicate`). Id-less deliveries remain at-least-once (documented); generic provider should send `X-Fa-Delivery-Id`. |
| 10 | Guest promoted to admin → guest token becomes manager | Medium | **Fixed** (#12): guest/agent-class promotion rejected before `network.Admins` update. |
| 11 | Join-password throttle keyed by IP:port | Medium | **Fixed** (#13): stable client IP (XFF first hop behind Cloud Run, `RemoteAddr` host otherwise). |
| 12 | GitLab/Bitbucket bot identities pass the loop filter | Medium | **Fixed** (#13): `_bot`/`_bot_` username forms, Bitbucket `app` actor type; comment-id/delivery dedupe is the second barrier. |
| 13 | CORS allowlist not applied to WS upgrade | Medium | **Fixed** (#13): `AcceptOptions.OriginPatterns = corsOrigins` — also fixes legitimate cross-origin browser upgrades. |
| 14 | Deploy hardening: admin token in env, mutable action tags, unpinned CI tool | Medium | **Fixed** (#13 pinned actions; 2026-11-01 secrets): `FA_NETWORK_DAP_ADMIN_TOKEN` moved to Secret Manager (`fa-network-dap-admin-token:latest`, Cloud Run reads via `--set-secrets`, deploy.yml updated), token **rotated** — old value revoked everywhere (hub VM `HUB_ADMIN_TOKEN` replaced, backup `/etc/dap-hub.env.bak-token-20261101`), GitHub Actions secret deleted. |
| 15 | Dropped agent resurrected by in-flight presence | Low | **Fixed** (#12): per-network tombstone re-checked after store reads, before every broadcast. |
| 16 | Global hub-agent roster + per-member ACL metadata visible to guests | Low | **Fixed (2026-11-01, decision taken):** hub agents project into roster, `/agents`, inbox and `presence.changed` ONLY for the network that enrolled them (`agent_owners`, new `store.NetworkAgentNames`); fail-closed on store errors; unowned agents visible nowhere. openapi contract updated. |

## Extra fix outside the numbered list

- Outbound GitHub API paths: strict `owner/repo` validation of the
  configured slug (#12) — a malformed slug could redirect authenticated
  API calls to a different `api.github.com` path.

## Verified good by the review (no action)

Fail-closed webhook auth (HMAC/bearer, constant-time), 1 MiB webhook body
cap, GitHub App JWT construction + installation token refresh,
`session_key` forwarding in all CI backends, no CI credential logging,
hub eviction URL escaping, relay-only payload custody, identity-only
presence-gated debounced wake-ups, WIF + scoped job permissions.

## Related operational note (not a review finding)

Private-channel DAP agents must receive the **chankey invite** for each
new channel (client-side, E2E DM or shared `~/.dap/channels.json`).
fa_network never holds channel keys (law #1); agents that keygen their
own pair for an unknown channel produce messages clients cannot decrypt.
Enrollment docs already carry this step; automating the invite belongs
to the client/provisioning side.

## 2026-11-01 appendix — same-connection fixes beyond the numbered list

- **Multi-socket same-token fanout loss** (production incident root
  cause, functional not security): `SessionRegistry` keyed a token to a
  single connection — a second socket silently replaced the first in
  fanout maps, and an older closing socket unregistered its replacement.
  Now tokens map to connection SETS with identity-safe removal; all
  fanout paths deliver to every socket. Regressions in
  registry_multisocket_test.go.
- All 16 findings are now closed or consciously deferred (session
  absolute/idle expiry remains a documented follow-up pending client
  reconnect UX).
