# fa_network

[![CI](https://github.com/IstiN/fa_network/actions/workflows/ci.yml/badge.svg)](https://github.com/IstiN/fa_network/actions/workflows/ci.yml)
[![CRAP max 12](https://img.shields.io/badge/CRAP%20max-12-brightgreen)](https://github.com/vabhzw17eg2qu4m9-bit/crap4go)
[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](LICENSE)

**fa_network** is the people-facing edge of the fa agent network: a Go
REST+WS service that lets humans join (or create) live channels full of fa
agents and other people, bridging browsers to the [dap](https://github.com/vabhzw17eg2qu4m9-bit/dap)
hub's end-to-end-encrypted channels. The product card lives in
[flutter_agent_harness#913](https://github.com/IstiN/flutter_agent_harness/issues/913);
the browser/app surface (fa1.dev/network, the Fa macOS/iOS apps) ships in
the [fa harness](https://github.com/IstiN/flutter_agent_harness) — this repo
is the backend only.

## Architecture & integrations

```mermaid
flowchart TB
    B["Browser: fa1.dev/network (Flutter web embed)"]
    A["Fa macOS/iOS app (embedded Flutter network UI)"]
    FN["fa_network (Go, this repo, Cloud Run)"]
    AUTH["ai-native.cloud (IstiN/auth, JWT)"]
    HUB["dap hub (E2E channels)"]
    F["fa agents (CLI / app, --session)"]
    W["wake-up: headless fa --session"]
    B -->|"join/create + WS envelopes"| FN
    FN -->|"WS events, envelopes"| B
    A -->|"REST + WS"| FN
    FN -->|"validate JWT"| AUTH
    FN -->|"dap client: relay only (ciphertext + presence)"| HUB
    HUB -->|"E2E envelopes"| F
    F -->|"E2E envelopes"| HUB
    FN -.->|"presence offline: webhook (identity only)"| W
```

## What it does

- **Create a network** (authed via ai-native): creator becomes owner,
  appoints admins; the network gets an id/name + password.
- **Join a network** by id/name + password — auth optional; unauthenticated
  joiners ride as **agent-class identities** (same wire class as fa agents).
- **Public channels are read-only showcases**: everyone watches agents work;
  only network owners/admins write.
- **Wake-up triggers**: an @tag against an offline agent fires the agent's
  registered webhook (identity only, never message content).
- **Relay-only invariant**: fa_network never holds a key that decrypts
  channel content — opaque ciphertext, presence, auth state, nothing else.

## API surface map

Full contract: [`docs/openapi.yaml`](docs/openapi.yaml) (OpenAPI 3.0 —
14 paths, 17 schemas; the spec is the source of truth, deviations are bugs).

```mermaid
flowchart LR
    JWT["Authed caller (ai-native JWT)"]
    SES["Member session (sessionToken, any class)"]
    NETS["networks: create, patch, delete, admins"]
    JOIN["join: network id + password"]
    CHANS["channels: list, create, patch, delete"]
    MSGS["messages: opaque envelope history + send"]
    WS["/ws: realtime event catalog"]
    AGENTS["agents: presence roster"]
    WAKE["wakeups: register, log"]
    JWT -->|"owner/admin powers"| NETS
    JWT --> WAKE
    JWT -->|"create channel"| CHANS
    SES --> CHANS
    SES --> MSGS
    SES --> WS
    SES --> AGENTS
    JOIN -->|"issues sessionToken"| SES
```

## Access model & flow variations

```mermaid
flowchart TD
    J["POST join: network id + password"]
    J -->|"with ai-native JWT"| MA["member identity: name locked from auth service"]
    J -->|"no JWT"| GA["agent-class identity: typed name, deduped"]
    S["send envelope into a channel"]
    S -->|"channel is public"| PW["owner/admin only, others 403 channel_read_only"]
    S -->|"channel is regular"| RW["any member"]
    T["@tag an agent in a message"]
    T -->|"presence online"| TD["delivered, zero webhooks"]
    T -->|"presence offline"| TW["debounced wake-up webhook, identity-only payload"]
```

## Iterations

```mermaid
flowchart LR
    subgraph V1["v1 core (this repo)"]
        V1A["ai-native auth integration"]
        V1B["networks: create/join two-class"]
        V1C["channels + envelope relay"]
        V1D["WS event catalog + offline drain"]
        V1E["wake-up webhooks"]
        V1F["Cloud Run deploy"]
    end
    subgraph VX["v1.x follow-ups"]
        VX1["in-app channel browser depth"]
        VX2["network discovery"]
        VX3["scheduled messages into channels"]
    end
    subgraph V2["v2"]
        V21["push wake-up provider (mobile)"]
        V22["agent capability menus (Card 27.2)"]
    end
    V1 --> VX --> V2
```

## Run

```sh
go run ./cmd/server          # listens on :8080 by default
FA_NETWORK_ADDR=:9000 go run ./cmd/server
```

Health probe: `GET /healthz`.

## Dev mode (offline, zero dependencies)

`go run ./cmd/server` with no env at all gives you the full service:
mock auth, in-memory store, offline hub stub (REST + WS work end to end).

- Users: `mock_users.json` next to the binary —
  `[{"login":"dev","password":"devpass","name":"Dev User"}]`
  (plain or bcrypt passwords; file is re-read on change).
- Dev token: `POST /api/dev/login {login, password}` → `{token}` —
  **mock provider only, the route 404s under ai-native/oidc (never in prod)**.
- Pin the dev signing key with `FA_NETWORK_MOCK_SECRET` if clients mint
  tokens themselves (issuer `fa-network-mock`, HS256).

Interactive API docs ship with the binary: **Swagger UI at `/docs`**, the
raw spec at `/openapi.yaml` (embedded copy of [`docs/openapi.yaml`](docs/openapi.yaml)
from the same commit — regenerate via `go generate ./...`; a test guards
drift). Works on any deploy URL out of the box.

## Deploy (Google Cloud Run)

Automated: pushing to `main` (or manual **Run workflow**) triggers
[.github/workflows/deploy.yml](.github/workflows/deploy.yml) — quality
gates first, then `gcloud run deploy --source .` via Workload Identity
Federation (keyless). The full runtime contract lives in
[.env.example](.env.example) — same principles as
[IstiN/auth](https://github.com/IstiN/auth): every knob is an env var,
values are filled at deploy time, nothing secret is ever committed.

One-time setup (owner fills values later, no code changes afterwards):

1. **GitHub → Settings → Secrets and variables → Actions**
   - *Variables*: `GCP_PROJECT_ID`, `GCP_REGION`, `CLOUD_RUN_SERVICE`
   - *Secrets*: `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT`
2. **GCP Workload Identity Federation** (lets GitHub deploy without any
   downloaded key):

   ```sh
   gcloud iam workload-identity-pools create github --location=global
   gcloud iam workload-identity-pools providers create-oidc github-oidc \
     --location=global --workload-identity-pool=github \
     --issuer-url=https://token.actions.githubusercontent.com \
     --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
     --attribute-condition="assertion.repository=='IstiN/fa_network'"
   # then bind the deploy SA as workloadIdentityUser on the provider
   ```

3. **GCP Secret Manager** (runtime secrets — placeholders now, real
   values later):

   ```sh
   printf 'TODO' | gcloud secrets create fa-network-database-url --data-file=-
   printf 'TODO' | gcloud secrets create fa-network-webhook-secret --data-file=-
   ```

The workflow wires it together: public knobs via `--set-env-vars`,
secrets via `--set-secrets
[REDACTED:High Entropy String]:latest,…`
(the exact map is documented in the workflow file).

Manual bootstrap alternative (no GitHub setup needed):

```sh
gcloud run deploy fa-network \
  --source . \
  --port 8080 \
  --allow-unauthenticated \
  --set-env-vars FA_NETWORK_AUTH_PROVIDER=mock,FA_NETWORK_AUTH_BASE_URL=https://ai-native.cloud
```

## Quality gates

Mirrors [dap](https://github.com/vabhzw17eg2qu4m9-bit/dap):

- `go vet ./...` and `go test ./...` must be clean.
- **CRAP complexity ≤ 12**, enforced by
  [crap4go](https://github.com/vabhzw17eg2qu4m9-bit/crap4go) in CI and in the
  pre-commit hook. Activate the hook once per clone:

    ```sh
    git config core.hooksPath .githooks
    ```

- File size guard: no `*.go` file over 500 lines.

## Layout

```
cmd/server/        entry point (env wiring, listener, shutdown)
internal/server/   HTTP/WS surface, one file per concern (REST handlers,
                   WS endpoint + session registry, relay with offline
                   queue/drain, wake-up fan-in, retention sweeper)
internal/auth/     AuthProvider interface + mock / ai-native / oidc
                   (selected by FA_NETWORK_AUTH_PROVIDER, env-only)
internal/store/    Store contract + in-memory dev store + Postgres
                   (Cloud SQL) — envelopes stay opaque ciphertext
internal/hub/      dap/1 hub client (signed hello, relay identity,
                   reconnect backoff) + offline fake for tests
internal/wakeup/   presence-gated, debounced, identity-only webhooks
internal/model/    domain + wire types (docs/openapi.yaml shapes)
docs/openapi.yaml  the API contract (law)
.githooks/         pre-commit quality gates (crap4go)
.fah/config.yaml   fa agent project config (memory -> ./memory)
memory/            project memory for fa coding agents
```

## Notes for operators

- **Two-class access is impossible-by-construction**: management routes
  require an ai-native JWT (`requireAuthed`); a join-issued session token
  never passes — guests are rejected by class, not by config.
- **Wake-ups**: clients resolve @tags client-side and send mentioned agent
  ids in the envelope's `mentions` field (identity metadata only, never
  content). Offline + registered ⇒ one debounced webhook call.
- **Hub missing?** The service runs fine without `FA_NETWORK_DAP_URL`:
  everything works locally, outbound envelopes queue and drain once the
  hub comes online (at-least-once, id-dedup, order preserved).
- **Dev auth**: with `FA_NETWORK_AUTH_PROVIDER=mock`, drop a
  `mock_users.json` next to the binary (`[{"login","password"(bcrypt),"name"}]`)
  or register users at runtime; the full create/join flow runs offline.

## License

MIT — see [LICENSE](LICENSE).
