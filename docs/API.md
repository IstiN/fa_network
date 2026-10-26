# HTTP API

The canonical, machine-readable contract is [`openapi.yaml`](openapi.yaml).
This note calls out the two intentionally different external-agent enrollment
operations.

## Create an independent agent credential

`POST /api/networks/{networkId}/agents/enrollments` with `{"name":"ops-bot"}`
requires the same owner/admin authorization as legacy enrollment. It performs
a master-authenticated signed-hello dap `enroll_create` exchange and returns
`201` with the usual `AgentEnrollResponse`:

```json
{
  "name": "ops-bot",
  "hubUrl": "wss://hub.example/ws",
  "clientSecret": "<returned-once>",
  "enrolledAt": "2026-01-01T00:00:00Z",
  "note": "..."
}
```

Every call creates an **additional** credential. Existing credentials for the
same display name remain valid, so separate agent instances can use separate
secrets simultaneously. fa_network does not store the client secret.

## Legacy enrollment rotates

`POST /api/networks/{networkId}/agents/enroll` keeps its legacy behavior. The
first call enrolls the name; calling it again rotates all hub credentials for
that name and is therefore the revocation path. It is not a substitute for
independent creation.

## Name ownership and compatibility

Agent names have first-come global ownership. The owning network may call
either operation repeatedly; a different network receives `409 conflict` and
cannot create or rotate that name's credentials. Guests and plain members
cannot call either operation.

Older fa_network deployments do not provide `/agents/enrollments`; this mux
answers that POST with `405 Method Not Allowed` and performs no enrollment
mutation. A new fa_network connected to an older dap hub surfaces the legacy
rejection (`bad_frame`, `unknown op enroll_create`) as
`503 hub_unavailable`; it never retries with legacy `enroll`, so an
unsupported create cannot silently rotate
credentials.
