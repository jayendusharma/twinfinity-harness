# Attempt-bound Responses proxy foundation

This reference describes the dormant, credential-free foundation in
`scripts/attempt_responses_proxy.py`. It is not installed in a current role
endpoint and does not authorize an upstream API call.

## Activation boundary

The native role broker must call `preflight_before_reservation` before it
reserves capacity or creates an executor attempt. The default activation is
disabled. A missing approved host credential reference produces:

```text
ACTIONABLE_HOLD / BROKER_UPSTREAM_AUTH_UNSUPPORTED
```

An opaque credential reference records the approved credential kind and the
approval digest. It is not a bearer token, key, password, cache path, or secret.
Only a future audited host transport may resolve it. The foundation does not
read a Codex login cache, desktop keyring, environment credential, or provider
secret.

Provisioning or selecting a Platform API project credential, workload identity,
or documented access token remains a material account, billing, IAM, or secret
operation. It requires exact human authority before endpoint activation. A
ChatGPT subscription login cache is not a supported Responses proxy credential.

## Closed child contract

The sandbox child receives:

- an owner-private machine-local `CODEX_HOME` containing one generated
  `config.toml`;
- a read-only attempt contract and repository view;
- the receipt output and runtime directories;
- a loopback-only Responses URL; and
- public attempt, contract, and endpoint identifiers.

It does not receive the coordination root, executor token, provider credential,
credential agent, user D-Bus, SSH agent, auth cache, keyring, general proxy
variables, or a host-network route. The generated provider is exact:

```toml
model = "<contract model>"
model_provider = "twinfinity-attempt-responses"

[model_providers.twinfinity-attempt-responses]
name = "Twinfinity attempt-bound Responses proxy"
base_url = "http://127.0.0.1:<attempt port>/v1"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
stream_idle_timeout_ms = <contract limit>
```

There is no `env_key`, auth command, custom header, or reusable child token.
Project-local configuration is not part of this security boundary. The host
proxy independently enforces the contract even if an admitted subprocess sends
raw HTTP to loopback.

The namespace initializer must tmpfs-mask `/home/ubuntu` and `/run/user/1000`
before Codex starts. `HOME` and the XDG paths point into the attempt runtime,
not the host home. The supplemental mount validator rejects the complete Codex
home, SSH/GnuPG homes, runtime bus, coordination root, secret directories, and
login-cache files even when a caller tries to bind one under an allowed child
destination.

## Framed transport

The native broker creates an AF_UNIX stream socket pair. Both descriptors are
non-inheritable by default. It explicitly passes one descriptor to a trusted
namespace initializer, which starts a loopback relay inside the isolated network
namespace and closes the descriptor before executing Codex.

The relay holds no provider or coordination credential. It sends a protocol
hello bound to the exact attempt ID, contract digest, endpoint digest, and proxy
policy digest. Request and response bytes use bounded, versioned frames. A
binding, version, frame-order, stream-ID, or size mismatch closes the channel
before a request ledger row is created.

The provided loopback function operates only on an already accepted socket. A
future namespace initializer is responsible for bringing up loopback, binding
`127.0.0.1`, hiding the relay from the Codex PID namespace, dropping
capabilities, and passing no relay descriptor to Codex.

## Request policy

Every connection consumes the exact attempt's finite request budget. The proxy
allows only HTTP/1.1 `POST /v1/responses` with one unambiguous content length and
an `application/json` body. It rejects child authorization, cookies, API keys,
OpenAI account or project routing, header smuggling, background execution,
stored responses, response includes, model drift, hosted tools, unknown response
IDs, and non-streaming requests. Hop-by-hop and child metadata headers are not
forwarded.

The proxy forwards a canonical body with the exact model, `store=false`, an
output-token ceiling, and at most the function-tool schema whose digest appears
in the contract. Input is conservatively reserved at one token per UTF-8 byte.
The owner ledger enforces request count, concurrency one, body bytes, cumulative
input/output/total tokens, attempt wall time, and SSE idle time.

A successful SSE stream must contain one consistent `resp_*` lineage ID and a
terminal `response.completed` event with integer input and output usage. Only
the response-ID digest is retained. A later `previous_response_id` is accepted
only when its digest belongs to a completed request in the same attempt.

## Owner-only ledger and recovery

The proxy creates three owner-only SQLite tables for the attempt, requests, and
request transition events. The durable request sequence is:

```text
CREATED -> UPSTREAM_STARTED -> STREAMING -> COMPLETE
        -> SAFE_NOT_SENT
        -> AMBIGUOUS
        -> FAILED
```

The database stores policy and credential-reference hashes, request and response
ID hashes, bounded counters, controlled error codes, timestamps, and transition
hashes. It never stores request bodies, prompts, headers, SSE content, raw
response IDs, cookies, or credentials.

`SAFE_NOT_SENT` is permitted only when the injected host transport proves zero
upstream request bytes were sent. Any exception after possible forwarding,
truncated or idle SSE stream, missing completion/usage, or child disconnect is
`AMBIGUOUS`; the proxy enters `HOLD` and the same request is never replayed.
Client and proxy stream retry counts remain zero. A terminal upstream rejection
is `FAILED`; `401` and `403` additionally hold the proxy for credential
resolution.

Crash recovery requires a hash of positive broker/systemd process-terminal
evidence; age or process discovery alone is not an input. A surviving `CREATED`
request becomes `SAFE_NOT_SENT`. `UPSTREAM_STARTED` or `STREAMING` becomes
`AMBIGUOUS`. In both cases the old proxy enters `HOLD`; recovery is idempotent
and never restarts or replays that attempt.

The future broker may accept a child receipt only after all proxy requests are
terminal and none is `AMBIGUOUS`. `complete_proxy` is the closed seam for that
later atomic broker integration. This foundation does not claim or complete a
coordination message, reserve or release capacity, terminalize an executor
attempt, install a profile, or change a current endpoint.
