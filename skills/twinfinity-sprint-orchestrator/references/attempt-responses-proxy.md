# Dormant experimental attempt-bound Responses proxy foundation

This reference describes the dormant, credential-free foundation in
`scripts/attempt_responses_proxy.py`. It is not installed in a current role
endpoint and does not authorize an upstream API call.
It is not a prerequisite for current registry-selected direct readiness or writer throughput.

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
not the host home. The supplemental mount validator requires six distinct,
canonical, owner-controlled sources under two exact host-authored roots:
read-only repository, contract, and provider configuration mounts plus separate
writable receipt-output, runtime, and private-home mounts. It rejects missing or
duplicate roles, traversal and symlink aliases, wrong destinations or access
modes, writable repository aliases, broad roots such as `/home/ubuntu`, and
sensitive roots including `/etc`, `/proc`, the Codex home, SSH/GnuPG homes, and
the coordination root. A future launcher must consume this validated role map;
it must not construct additional bind mounts from child input.

## Framed transport

The native broker creates an AF_UNIX stream socket pair. Both descriptors are
non-inheritable by default. It explicitly passes one descriptor to a trusted
namespace initializer, which starts a loopback relay inside the isolated network
namespace and closes the descriptor before executing Codex.

The relay holds no provider or coordination credential. It sends a protocol
hello bound to the exact attempt ID, contract digest, endpoint digest, proxy
policy digest, and permit-binding digest. The host compares the supplied binding
to both `proxy.contract` and `proxy.permit` before it reads a request start or
creates a request row. Request and response bytes use bounded, versioned frames.
A binding, version, frame-order, stream-ID, or size mismatch closes the channel
before a request ledger row is created.

The provided loopback function operates only on an already accepted socket. A
future namespace initializer is responsible for bringing up loopback, binding
`127.0.0.1`, hiding the relay from the Codex PID namespace, dropping
capabilities, and passing no relay descriptor to Codex.

## Request policy

Every connection consumes the exact attempt's finite request budget. The proxy
allows only HTTP/1.1 `POST /v1/responses` with one unambiguous content length and
an `application/json` body. JSON objects reject duplicate keys, named
non-finite constants, and finite-syntax exponent overflow such as `1e400` at
every nesting depth. Canonical JSON serialization also rejects NaN and infinity,
so request, tool-schema, policy, and evidence digests cannot normalize a
non-finite value. The top-level request schema is closed to `model`, `stream`,
`input`, optional string `instructions`, `background=false`, `store=false`,
`max_output_tokens`, and the exact contract-hashed `tools` value. Input is
closed recursively to text-only user, system, or developer messages and, only
when the host has already established same-process response lineage,
function-call outputs. Assistant history, item references, hosted media/file
parts, unknown item or content types, and routing-shaped keys at any input depth
are rejected. It also rejects child authorization, cookies, API keys,
OpenAI account or project routing, header smuggling, background execution,
stored responses, response includes, model drift, hosted tools, and
non-streaming requests. Child-controlled conversations, prior-response IDs,
stored-prompt IDs or cache keys, metadata, users, service tiers, and any project,
organization, or lineage routing field are rejected before upstream open.
Hop-by-hop and child metadata headers are not forwarded.

The proxy forwards a canonical body with the exact model, host-authored
same-process response lineage when available, `store=false`, an output-token
ceiling, and at most the function-tool schema whose digest appears in the
contract. Input is conservatively reserved at one token per UTF-8 byte. The
owner ledger enforces request count, concurrency one, body bytes, cumulative
input/output/total tokens, attempt wall time, per-I/O time, SSE idle time, stream
chunk bytes, individual SSE event bytes, and total response bytes.

A successful SSE stream must contain only strict duplicate-free JSON `data:`
events, start with one `response.created`, retain one consistent `resp_*`
lineage ID, and contain exactly one terminal
`response.completed` event with integer input and output usage. Except for one
optional `[DONE]`, comments and duplicate or reordered terminal events are
rejected, as is every event after completion. Completion and `[DONE]` bytes are
withheld until EOF
and usage has passed the durable budget check, so an over-budget response never
reaches the child as semantic success. Only the response-ID digest is retained;
the raw ID remains in owner-process memory solely to author the next request in
that same live attempt.

## Owner-only ledger and recovery

The proxy creates three owner-only SQLite tables for the attempt, requests, and
request transition events. The durable request sequence is:

```text
CREATED -> UPSTREAM_STARTED -> STREAMING -> COMPLETE
        -> SAFE_NOT_SENT
        -> AMBIGUOUS
        -> FAILED
```

The transition graph is closed: terminal requests cannot reopen. The database
stores policy and credential-reference hashes, request and response ID hashes,
bounded counters, structured upstream byte-send evidence digests, controlled
error codes, timestamps, and transition hashes. It never stores request bodies,
prompts, headers, SSE content, raw response IDs, cookies, or credentials.

`SAFE_NOT_SENT` is permitted only after the injected host transport returns and
the ledger durably records exact attempt, permit, request, operation, terminal
error, and zero-byte-send evidence. An exception cannot assert this state. Any
exception after possible forwarding, invalid evidence, truncated or idle SSE
stream, missing completion/usage, or child disconnect is `AMBIGUOUS`; the proxy
enters `HOLD` and the same request is never replayed.
Client and proxy stream retry counts remain zero. A terminal upstream rejection
is `FAILED`; `401` and `403` additionally hold the proxy for credential
resolution.

Crash recovery requires a structured process-terminal receipt bound to the
exact attempt, permit binding, previously registered process identity, terminal
status, and observation time; age or process discovery alone is not an input.
A surviving `CREATED` request receives durable zero-byte recovery evidence and
becomes `SAFE_NOT_SENT`. `UPSTREAM_STARTED` or `STREAMING` becomes `AMBIGUOUS`.
In both cases the old proxy enters `HOLD`; recovery attaches the receipt digest,
is idempotent for that exact receipt, and never restarts or replays the attempt.

Every credentialed upstream open/read/close operation runs in a per-request
spawned host worker process. The worker receives the credential reference but
the sandbox relay does not. It is armed with a parent-death kill guard and owns
the upstream stream for its entire lifetime. An open/read/close deadline kills
the worker, joins it, and verifies a terminal exit code before the proxy returns
`AMBIGUOUS` or `HOLD`; a cancellation callback or acknowledgement is never
accepted as terminal proof. If a killed worker cannot be proven terminal, the
proxy process fails stop instead of returning while credentialed work remains
live. This prevents a broken cancel implementation from sending later when an
old open call is released after the proxy decision.

A future audited transport must be serializable into that spawned worker.
Failure to construct the boundary occurs before credentialed open and fails
closed; the generic relay-only bounded-call helper is never used for credentialed
upstream work.

Inherited-channel read/write, loopback read/write, and accept helpers likewise
use absolute real deadlines. Timeout terminalizes any active request as
`FAILED`, `AMBIGUOUS`, or an already durable `COMPLETE`, and never leaves a
request active for replay. Response forwarding is frame-by-frame with
backpressure; only one bounded SSE event, the bounded terminal pair, or the
explicitly bounded test helper response may be buffered.

The future broker may accept a child receipt only after all proxy requests are
terminal and none is `AMBIGUOUS`. `complete_proxy` is the closed seam for that
later atomic broker integration. This foundation does not claim or complete a
coordination message, reserve or release capacity, terminalize an executor
attempt, install a profile, or change a current endpoint.
