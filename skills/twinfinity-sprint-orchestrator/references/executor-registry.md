# Role endpoints and bounded attempts

Use this protocol for Twinfinity endpoint configuration, dispatch, attempt recovery, migration, rollback, and archive readiness. It changes local routing only; [control-plane.md](control-plane.md) remains the authority contract.

## Identity model

Address work to `planner`, `development`, or `sre`, never to a long-lived model thread. Each role has additive immutable endpoint versions and one compare-and-swap current pointer. Endpoint IDs follow `role.<role>.v<version>`.

The endpoint-ID grammar is not identity authority. Public routing resolves only an endpoint in the reviewed current-and-rollback catalog and, once tables exist, its exact immutable SQLite row. Reviewed UUID aliases are accepted only by the private migration/readback path. Public claim and mutation paths require an exact current endpoint and never fail open when pointers are absent.

The current pointer is routing, not authority. It does not change an owning issue, Product Manager decision, approval, capacity, lease, source, branch, worktree, review, release, or provider guard.

Historical endpoint identities and aliases are immutable provenance only. Do not place them in new commands, current pointers, mutable items, active watches, attempts, or current GitHub routing claims. Preserve immutable historical events, messages, decisions, receipts, and comments.

## Configuration and profiles

Load [twinfinity-executor-registry.toml](twinfinity-executor-registry.toml) through `executor_registry.py`. The schema is closed. Reject unknown or missing fields, duplicate endpoint IDs or logical profiles, version/ID mismatch, empty command vectors, historical identity tokens, thread-continuation commands, and overlapping Development/SRE mutating topics.

The installed role contracts are:

| Role | Logical profile | Mutating topics | Entrypoint skill |
| --- | --- | --- | --- |
| Planner | `planner` | none; `coordination.notice` is non-authorizing | `twinfinity-sprint-orchestrator` |
| Development | `development` | `development.*` only | `twinfinity-development-executor` |
| SRE | `sre` | `sre.*` only | `twinfinity-devops-sre` |

Planner, Development, and SRE use distinct strict Codex profiles. Planner has no delivery hook and receives only non-authorizing `coordination.notice` work. The source-current Development and SRE v6 direct profiles retain the focused `delivery_guard.py` hook and support their complete writer topics plus non-authorizing readiness notices. Both v6 profiles add on-request Auto-review for narrowly scoped admitted Git metadata and guarded GitHub or network boundary crossings while keeping `workspace-write`, the existing writable roots, and sandbox network disabled. Every reviewed endpoint has a versioned portable template named `$CODEX_HOME/<logical-profile>-v<version>.config.toml`; the registry binds its exact SHA-256 and command manifest. A runtime launch validates and loads only the exact selected endpoint's installed profile from the reviewed current-and-rollback catalog, then rejects it unless the immutable SQLite row is that role's DB current pointer. The complete installed catalog is required only at an explicit catalog audit, migration, rollback, or staged-activation boundary. Each execution role preserves v3 as its exact direct-writer rollback endpoint; v4 is historical and v5 alone is broker-only. A profile or endpoint cannot grant mutation authority outside the role contract, current user authority, and exact control-plane row.

Changing a role creates a new immutable endpoint version. Advance only that role's current pointer by compare-and-swap. Never edit a persisted endpoint or alias in place.

### Production and staged catalog

The checked-in registry and portable templates are staged cutover inputs, not evidence that live profiles or pointers have moved:

| Role | Endpoint | Portable profile SHA-256 | Status |
| --- | --- | --- | --- |
| Planner | `role.planner.v2` | `38d39166c7573d676206a0f70efd4ebbc68c2d74cd743bab85f48de56b5128cf` | source-current and production current |
| Development | `role.development.v6` | `7822788d1ace463acb48505511e82302dcb317d8aef306506de202236089a145` | source-current direct-writer cutover target; not proof of installation or activation |
| Development | `role.development.v3` | `e75697c80eb2107dbd338ba1d49e9ac47364bb36aa414d99a8aa28145dafc247` | exact direct-writer rollback endpoint |
| Development | `role.development.v4` | registry-bound file | retained historical hardening |
| Development | `role.development.v5` | registry-bound file | dormant broker-only readiness isolation |
| SRE | `role.sre.v6` | `733c2e2cfabd2fd12605d70c24f688b46b4c9b728ed353287fe673ed8ab67a09` | source-current direct-writer cutover target; not proof of installation or activation |
| SRE | `role.sre.v3` | `918c0564b39d28d7776a9b3e4fb7b040b0de2935ad5e8a98099650e6c5ced7f0` | exact direct-writer rollback endpoint |
| SRE | `role.sre.v4` | registry-bound file | retained historical hardening |
| SRE | `role.sre.v5` | registry-bound file | dormant broker-only readiness isolation |

The v5 profiles alone accept the experimental brokered `readiness/v1` behavior implemented in `role_executor_broker.py`. They are preserved for later hardening work, but they are deliberately not install-required or on the production critical path. Writer messages, terminal watches, recovery work, hosted operations, and credential transport remain unimplemented at v5. No current Planner, Development, SRE, readiness, or product-delivery path may depend on them. Development and SRE v6 have no `execution_protocol` and validate as direct writers.

Validate the catalog from source or a staged atom with `executor_registry.py --profile-root <profile-directory> audit-config`. Do not install or activate any endpoint merely because its source artifacts validate. V6 installation and compare-and-swap activation remain separate stopped-state operations for each role; the source catalog preserves the corresponding v3 endpoint for exact rollback. Any future v5 work requires a separate reviewed source change, complete missing mechanics, explicit installation authority, and a fresh pointer decision. Planner stays at v2 unless its bytes or contract change.

### Dormant experimental v5 boundary

The following implementation is retained only as off-path experimental evidence. `run_role_executor.py` delegates a registry-declared `readiness/v1` endpoint to the owner-side broker, but the source-current catalog selects the direct Development and SRE endpoints; installation and live database pointers remain separately attested runtime facts. The broker first proves the exact PREPARED/unclaimed message and unattached campaign, then performs the credential-transport preflight before it may reserve an attempt. Its latent owner mechanics build one canonical input projection from the exact message, GitHub issue snapshot, readiness campaign and gates, graph, candidate, and capacity-policy rows, plus a self-contained reviewed role instruction and exact receipt JSON schema.

The broker-run lifecycle is `PREPARING -> LAUNCHING -> RUNNING -> COMPLETE`; any nonrecoverable boundary failure goes to terminal `HOLD`. A future Bubblewrap child starts behind `--block-fd` and cannot run Codex until one `BEGIN IMMEDIATE` transaction has claimed the exact message, attached the exact readiness campaign, and moved both attempt and broker run to `RUNNING`. Its command policy requires user/PID/IPC/UTS/cgroup namespaces, disabled nested user namespaces, private `/proc`, `/tmp`, `/run`, and `/dev`, no user D-Bus, an empty read-only coordination root, the digest-bound contract/projection/instruction/schema/profile, dropped capabilities, no-new-privileges, and exactly one writable result file. The child has a 1,048,576-byte file limit, 300-second CPU limit, 600-second wall deadline, 64-descriptor ceiling, and stdout/stderr discarded. The complete outer transient attempt is additionally constrained and positively attested at launch by `MemoryMax=2147483648`, `TasksMax=64`, `RuntimeMaxSec=660s`, and aggregate `CPUQuota=100%`; missing, infinite, or changed values fail before reservation. The raw executor token, owner database path, and every credential remain absent. Pre-launch command and cgroup attestation are recorded with the broker transition; real security-boundary availability still depends on the unimplemented credential-free attempt proxy.

Before claim/attach, failure terminalizes only its own attempt and broker rows and never rewrites a foreign claim or prior campaign attachment. After claim/attach, child, deadline, receipt, or binding failure atomically moves the exact message, readiness campaign, attempt, and broker run to `HOLD`, but only after the broker has positively observed the exact child exit or the exact stored systemd invocation inactive. Terminate and kill timeouts preserve `LAUNCHING` or `RUNNING` truth for broker recovery; they never fabricate a terminal row while an evaluator may remain active. Every handler returns authoritative row readback. On success, one transaction stores canonical receipt JSON, digest, and file observation in `role_executor_broker_receipt_pickups`, completes the message and attempt, and marks the broker run `COMPLETE`. The owner then records only those immutable SQLite bytes through `kanban_readiness.record`; `coordination_supervisor.py` consumes any pickup left between those commits. Each pickup is isolated: graph, source, policy, item, campaign, attempt, or endpoint drift durably records one immutable `STALE`, `HOLD`, or `ERROR` disposition and cannot block later pickups or ordinary wakes on the next tick. The filesystem is derived/non-authorizing, and neither API accepts caller-substituted receipt bytes. Generic attempt recovery skips active broker rows; broker recovery owns PREPARING cleanup and identity-exact inactive RUNNING replay/HOLD with race-safe readback.

## Dispatch and attempt lifecycle

Module ownership is narrow:

- `coordination_store.py` owns source, item, inbox, outbox, lease, allocation, watch, and event transactions;
- `executor_registry.py` owns endpoints, aliases, current pointers, change ledger, and attempt primitives;
- `coordination_supervisor.py` selects current due targets;
- `role_executor_transport.py` builds the bounded systemd transient-unit invocation; and
- `run_role_executor.py` validates the current endpoint and selects the endpoint-bound direct or broker protocol; and
- `role_executor_broker.py` exclusively owns v5 readiness reservation, claim/attach, isolation, receipt pickup, message completion, and attempt terminalization.

For every inbox, terminal-watch, or hosted-operation wake:

1. Revalidate the exact target, topic, role, row state, and current endpoint inside `BEGIN IMMEDIATE`.
2. Reserve one `executor_attempts` row before any process starts.
3. Bind role, endpoint, fresh attempt instance, one-way token digest, target kind/key, state, heartbeat, and optimistic version.
4. Transition `RESERVED -> LAUNCHING` and bind the deterministic target-specific transient-unit name, systemd invocation ID, and control group before process creation.
5. Launch a fresh `codex exec` through the endpoint's immutable command and strict profile.
6. Record the positive child PID only with `LAUNCHING -> RUNNING`.
7. Heartbeat through versioned `RUNNING` updates and finish as `COMPLETE` or `HOLD` with token validation and version compare-and-swap.

Persist only the token digest. Runtime-selectable direct endpoints—each role's source-current endpoint and explicit v3 rollback, plus Planner v2—pass the raw token only in the child environment. Historical v4 and broker-only v5 are not runtime-selectable. Brokered v5 readiness keeps the token exclusively in the outer owner process and uses a fixed non-authorizing child prompt.

Active uniqueness is `(role, target_kind, target_key)` plus logical-lineage uniqueness. Planner attempts additionally carry an immutable canonical repository scope with a partial-unique active fence, so one repository has at most one active Planner control attempt while distinct repositories remain independent. The supervisor's per-pass launch policy is four total transport attempts: three base message slots and one terminal-watch reserve. A due eligible watch owns the reserve; otherwise a fourth message may borrow it. One stable FIFO message slot is reserved for the oldest eligible due `INFLIGHT` retry, with the remaining message slots available to fresh work. Unselected rows retain their prior state and retry counters. This transport budget does not consume Development, Shared, or SRE capacity. Endpoint availability is never a capacity semaphore.

Attempt completion does not complete an inbox item, terminal watch, delivery item, or hosted operation. The fresh attempt must consume the target contract and drive it to its independently verified terminal state or an exact durable `HOLD`.

Each reservation records an authoritative target-progress digest and each terminal transition reads it back. A non-authorizing `coordination.notice` digest contains only that exact message's immutable payload binding and lifecycle; changes to a merely referenced delivery item do not count as notice progress. Mutating messages and terminal watches also bind the exact item and generation/lineage watch progress their contracts authorize. Exit zero with an unchanged digest is `EXECUTOR_TARGET_NO_PROGRESS`, not success. After a launcher reports failure, the supervisor re-reads and validates the exact target contract and progress inside the failure-recording transaction before it may exhaust the retry budget. Supervisor wake retries retain a three-attempt budget for identical phase, payload, and progress; authoritative progress resets the budget and keeps the target retryable, while exhaustion without progress moves the exact message or terminal watch to a typed durable `HOLD`.

## Native role execution

The Planner endpoint loads its exact versioned `twinfinity-planner-v2` profile, must read `twinfinity-sprint-orchestrator/SKILL.md`, remains non-coding, and has owner-local write access only to the coordination root. A direct Development or SRE endpoint likewise loads the exact versioned profile bound to its immutable manifest and reads its role skill before acting. A future brokered v5 evaluator receives only the v5 profile, its self-contained digest-bound readiness instruction, the exact receipt schema, and canonical broker inputs inside its private mount tree; it does not receive the mutable generic Development or SRE skill tree.

Runtime-native Development and SRE are limited to each role's source-current endpoint and explicit v3 rollback. Those direct attempts perform authorized Git, network, Docker, GitHub, provider, and cleanup work only through their role skill, exact admission, strict topic set, and controlled escalation. Historical v4 and broker-only v5 cannot be selected for a runtime launch. V5 is the isolated readiness evaluator described above, and all unimplemented target kinds fail closed.

## Crash recovery

If launch fails before a child exists, record `LAUNCH_FAILED`. Do not retry that attempt.

Recover stale pre-launch reservations with:

```bash
python3 scripts/executor_registry.py recover-reserved --older-than-seconds 120
```

This compare-and-swap transitions eligible stale `RESERVED` rows to `LAUNCH_FAILED`. A later current-target wake may create a new attempt after all current guards pass.

For heartbeat-expired `LAUNCHING` or `RUNNING` rows, use:

```bash
python3 scripts/executor_registry.py recover-active --older-than-seconds 120
```

Recovery requires the exact stored target-specific unit, invocation ID, control group, attempt event chain, and positive systemd evidence that the same loaded invocation is terminal. Active, absent, mismatched, ambiguous, or command-failed evidence remains `HOLD`. Do not infer process death from age or `/proc`. Recovery terminally holds the old attempt and never restarts it.

Do not use `systemd-run --collect` for these attempts because failed units must remain inspectable. Resetting a failed unit is a separate operator action after the attempt row is terminal and the exact target has been reviewed.

## Migration and audit

Use the strict endpoint config and the reviewed historical-alias data file. The routing reconciliation command is network-free and does not mutate GitHub, systemd, external configuration, archives, or repository state.

Generate and review a plan:

```bash
python3 scripts/executor_registry.py \
  --config references/twinfinity-executor-registry.toml audit-config
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml dry-run
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml audit
```

Review the plan digest, new immutable endpoint definitions, expected pointer versions, mutable item/watch compare-and-swap set, historical alias mapping, schema transition, and any GitHub body remediation packets. Stop all SQLite-writing timers and active attempts before an authorized live migration.

Apply only the reviewed plan digest with one unique operation key:

```bash
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml \
  migrate --operation-key '<unique-key>' \
  --expected-plan-sha256 '<reviewed-plan-sha256>'
```

The transaction inserts immutable endpoints and aliases, advances current pointers by compare-and-swap, and rewrites only the planned mutable current routing fields. The first pointer ever committed moves the registry monotonically to `CUTOVER_COMPLETE`; the transaction must finish with exactly one role-matched pointer for each role. Thereafter a zero or incomplete pointer set is `HOLD`. If the attempt schema needs expansion, migration refuses active attempts, preserves attempt/event history, and installs target-unique active fencing. Exact operation-key/digest repetition is idempotent; changed bytes or state is conflict.

Already-claimed admissions remain immutable provenance. Runtime continuation may consume a historical endpoint/item-version binding only through an intact canonical `APPLIED` ledger chain that proves every exact same-role pointer, item, and watch hop. It does not make the historical endpoint routable for new work. For the two known old-runtime HOLDs, first run the owner-only store preview with the exact applied change ID/version, repository/issue, admission message ID, watch key, and both current HOLD `updated_at` values; pass its `preview_sha256` unchanged to `apply-endpoint-rotation-admission-rearm`. Exact replay returns the same immutable receipt. Missing proof, an unrelated version bump, a competing attempt, terminal-closeout state, or any envelope/CAS drift fails closed without partial mutation or launch.

## Rollback

Rollback restores only the previous complete current-pointer set and mutable local routing fields captured by one applied version cutover. It preserves endpoints, versioned profile bindings, aliases, attempts, messages, events, change history, and the compatible attempt schema. The initial reviewed cutover cannot roll back to zero pointers or legacy UUID routing.

```bash
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml \
  rollback --change-id '<change-id>' --expected-version '<version>'
```

An exact repeat is idempotent. Pointer, item, watch, profile, endpoint-manifest, or change-version drift is `HOLD`; never force an older value over newer work. An exact execution-role v6-to-v3 rollback restores only that role's pointer and bound mutable routing fields; the other roles remain unchanged, and the next launch loads immutable v3 through a fresh attempt. No session resumes. File-level SQLite restore is disaster recovery, not endpoint rollback.

## GitHub body remediation

Do not rewrite a historical body merely to erase provenance. Freeze the exact current-body inventory and its source digests, classify whether any occurrence still routes actionable work, and publish/read back one secret-safe negative-routing receipt on #179 for the frozen inventory. A body occurrence blocks only while it remains an actionable legacy route, the inventory is incomplete or drifted, or the #179 receipt is missing or contradictory. If a live body truly requires semantic correction, use the separately authorized provider-atomic protocol in [control-plane.md](control-plane.md#issue-body-mutation); never treat archive readiness as authority for that rewrite. Comments remain immutable provenance and are never rewritten.

## Archive readiness

Run the read-only gate:

```bash
python3 scripts/archive_readiness_audit.py
```

`PASS` requires one strict-config-valid current pointer for every role, target-unique attempt fencing, and no mutable item, watch, READY admission, approval delivery, hosted operation, endpoint command, or frozen GitHub inventory dependent on historical routing. Healthy active attempts on current role endpoints are nonblocking. Only pre-cutover, legacy-routed, wrong-endpoint, or otherwise invalid active attempts block. Immutable terminal records and comments may retain provenance.

`PASS` means historical execution identities are unnecessary for current routing. It does not authorize deleting archives or any other data.

## Failure rules

- Stop on config, source, pointer, item, watch, target, token, attempt-version, unit, invocation, control-group, role, profile, topic, or immutable-row drift.
- Never fabricate a current pointer, launch before reservation, persist a raw token, or use a terminal watch outside the attempt ledger.
- Never retry the same failed attempt. A later fresh attempt requires a current target and all ordinary guards.
- Never interpret endpoint or attempt state as product approval, repository authority, hosted authority, capacity, or completion evidence.
- Never run migration, rollback, archive deletion, systemd changes, GitHub mutation, or production-database work merely because a dry-run or local test passes.
