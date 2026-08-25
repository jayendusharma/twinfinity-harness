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

Planner, Development, and SRE use distinct strict Codex profiles. Development and SRE may share only the focused `delivery_guard.py` hook; Planner has no delivery hook and receives only non-authorizing `coordination.notice` work. Every reviewed endpoint, including an executable rollback target, has a versioned portable template named `$CODEX_HOME/<logical-profile>-v<version>.config.toml`. The registry catalog and immutable SQLite endpoint row bind its exact SHA-256 and command manifest. The runner selects that versioned profile from the exact current pointer; it never reloads only the newest singleton role definition. A profile or endpoint cannot grant mutation authority outside the role contract, current user authority, and exact control-plane row.

Changing a role creates a new immutable endpoint version. Advance only that role's current pointer by compare-and-swap. Never edit a persisted endpoint or alias in place.

### Staged strict-profile cutover

The checked-in registry and portable templates are staged cutover inputs, not evidence that live profiles or pointers have moved:

| Role | Staged endpoint | Portable profile SHA-256 | Pointer intent |
| --- | --- | --- | --- |
| Planner | `role.planner.v2` | `38d39166c7573d676206a0f70efd4ebbc68c2d74cd743bab85f48de56b5128cf` | unchanged |
| Development | `role.development.v4` | `96542613dab00abca2a3bcc7e6975025f7b8ed01f610b54ecf23ea6b470c3f18` | additive `role.development.v3` to `role.development.v4` CAS |
| SRE | `role.sre.v4` | `2257302ec8dafb3ad7f45018b28b98e6a120344f0fab1cc9ae81037639edd5e7` | additive `role.sre.v3` to `role.sre.v4` CAS |

The Development and SRE v4 profiles accept exactly two entry classes. The first is an exact current-endpoint, non-authorizing `coordination.notice` for one read-only Kanban-readiness phase with zero writer WIP for that role. The second is the role's exact Planner admission, recovery, terminal-watch wake, or, for SRE, an authorized read-only operational audit. A readiness notice grants no repository, GitHub, provider, admission, tracker, lease, allocation, application, operational-target, or hosted mutation authority. Every mutation still requires its exact role admission and all ordinary authority and safety gates. Legacy aliases, prior endpoints, and resumed Codex threads are not execution routes.

Do not install the staged templates or run migration merely because these artifacts validate. A later authorized cutover must install all five reviewed versioned profile files (`planner-v2`, Development v3/v4, and SRE v3/v4), re-read their digests, build a fresh plan against live SQLite, and compare-and-swap only the Development and SRE pointers from their exact observed v3 rendezvous. Planner stays at v2 unless its bytes or contract change. The v3 files are executable rollback inputs, not new-work routes while v4 is current.

## Dispatch and attempt lifecycle

Module ownership is narrow:

- `coordination_store.py` owns source, item, inbox, outbox, lease, allocation, watch, and event transactions;
- `executor_registry.py` owns endpoints, aliases, current pointers, change ledger, and attempt primitives;
- `coordination_supervisor.py` selects current due targets;
- `role_executor_transport.py` builds the bounded systemd transient-unit invocation; and
- `run_role_executor.py` validates, reserves, launches, heartbeats, and closes one attempt.

For every inbox, terminal-watch, or hosted-operation wake:

1. Revalidate the exact target, topic, role, row state, and current endpoint inside `BEGIN IMMEDIATE`.
2. Reserve one `executor_attempts` row before any process starts.
3. Bind role, endpoint, fresh attempt instance, one-way token digest, target kind/key, state, heartbeat, and optimistic version.
4. Transition `RESERVED -> LAUNCHING` and bind the deterministic target-specific transient-unit name, systemd invocation ID, and control group before process creation.
5. Launch a fresh `codex exec` through the endpoint's immutable command and strict profile.
6. Record the positive child PID only with `LAUNCHING -> RUNNING`.
7. Heartbeat through versioned `RUNNING` updates and finish as `COMPLETE` or `HOLD` with token validation and version compare-and-swap.

Persist only the token digest; pass the raw token only in the child environment. The attempt prompt identifies one exact target and carries no authority beyond that target's ordinary guards.

Active uniqueness is `(role, target_kind, target_key)`. An identical target deduplicates while distinct targets may launch only when their SQLite allocation and the active immutable capacity policy already allow them. Endpoint availability is never a capacity semaphore.

Attempt completion does not complete an inbox item, terminal watch, delivery item, or hosted operation. The fresh attempt must consume the target contract and drive it to its independently verified terminal state or an exact durable `HOLD`.

## Native role execution

The Planner endpoint loads `/home/ubuntu/.codex/twinfinity-planner.config.toml`, must read `twinfinity-sprint-orchestrator/SKILL.md`, remains non-coding, and has owner-local write access only to the coordination root. The Development endpoint loads `/home/ubuntu/.codex/twinfinity-development.config.toml` and must read `twinfinity-development-executor/SKILL.md` before acting. The SRE endpoint loads `/home/ubuntu/.codex/twinfinity-sre.config.toml` and must read `twinfinity-devops-sre/SKILL.md` before acting.

Development and SRE native attempts perform their authorized Git, network, Docker, GitHub, provider, and cleanup work only through their role skill, exact admission, strict topic set, and controlled escalation.

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

## Rollback

Rollback restores only the previous complete current-pointer set and mutable local routing fields captured by one applied version cutover. It preserves endpoints, versioned profile bindings, aliases, attempts, messages, events, change history, and the compatible attempt schema. The initial reviewed cutover cannot roll back to zero pointers or legacy UUID routing.

```bash
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml \
  rollback --change-id '<change-id>' --expected-version '<version>'
```

An exact repeat is idempotent. Pointer, item, watch, profile, endpoint-manifest, or change-version drift is `HOLD`; never force an older value over newer work. After a v4-to-v3 rollback, fresh attempts load the immutable `*-v3.config.toml` profile through a new attempt; no session resumes. File-level SQLite restore is disaster recovery, not endpoint rollback.

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
