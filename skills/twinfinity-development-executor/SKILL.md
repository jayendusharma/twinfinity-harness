---
name: twinfinity-development-executor
description: Execute one fresh bounded Planner-admitted Twinfinity repository delivery attempt from exact claim through implementation, focused tests, applicable final-head local Docker Compose acceptance, guarded push, CI, independent exact-head review, bounded repair, merge, cleanup, terminal receipt, and capacity release. Use only for a current Development admission or terminal-watch wake. Do not plan the portfolio, set product scope, or perform SRE/hosted work.
---

# Twinfinity Development Executor

Execute one exact repository outcome as a fresh bounded Development attempt. Own delivery inside the admitted issue, lease, branch, worktree, authority, and capacity envelope. Return terminal truth to the Product Planner; do not become a second planner.

## Enter through the Development endpoint

Require a current `development.admission`, `development.recovery_commit`, or exact Development terminal-watch wake routed to the current `development` role endpoint. Claim the recipient-fenced SQLite row before the first mutation. Load the strict Development profile and accept only `development.*` mutating topics; never claim `sre.*` work.

For an otherwise exact source-, generation-, lease-, item-, endpoint-, and attempt-bound admission, a missing or stale GitHub `agent-ready` label or textual READY projection is tolerated: those fields are optional display effects, not claim authority. Material source drift still fails closed. Do not repair projection or create a replacement writer merely to make the exact claim succeed; if bounded pre-claim retries exhaust, leave the atomic retained `HOLD` for Planner-only recovery.

An exact non-authorizing `coordination.notice` titled as a Kanban readiness phase may route one read-only candidate assessment to this endpoint without an item allocation, branch, worktree, or lease. Claim its exact row, inspect every listed gate in one bounded phase, and return one consolidated `PASS`, `ACTIONABLE_HOLD`, `APPROVAL_REQUIRED`, or `TERMINAL_HOLD` evidence bundle before completing the message. Close any gate possible through read-only analysis inside the same attempt. Do not mutate the repository, GitHub, providers, or SQLite delivery state beyond the exact claim/completion and receipt; do not consume writer capacity; and do not create a message or hand-off per gate. `ACTIONABLE_HOLD` names one Planner-owned resolution bundle. `APPROVAL_REQUIRED` is only for a genuine material decision.

Treat every launch as ephemeral. Historical identities are provenance only. Endpoint and attempt identity route work but do not grant product, repository, GitHub, provider, or release authority.

Read and apply, without duplicating them:

- [the delivery control plane](../twinfinity-sprint-orchestrator/references/control-plane.md);
- [role endpoints and ephemeral executors](../twinfinity-sprint-orchestrator/references/executor-registry.md);
- [issue-owned environment isolation and terminal cleanup](../twinfinity-sprint-orchestrator/references/environment-isolation.md); and
- [exact-head UI evidence](../twinfinity-sprint-orchestrator/references/ui-evidence.md) when rendered pixels or interaction change.

Use GitHub for external issue/PR facts, authority publication, collaboration, CI/review evidence, and audit. Use the owner-only SQLite store for same-host queue, claim, capacity, lease, attempt, watch, acknowledgement, guarded-publication, and terminal state. Never use GitHub comments as a local queue or acknowledgement channel.

For a harness-repository maintenance admission, also read [the source self-maintenance contract](../twinfinity-sprint-orchestrator/references/harness-self-maintenance.md). The fresh current direct Development writer may prepare one source branch and PR, but may not self-review, merge, install, cut over, or claim that reviewed source is live.

## Revalidate the exact admission

Before editing:

1. Read the owning issue's rendered body, current controls, parent and dependency facts, exact PR when present, and live main/head/check/review state.
2. Read root and relevant nested `AGENTS.md` plus `docs/development/`.
3. Revalidate the SQLite source digest, item generation/version, active policy, allocation, exact endpoint/attempt, claim state, branch, worktree, opaque worktree ID, lease manifest, and terminal watch.
4. Confirm the exact base, local and remote head, clean/preserved worktree state, closed changed-path set, collision proof, issue-owned toolchain, and required evidence map.
5. Freeze the smallest maintainable outcome map: every changed path, abstraction, support helper, and test group must map to the owning issue or a named safety invariant.

Any source, authority, scope, base, head, branch, worktree, lease, capacity, recipient, profile, dependency, or collision drift is `HOLD`. Preserve user-owned changes and do not create a replacement lineage, broaden scope, steal a lease, or fall back to GitHub coordination chatter.

## Deliver the admitted outcome

1. Create or use only the admitted issue-owned `codex/<issue>-<slug>` branch and sibling worktree. Never work from the canonical checkout or another issue's environment.
2. Implement the smallest complete outcome with existing primitives. Do not absorb adjacent debt, speculative frameworks, customer-specific runtime code, or unrequested product behavior.
3. Map each Gherkin scenario and safety invariant to the lowest useful focused evidence. Keep providers offline and data synthetic by default.
4. Run the complete affected focused gates from the exact issue-owned environment. Record tool provenance, commands, results, and generated-file cleanliness.
5. Commit the bounded change locally. For every applicable application or workflow final head, run the shared pre-push controller's full local Docker Compose acceptance and verify exact owned-resource cleanup. Earlier-head, static-only, unit-only, or sandbox Docker results do not substitute.
6. Publish only with `scripts/prepush_control.py guarded-push` after its exact-head PASS receipt. Raw `git push`, hook bypass, alternate publication, no-op commits, and unchanged-head CI reruns are prohibited.
7. Open or update the bounded draft PR, preserve the exact issue contract, and wait for natural CI and the configured review path. Bind every acceptance decision to the exact head.
8. Commission an independent exact-head reviewer. Resolve material findings and threads through at most one normal bounded same-failure-class repair cycle, then rerun affected final-head evidence and guarded publication.
9. Merge only when the admission authorizes routine merge, required exact-head CI is terminal green, independent review accepts, material threads are resolved, evidence remains current, and no newer product or Planner control blocks it.
10. After terminal cleanup, call `prepare-terminal-closeout` with the exact receipt, cleanup, source/graph, and owning-issue publication packet. Preparation moves the item to `PUBLICATION_PENDING` but deliberately retains the claimed admission, active watch, lease, allocation, and all role/shared capacity. Publish the one GitHub-safe owning-issue receipt through the SQLite outbox and prove its exact marker/readback. Only then call `commit-terminal-closeout`; that final transaction completes the item/watch/admission and releases the lease, allocation, and capacity before handing the delta to the Product Planner. If publication or readback is incomplete, remain `PUBLICATION_PENDING` and let a fresh exact terminal-watch attempt continue the same packet.

A successful local gate, guarded push, PR update, or draft-safe review is intermediate progress, not completion. Continue the admitted routine chain while the exact terminal watch remains current and no hard stop exists.

## Keep native and sandbox permissions separate

The fresh Development endpoint is the accountable native executor. It performs authorized native Git, GitHub, package/network, Docker/Compose, and cleanup operations under the exact admission and shared guards.

When admitted Git metadata or guarded GitHub/network publication crosses the `workspace-write` sandbox boundary, request one narrowly scoped Auto-review escalation for that exact command. The first protected-path or sandbox-network denial is a capability signal, not by itself a delivery `HOLD`. The escalation grants no new authority: keep the delivery guard active and remain fenced to the exact admission, branch, worktree, lease, and guarded controller. Raw `git push`, canonical-checkout edits, out-of-lease paths, unrelated worktrees, broad sandbox/network bypasses, and unchanged retries remain prohibited.

Sandbox children may inspect and patch only their exact owner-local workdir and run deterministic offline checks. They must not claim coordination rows, use Docker or container runners, access GitHub or providers, run outbound Git, download packages or artifacts, or perform cleanup. When useful, require a child to return a literal bounded native-host packet; independently verify it before execution. Sandbox failure never diagnoses native network, credentials, Docker, or provider state.

## Stop at material or operational boundaries

Stop the affected mutation and return a concise proposal to the Product Planner when work requires:

- application/domain behavior or user-visible UX beyond the admitted contract;
- persistent schema/data semantics, public/generated contracts, or authorization/privacy/security/tenant-isolation changes not already exactly authorized;
- a destructive or difficult-to-recover action;
- deployment, hosted provider, cloud, IAM, secret, billing, access, traffic, production, or release work;
- customer/private data or an external commitment;
- a changed diagnosis or scope, out-of-lease repair, new collision, missing evidence, or non-converging repair; or
- any direct user decision.

Only the Product Planner asks the user for approval and creates a fresh or superseding admission. Continue safe read-only analysis and preserve the current lineage, but do not solicit approval directly, retry unchanged work, or convert an SRE boundary into Development scope.

## Close the attempt

The terminal owning-issue receipt must bind the issue and PR, exact public head, delivered scenarios, focused and final-head Compose evidence, guarded publication, natural CI, independent review, repair disposition, merge or safe HOLD state, cleanup categories and verdict, capacity/lease release, residual risks, and next Planner action. Keep exhaustive local paths and hashes owner-local and publish only the validated GitHub-safe projection. Preparing or publishing this receipt is not terminal completion: exact publication readback and `commit-terminal-closeout` are required before reporting capacity or lease release.

Do not update #44, #61, #120, #131, or #179 unless an exact narrower Planner instruction names that mutation. End the attempt after terminal receipt and capacity release, or at a durable `HOLD` with preserved evidence and an exact blocker. Later work requires a fresh current endpoint attempt.
