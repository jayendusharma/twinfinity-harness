# Same-host hosted-operation control

Use `scripts/hosted_operation_control.py` for an authorized provider operation that owns no Git worktree. GitHub supplies the external issue and published-authority facts. SQLite supplies the same-host queue, capacity, claim fence, attempt target, idempotency, and receipt index. The operation runs only through a fresh bounded SRE endpoint attempt using `twinfinity-devops-sre`.

## Authority boundary

Provider access, cloud, deployment, database, IAM, service account, secret, billing, access, traffic, production, shared hosted data, destructive action, private/customer data, and external commitment require exact current user authority for the named read or mutation. A local row or available credential grants none.

Bind one provider, target kind/key, operation kind, expected state, desired state, exclusions, stop conditions, rollback/final-safe state, and authority publication. Stop on any source, authority, target, blocker, capacity, identity, or provider-state drift. Ambiguous external effects enter readback-only recovery and are never blindly retried.

## Transaction lifecycle

1. Refresh the owning issue and published authority into normalized GitHub snapshots.
2. Create an owner-only JSON transaction binding the exact issue digest, authority record/digest, provider tuple, closed scope, current SRE endpoint, declared SRE allocation, optional blockers, exclusions, and stop conditions. Store no credentials or data payloads.
3. Run `hosted_operation_control.py prepare --transaction-file <path>`. A blocked row waits without allocation; an eligible row reserves only the declared allocation allowed by the active immutable SQLite policy.
4. The systemd supervisor revalidates the row and wakes a fresh target-bound SRE attempt. The wake carries no authority.
5. The SRE attempt reads `twinfinity-devops-sre/SKILL.md`, re-fetches the owning GitHub source and authority, resolves the live provider identity and target, and claims the exact row. Drift atomically places it on `HOLD`.
6. Perform only the named operation under the applicable controlled escalation. Capture secret-safe before/after state, abort signals, verification, rollback/final-safe state, and residual risk.
7. Enqueue and publish exactly one `twinfinity.hosted-operation-receipt.v1` owning-issue comment through the SQLite outbox. Bind the operation ID, hashed idempotency key, provider tuple, target key, scope digest, outcome, matching verification state, and compact summary.
8. Complete the hosted row only after exact outbox readback. Success becomes terminal complete; failure or partial effect becomes terminal hold. Release allocation only with the structured receipt.

Post-claim work cannot use a receipt-free hold. A process exit, timeout, or local error is not terminal evidence when the provider may have changed.

## Supported operation classes

The controller supports only explicitly implemented provider/target/operation tuples with closed schemas and tests. Installed classes cover bounded GitHub configuration, environment, billing-budget, and infrastructure-only workflow recovery plus read-only Google Cloud and Supabase metadata inventory.

Add a new tuple-specific schema and tests before supporting another class. Mutations require positive declared SRE allocation and exact published authority; metadata reads declare no writer allocation but still require authorization for the provider access. Total occupancy cannot exceed the active immutable SQLite policy.

## Infrastructure-only workflow recovery

The installed workflow-recovery class is the sole unchanged-head exception and applies only when live provider evidence proves no runner acquired the original attempt, no substantive step ran, no logs or artifacts exist, and every substantive job was skipped under unambiguous hosted-infrastructure provenance.

After the exact user decision is published, use one `scripts/hosted_operation_clearance.py` call. It claims the decision delivery, rebuilds the canonical scope from live GitHub plus native SQLite receipts, compares the approved execution digest, records local acknowledgement, and prepares the hosted row in one idempotent controlled window. Do not serialize these mechanics across model turns or hand-compute derived receipt digests.

Bind the repository, PR, workflow, original provider run and attempt, check suite, exact head/base, final-head local gate, guarded publication, and a later verified provider-capacity restoration receipt. Reserve the unique exact target before calling only the provider's same-run rerun endpoint for the next attempt. Never use a no-op commit, workflow dispatch, Ready toggle, source/PR edit, check recreation, blind transport retry, or second exception. Ordinary exact-head CI and review still control merge.

## Operational checks

```bash
systemctl --user is-active twinfinity-hosted-operation-supervisor.timer
python3 scripts/hosted_operation_control.py show
sqlite3 -readonly /home/ubuntu/.codex/twinfinity-coordination/ack-transactions.sqlite3 \
  'select id,state,provider,target_kind,operation_kind,sre_units,last_error from hosted_operations order by id;'
```

Treat these as read-only diagnostics. Do not expose provider identifiers, sensitive state, or payloads in the result. Never use GitHub comments as the local operation queue or infer authority from the SQLite row.
