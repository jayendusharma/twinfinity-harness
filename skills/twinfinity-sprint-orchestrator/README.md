# Twinfinity Product Planner operator guide

This is the concise machine-portability and operator guide for `twinfinity-sprint-orchestrator`. Read [SKILL.md](SKILL.md) for Planner behavior, [references/control-plane.md](references/control-plane.md) for shared delivery invariants, and [references/executor-registry.md](references/executor-registry.md) for endpoint and attempt semantics.

## Prerequisites

- Native Ubuntu under the owner account used by the installed paths.
- Python with `tomllib`, SQLite CLI, Codex CLI, systemd user manager, `systemd-run`, Git, and repository-required Docker/Node tooling.
- The installed Twinfinity skills and one canonical repository checkout.
- Owner-local Codex and GitHub authentication established outside documentation and backups.
- User lingering enabled by an administrator when timers must run without an interactive login.

Verify without changing control state:

```bash
/usr/bin/python3 --version
/home/ubuntu/.local/bin/codex --version
/usr/bin/systemd-run --version
sqlite3 --version
systemctl --user is-system-running
```

## Canonical paths and profiles

| Purpose | Exact path |
| --- | --- |
| Installed Planner skill | `/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator` |
| Development skill | `/home/ubuntu/.codex/skills/twinfinity-development-executor` |
| SRE skill | `/home/ubuntu/.codex/skills/twinfinity-devops-sre` |
| Product Manager skill | `/home/ubuntu/.codex/skills/twinfinity-product-strategist` |
| Governor skill | `/home/ubuntu/.codex/skills/twinfinity-skill-governor` |
| Coordination root | `/home/ubuntu/.codex/twinfinity-coordination` |
| Coordination database | `/home/ubuntu/.codex/twinfinity-coordination/ack-transactions.sqlite3` |
| Canonical repository checkout | `/home/ubuntu/code/twinfinityapp` |
| User unit directory | `/home/ubuntu/.config/systemd/user` |
| Endpoint registry config | `/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/references/twinfinity-executor-registry.toml` |
| Planner installed profile | `/home/ubuntu/.codex/twinfinity-planner.config.toml` |
| Planner portable template | `/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/references/twinfinity-planner.config.toml` |
| Development installed profile | `/home/ubuntu/.codex/twinfinity-development.config.toml` |
| Development portable template | `/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/references/twinfinity-development.config.toml` |
| SRE installed profile | `/home/ubuntu/.codex/twinfinity-sre.config.toml` |
| SRE portable template | `/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/references/twinfinity-sre.config.toml` |

Codex profile files follow the official `$CODEX_HOME/profile-name.config.toml` convention and are selected by `--profile profile-name`. The closed-schema endpoint TOML binds every role endpoint to the SHA-256 of its exact portable template; every config load and attempt requires the installed copy to match byte-for-byte. Planner, Development, and SRE retain distinct role instructions. Planner remains non-coding and accepts only non-authorizing notices; Development and SRE retain mutually exclusive mutating topics. Recreate authentication separately on a new machine; never copy secrets into endpoint config, SQLite plans, unit files, archives, or this guide.

## Owner-safe SQLite backup

The coordination root must be owner-owned mode `0700`. The database and backups must be owner-owned nonsymlink single-link regular files mode `0600`. Quiesce all database-writing timers, services, and transient role attempts before an operator backup:

```bash
systemctl --user stop \
  twinfinity-coordination-supervisor.timer \
  twinfinity-hosted-operation-supervisor.timer \
  twinfinity-portfolio-graph-supervisor.timer
systemctl --user stop \
  twinfinity-coordination-supervisor.service \
  twinfinity-hosted-operation-supervisor.service \
  twinfinity-portfolio-graph-supervisor.service
systemctl --user stop 'twinfinity-role-executor-*'
```

Confirm no `RESERVED`, `LAUNCHING`, or `RUNNING` attempt and no claimed hosted mutation. Then use SQLite backup, not a bare copy of a live WAL database:

```bash
coord_db=/home/ubuntu/.codex/twinfinity-coordination/ack-transactions.sqlite3
backup_root=/home/ubuntu/.codex/twinfinity-coordination/backups
backup_file="$backup_root/ack-transactions.operator-backup.sqlite3"
umask 077
install -d -m 0700 "$backup_root"
sqlite3 -readonly "$coord_db" 'PRAGMA integrity_check;'
sqlite3 -readonly "$coord_db" ".backup '$backup_file'"
chmod 0600 "$backup_file"
sqlite3 -readonly "$backup_file" 'PRAGMA integrity_check;'
sha256sum "$backup_file"
```

Record the backup digest and purpose outside the database without embedding credentials or mutable queue contents.

## Owner-safe disaster restore

Use file restore only after exact authorization, all writers are stopped, and newer coordination state loss is explicitly accepted. Endpoint rollback is the normal routing recovery.

Choose a unique stage path and a unique forensic directory for this one attempt. The helper is dry-run by default: it validates owner/type/mode/link invariants, path and sidecar safety, backup integrity, stopped systemd units, and inactive SQLite attempts, terminal watches, and hosted operations without creating either destination.

```bash
coord_root=/home/ubuntu/.codex/twinfinity-coordination
coord_db="$coord_root/ack-transactions.sqlite3"
backup_file="$coord_root/backups/ack-transactions.operator-backup.sqlite3"
restore_stage="$coord_root/ack-transactions.restore-stage.<unique-id>.sqlite3"
forensic_dir="$coord_root/forensics/operator-restore-<unique-id>"
restore_control=/home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts/environment_restore_control.py
python3 "$restore_control" \
  --database "$coord_db" \
  --backup "$backup_file" \
  --stage "$restore_stage" \
  --forensic-dir "$forensic_dir"
```

Review the exact dry-run paths and backup digest. Apply only with the same arguments and the exact database-bound confirmation:

```bash
python3 "$restore_control" \
  --database "$coord_db" \
  --backup "$backup_file" \
  --stage "$restore_stage" \
  --forensic-dir "$forensic_dir" \
  --apply \
  --confirm "RESTORE:$coord_db"
```

Every dry-run or apply attempt holds an exclusive restore lock on the private coordination directory. Apply stages and verifies the backup first, rechecks every gate, then places the current database and a complete WAL/SHM pair in the new forensic directory before installing the staged database. If any file transition, fsync, or postcondition fails after placement begins, the helper restores and validates the canonical database and every sidecar before returning `HOLD`; it reports `RESTORE_ROLLBACK_FAILED` if that recovery cannot be proven. It never stops or restarts units and never cleans a failed stage or forensic attempt. Any existing destination, symlink, wrong ownership/type/mode/link count, active unit or control row, incomplete sidecar pair, backup sidecar, state drift, or integrity failure is `HOLD`. After restore, run the routing audit and manual supervisor checks before enabling timers.

## Endpoint migration and rollback

Stop writers and take a verified backup. Generate and review the exact routing plan:

```bash
cd /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator
python3 scripts/executor_registry.py \
  --config references/twinfinity-executor-registry.toml audit-config
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml dry-run
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml audit
```

Apply only a reviewed plan digest:

```bash
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml \
  migrate --operation-key '<unique-operation-key>' \
  --expected-plan-sha256 '<reviewed-plan-sha256>'
```

Rollback only the applied routing change:

```bash
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml \
  rollback --change-id '<change-id>' --expected-version '<version>'
```

Rollback preserves immutable endpoint, attempt, message, event, and change history. Stop on pointer, item, watch, or version drift.

## Six installed systemd units and timers

The installation uses three oneshot services and three persistent timers under `/home/ubuntu/.config/systemd/user`:

| Unit | Exact installed contract |
| --- | --- |
| `twinfinity-coordination-supervisor.service` | `Type=oneshot`; canonical repository `WorkingDirectory`; `ExecStart=/usr/bin/python3 /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts/coordination_supervisor.py`; `TimeoutStartSec=30`; `After=default.target`. |
| `twinfinity-coordination-supervisor.timer` | `OnBootSec=20s`; `OnUnitActiveSec=30s`; `AccuracySec=5s`; `Persistent=true`; `WantedBy=timers.target`. |
| `twinfinity-hosted-operation-supervisor.service` | `Type=oneshot`; canonical repository `WorkingDirectory`; `ExecStart=/usr/bin/python3 /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts/hosted_operation_control.py supervise`; `TimeoutStartSec=45`; `After=default.target`. |
| `twinfinity-hosted-operation-supervisor.timer` | `OnBootSec=25s`; `OnUnitActiveSec=30s`; `AccuracySec=5s`; `Persistent=true`; `WantedBy=timers.target`. |
| `twinfinity-portfolio-graph-supervisor.service` | `Type=oneshot`; `ExecStart=/usr/bin/python3 /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts/portfolio_graph_supervisor.py`; `TimeoutStartSec=240`; `After=default.target`. |
| `twinfinity-portfolio-graph-supervisor.timer` | `OnBootSec=90s`; `OnUnitActiveSec=5min`; `AccuracySec=15s`; `Persistent=true`; `WantedBy=timers.target`. |

Treat installed unit files as owner-controlled configuration. On migration, transfer or independently recreate their reviewed bodies, compare `ExecStart`, timeout, schedule, persistence, owner, and mode, then:

```bash
systemctl --user daemon-reload
systemctl --user start twinfinity-coordination-supervisor.service
systemctl --user start twinfinity-hosted-operation-supervisor.service
systemctl --user start twinfinity-portfolio-graph-supervisor.service
systemctl --user enable --now \
  twinfinity-coordination-supervisor.timer \
  twinfinity-hosted-operation-supervisor.timer \
  twinfinity-portfolio-graph-supervisor.timer
systemctl --user list-timers 'twinfinity*' --all --no-pager
systemctl --user list-units 'twinfinity-role-executor-*' --all --no-pager
```

Do not enable timers until the database, exact profiles, endpoint pointers, repository path, unit bodies, and manual oneshot runs validate.

## Machine migration checklist

1. Stop the six units and all transient role attempts; verify no active attempt or hosted mutation.
2. Validate and back up SQLite with `.backup`; record hashes for the backup, installed skill tree, exact profile files, endpoint config, and six unit files.
3. Transfer the skill, verified backup, required registered artifacts, and nonsecret configuration through an owner-controlled channel.
4. Restore canonical paths, owner, modes, and single-link regular-file invariants. A different home path requires new endpoint versions and reviewed unit bodies.
5. Recreate Codex/GitHub authentication independently; install the Planner, Development, and SRE templates byte-for-byte at their official profile paths and validate their registry-bound digests.
6. Restore SQLite through the staged owner-safe procedure, run integrity and routing audits, and verify current role pointers.
7. Install the six unit bodies, run manual oneshots one at a time, inspect journals and attempt rows, then enable timers.
8. Run validation and archive readiness. Do not delete the source installation or archives merely because the destination starts successfully.

## Crash recovery

The supervisors use owner-only nonblocking locks; overlapping invocations exit without adding a writer. SQLite commits survive process failure, but external GitHub and provider effects always require exact readback.

Recover stale attempt states from the skill root:

```bash
python3 scripts/executor_registry.py recover-reserved --older-than-seconds 120
python3 scripts/executor_registry.py recover-active --older-than-seconds 120
```

`recover-reserved` terminally marks eligible pre-launch reservations. `recover-active` requires exact stored systemd unit, invocation, control-group, event-chain, and terminal-state evidence. It never uses age or `/proc` alone and never restarts the old attempt.

Useful read-only checks:

```bash
coord_db=/home/ubuntu/.codex/twinfinity-coordination/ack-transactions.sqlite3
sqlite3 -readonly "$coord_db" 'PRAGMA integrity_check;'
python3 scripts/executor_registry.py \
  --config references/twinfinity-executor-registry.toml audit-config
systemctl --user status twinfinity-coordination-supervisor.timer --no-pager
systemctl --user status twinfinity-hosted-operation-supervisor.timer --no-pager
systemctl --user status twinfinity-portfolio-graph-supervisor.timer --no-pager
journalctl --user -u 'twinfinity-role-executor-*' -n 200 --no-pager
```

Leave ambiguous external effects in readback-only recovery. Never restart the same failed attempt or create a replacement lineage to clear bookkeeping.

## Validation

Run tests only against temporary databases:

```bash
cd /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_executor_registry tests.test_coordination_supervisor
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
compile_cache=/tmp/twinfinity-sprint-orchestrator-pycompile
PYTHONPYCACHEPREFIX="$compile_cache" python3 -m py_compile scripts/*.py tests/*.py
python3 /home/ubuntu/.codex/skills/.system/skill-creator/scripts/quick_validate.py \
  /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator
python3 scripts/reconcile_routing_artifacts.py \
  --config references/twinfinity-executor-registry.toml audit
```

Also validate all Markdown links and scan installed Markdown for stale routing and historical executable terminology.

## Archive gate

Run:

```bash
python3 scripts/archive_readiness_audit.py
```

`PASS` requires valid current endpoint/profile/command contracts, target-unique attempt fencing, and no mutable current item, watch, admission, approval delivery, hosted operation, endpoint command, or frozen GitHub routing inventory dependent on historical routing. A healthy active attempt on its current role endpoint is nonblocking. A pre-cutover, legacy-routed, wrong-endpoint, or otherwise invalid active attempt blocks readiness. Immutable receipts and comments may preserve provenance.

Archive readiness never authorizes deletion. Deleting archives or other data requires a separate exact decision and ownership proof.

## Current module responsibility map

| Module | Responsibility |
| --- | --- |
| `owner_safe_sqlite.py` | Owner/type/mode/link safety and shared SQLite open primitives. |
| `executor_registry.py` | Endpoint config, pointers, aliases, attempts, migration ledger, and recovery. |
| `coordination_store.py` | Shared source, item, allocation, lease, inbox, outbox, watch, event, admission, closeout, and artifact transactions. |
| `portfolio_graph.py` / `portfolio_graph_supervisor.py` | Dependency graph, coverage, collisions, scheduling decisions, refresh, and recovery. |
| `kanban_pull_buffer.py` / `kanban_readiness.py` / `portfolio_convergence.py` | Zero-WIP candidates, one-phase all-gates readiness, bounded resolution, READY binding, dirty events, and atomic successor admission. |
| `approval_ledger.py` / `approval_guard.py` | Material proposal, user decision, delivery, revocation, and execution-effectivity checks. |
| `prepush_control.py` / `delivery_guard.py` | Exact-head gate receipts, guarded publication, and native delivery command enforcement. |
| `hosted_operation_control.py` / `hosted_operation_clearance.py` | Exact SRE provider-operation lifecycle and clearance. |
| `coordination_supervisor.py` | Due work selection, wake ledger, and fresh role-attempt scheduling. |
| `role_executor_transport.py` / `run_role_executor.py` | Target-specific transient systemd transport and attempt process lifecycle. |
| `publish_coordination_outbox.py` | Sparse GitHub publication, idempotency, and exact readback. |
| `reconcile_routing_artifacts.py` / `archive_readiness_audit.py` | Endpoint migration/rollback planning and read-only retirement gating. |
| `environment_rebuild_control.py` | Typed issue-owned environment recovery execution and evidence. |
| `environment_restore_control.py` | Dry-run-first owner-safe coordination SQLite disaster restore and forensic preservation. |
| `issue_body_cas.py` / validators | Provider-atomic body mutation contract and document/control receipt validation. |

Keep dependencies inward toward owner-safe SQLite and focused domain modules. Provider publication, process transport, approval policy, hosted operations, and repository execution remain outside the shared store.
