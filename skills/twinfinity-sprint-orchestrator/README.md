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
| Planner source-current profile | `/home/ubuntu/.codex/twinfinity-planner-v3.config.toml` |
| Development source-current profile | `/home/ubuntu/.codex/twinfinity-development-v6.config.toml` |
| SRE source-current profile | `/home/ubuntu/.codex/twinfinity-sre-v6.config.toml` |

Codex profile files follow the official `$CODEX_HOME/profile-name.config.toml` convention and are selected by `--profile profile-name`. The reviewed source catalog targets Planner v3, Development v6, and SRE v6; Planner preserves v2 as its exact direct rollback endpoint, each execution role preserves v3, and v5 alone remains broker-only. Planner v3 uses the read-only `planner-park/v1` protocol described below. A source-catalog target is not evidence that the corresponding profile is installed or that the live pointer has moved. A current runtime launch validates only its exact selected current installed profile. An explicit catalog audit or staged activation boundary uses `executor_registry.py --profile-root <absolute-staged-reference-root> audit-config` and validates the complete catalog without reading or writing live `CODEX_HOME`. Recreate authentication separately on a new machine; never copy secrets into endpoint config, SQLite plans, unit files, archives, or this guide.

### Planner v3 claimed-no-delivery PARK

An ordinary Planner v3 `coordination.notice` remains non-authorizing and read-only. Only the closed claimed-no-delivery PARK schema may request the fixed controller command. The runner removes the raw attempt token and database path from the Codex child, binds the exact Codex/profile/config/managed-hook/controller/source bytes and process identities, pauses heartbeats behind a zero-WAL `BEGIN IMMEDIATE` barrier, and releases the prompt only after the one-use local capability is armed. The actual synchronous nested Bash `PreToolUse` hook must validate the exact raw command and session/turn/tool identity; the controller then reauthenticates, performs two byte-identical current Git/GitHub observations, adopts the capability, and alone opens the writable store for the atomic PARK or official replay.

Missing, duplicate, malformed, expired, replayed, wrong-process, command-drifted, configuration-drifted, or specialized-tool events are terminal `HOLD`. No alternate tool path receives mutation authority. Crash, hook absence/failure, timeout, barrier failure, or denial leaves the PARK target and controller-owned allocation, lease, watch, dirty-event, and release state unchanged. This source protocol never authorizes installing the profile, advancing a live endpoint pointer, or PARKing a live lineage.

## Clean control-plane bootstrap

`scripts/clean_control_plane.py` creates only an explicit nonexisting, noncanonical database. Its closed manifest binds the reviewed source main, registry-declared current-profile hashes and pointers, approved goal, application main and exact GitHub snapshots, capacity authority, optional retained #320 evidence, and an immutable old-database archive digest. `validate` is read-only and manifest-authenticated. Neither command switches the canonical database or starts timers.

Create the candidate in the private coordination root, validate it, then use SQLite backup to place a byte-equivalent candidate under `backups/` for the existing stopped-state `environment_restore_control.py` dry-run/apply seam. That restore keeps the former canonical database and sidecars queryable in its unique forensic directory and rolls filesystem placement back on failure. Do not drop tables or overwrite the old archive.

```bash
python3 scripts/clean_control_plane.py bootstrap \
  --database /home/ubuntu/.codex/twinfinity-coordination/clean-candidate.<id>.sqlite3 \
  --manifest /path/to/reviewed-bootstrap.json \
  --source-root /path/to/reviewed-harness-main \
  --harness-main-sha '<exact-main-sha>'
python3 scripts/clean_control_plane.py validate \
  --database /home/ubuntu/.codex/twinfinity-coordination/clean-candidate.<id>.sqlite3 \
  --manifest /path/to/reviewed-bootstrap.json \
  --source-root /path/to/reviewed-harness-main \
  --harness-main-sha '<exact-main-sha>'
```

The manifest's old-control-plane disposition durably supersedes stranded readiness campaigns 1 and 2 without replaying their attempts or fabricating receipts. Omitting `retained_item` creates no retained work; when supplied, it may bind only #320 with the registry-declared current SRE endpoint, exact source, lease, and registered artifact evidence.

## Source installation atom

`scripts/source_install_atom.py` stages only manifest-listed relative paths, independently verifies the source Git commit and file bytes, verifies destination prior hashes/modes/UIDs/GIDs, and emits rollback data. A separately authorized stopped-state `apply` revalidates the stage under an exclusive destination lock, holds every validated destination-parent descriptor through backup, replacement, postcondition, and recovery, and persists both the parent identity chains and a `PREPARED` recovery journal before the first replacement. After an error or interruption, explicit `rollback` derives each file's exact prior/installed state through those bindings and restores all changed entries; it refuses receipt tampering, parent-identity drift, or any unbound byte, mode, UID, or GID. This is a journaled multi-file install, not a filesystem-atomic transaction or package manager. Reviewed source, staged validation, installation, database replacement, endpoint activation, and timer start remain separate decisions.

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

## Stopped-state READY quarantine before convergence

Do not start either convergence-capable supervisor against historical `READY`
state. After separately authorized source installation, stop every database
writer, prove that no role attempt is active, and take the owner-safe backup
above. Keep the database and a canonical request file beneath the owner-only
coordination root. The quarantine command validates an existing database; it
does not create the database or implicitly install schema.

Perform the cutover in this order:

1. Run the explicit schema-readiness step while writers remain stopped.
2. Read the complete repository-scoped `READY` inventory and retain its
   `inventory_sha256`.
3. Review a canonical request binding that digest, one unique operation key,
   the exact installed and merged harness main, and the applicable cutover
   authority digest.
4. Run `quarantine-unattested-ready` once and retain its complete canonical
   receipt. Exact replay returns that receipt; changed bytes or post-state
   drift return `HOLD` without another transition.
5. Read the inventory again. Every remaining `READY` item must report
   `ATTESTED`; safe invalid lineages are `HOLD/NONE`, have no current
   pull-buffer pointer, and retain their immutable history.
6. Complete routing and installed-runtime attestation. Only then may a
   separately authorized operator start convergence.

From the installed skill root, the schema and inventory commands are:

```bash
pull_buffer=scripts/kanban_pull_buffer.py
repository=twinfinityai/twinfinityapp
/usr/bin/python3 "$pull_buffer" initialize
/usr/bin/python3 "$pull_buffer" ready-quarantine-inventory \
  --repository "$repository"
```

The request file must be UTF-8 canonical JSON with no trailing newline and
exactly these fields (placeholders are not executable values):

```json
{"cutover_authority_sha256":"<64-lowercase-hex>","expected_ready_inventory_sha256":"<inventory-sha256>","operation_key":"<unique-operation-key>","repository":"twinfinityai/twinfinityapp","schema":"twinfinity-ready-quarantine-request/v1","source_harness_main_sha":"<40-lowercase-hex>","source_harness_repository":"jayendusharma/twinfinity-harness"}
```

After placing that reviewed file beneath the coordination root as an
owner-owned, nonsymlink, single-link regular file with exact mode `0600`, run
and read back. The command opens this request nonblocking, verifies its stable
descriptor identity before and after a bounded read of at most 1 MiB plus one
sentinel byte, and rejects a FIFO, device, oversized file, wrong mode, link, or
owner before opening the database:

```bash
request=/home/ubuntu/.codex/twinfinity-coordination/ready-quarantine-request.json
chmod 0600 "$request"
/usr/bin/python3 "$pull_buffer" quarantine-unattested-ready --request "$request"
/usr/bin/python3 "$pull_buffer" quarantine-unattested-ready --request "$request"
/usr/bin/python3 "$pull_buffer" ready-quarantine-inventory \
  --repository "$repository"
/usr/bin/python3 scripts/executor_registry.py \
  --config references/twinfinity-executor-registry.toml audit-config
/usr/bin/python3 scripts/archive_readiness_audit.py
```

The first quarantine invocation uses one `BEGIN IMMEDIATE` transaction across
classification, pointer retirement, item/readiness holds, and the immutable
receipt. It derives validity only from SQLite relationships. A foreign pointer,
stale inventory, row-version drift, any active or retained READY lineage, or any
partial failure rolls the whole operation back. The command never deletes or
rewrites immutable candidates, campaigns, receipts, finalizations, dirty
events, admissions, messages, watches, attempts, or audits. Reserved pre-push
publications and their retained execution lineage are both inventory-bound and
an operation-wide active-lineage fence. Every durable `MESSAGE_CLAIMED` event is
enumerated independently before READY-item classification. A claimed execution
message with a missing link, malformed or duplicate-keyed JSON, missing
identity, conflicting repository or issue identity, or a payload-digest
conflict returns
`READY_QUARANTINE_CLAIMED_MESSAGE_INVALID` before the first durable write,
including when the message is already `COMPLETE` or `HOLD`. None of these source
commands installs files, changes endpoints, manages systemd, runs convergence,
or touches a provider or TwinfinityApp checkout.

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

## On-demand lifecycle and six installed units

Use the repository [installation guide](../../docs/installation.md) for the
manifest-bound dry-run/apply/start/stop flow and the [architecture guide](../../docs/architecture.md)
for role and state ownership. The scripts keep installation separate from
activation and never enable the timers.

The installation uses three oneshot services and three persistent timers under `/home/ubuntu/.config/systemd/user`:

| Unit | Exact installed contract |
| --- | --- |
| `twinfinity-coordination-supervisor.service` | `Type=oneshot`; canonical repository `WorkingDirectory`; `ExecStart=/usr/bin/python3 /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts/coordination_supervisor.py`; `TimeoutStartSec=30`; `After=default.target`. |
| `twinfinity-coordination-supervisor.timer` | `OnBootSec=20s`; `OnUnitActiveSec=30s`; `AccuracySec=5s`; `Persistent=true`; `WantedBy=timers.target`. |
| `twinfinity-hosted-operation-supervisor.service` | `Type=oneshot`; canonical repository `WorkingDirectory`; `ExecStart=/usr/bin/python3 /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts/hosted_operation_control.py supervise`; `TimeoutStartSec=45`; `After=default.target`. |
| `twinfinity-hosted-operation-supervisor.timer` | `OnBootSec=25s`; `OnUnitActiveSec=30s`; `AccuracySec=5s`; `Persistent=true`; `WantedBy=timers.target`. |
| `twinfinity-portfolio-graph-supervisor.service` | `Type=oneshot`; `ExecStart=/usr/bin/python3 /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator/scripts/portfolio_graph_supervisor.py`; `TimeoutStartSec=240`; `After=default.target`. |
| `twinfinity-portfolio-graph-supervisor.timer` | `OnBootSec=90s`; `OnUnitActiveSec=5min`; `AccuracySec=15s`; `Persistent=true`; `WantedBy=timers.target`. |

Treat installed unit files as owner-controlled configuration. On migration,
install their reviewed bodies through the manifest-bound lifecycle, compare
`ExecStart`, timeout, schedule, persistence, owner, and mode, then use
the repository-root `scripts/start.sh` only with separate live-use authority.
It reloads the user manager and starts the three timers without enabling them.
From the reviewed harness source root:

```bash
./scripts/start.sh \
  --manifest /path/to/reviewed-install-manifest.json \
  --source-root /path/to/reviewed/harness-source \
  --destination-root /home/ubuntu
systemctl --user list-timers 'twinfinity*' --all --no-pager
systemctl --user list-units 'twinfinity-role-executor-*' --all --no-pager
```

Do not enable these timers. Stop with `scripts/stop.sh`; a transient executor
that remains active after bounded observation is a truthful nonzero result, not
permission to kill it or fabricate completion.

## Machine migration checklist

1. Stop the six units and all transient role attempts; verify no active attempt or hosted mutation.
2. Validate and back up SQLite with `.backup`; record hashes for the backup, installed skill tree, exact profile files, endpoint config, and six unit files.
3. Transfer the skill, verified backup, required registered artifacts, and nonsecret configuration through an owner-controlled channel.
4. Restore canonical paths, owner, modes, and single-link regular-file invariants. A different home path requires new endpoint versions and reviewed unit bodies.
5. Recreate Codex/GitHub authentication independently; install the Planner, Development, and SRE templates byte-for-byte at their official profile paths and validate their registry-bound digests.
6. Restore SQLite through the staged owner-safe procedure, run integrity and routing audits, and verify current role pointers.
7. Install the six unit bodies, run manual oneshots one at a time, inspect journals and attempt rows, then invoke the reviewed repository-root `./scripts/start.sh`; it starts all three timers without enabling them.
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

## Readiness approval lifecycle

For `APPROVAL_REQUIRED`, the one candidate-phase receipt carries a closed `READINESS` proposal input bound to the authenticated Development or SRE worker endpoint/attempt and the current Planner. The worker stages that immutable input but never submits it or asks the human. After the exact message and attempt are `COMPLETE`, supervisor pickup atomically records the receipt, submits and binds the proposal in the central approval ledger, enters `APPROVAL_PENDING`, and relies only on the proposal-review notice.

After the Planner records the user's decision and the owning-issue outbox publication/readback is `COMPLETE`, the supervisor creates one idempotent exact current-Planner decision notice. Consume it with fresh owning-issue JSON:

```bash
python3 scripts/kanban_pull_buffer.py readiness-apply-decision \
  --message-id '<exact-decision-notice-id>' \
  --planner-session-id '<current-planner-endpoint>' \
  --source '<fresh-owning-issue.json>'
```

The consumer is atomic across message claim/completion, historical role-equivalent approval delivery claim/acknowledgement, source/scope/revocation checks, immutable consumption, and disposition. `APPROVE` derives one deterministic successor from stored state. `REJECT` and `COURSE_CORRECT` enter durable `HOLD`; course correction requires a new materially different proposal. Readiness `DEFER` enters `HOLD` with a strict UTC `AT` revisit trigger and produces one due Planner re-review rather than approving automatically. Generic message claim and caller-authored approval resumes fail closed. Revocations are processed before portfolio convergence, and approval-resumed READY activation rechecks effectivity inside the admission transaction.

## Validation

Run tests only against temporary databases and the source-bound hermetic Codex
home. The runner creates a private temporary `CODEX_HOME`, installs only the
exact versioned profiles declared by the checked-in schema-v2 endpoint catalog,
validates their source and installed bytes through the production loader, runs
discovery, and removes the temporary tree. This is the canonical full-suite
command:

```bash
cd /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator
python3 scripts/run_hermetic_tests.py
```

Pass unittest selectors to the same runner for focused evidence:

```bash
python3 scripts/run_hermetic_tests.py \
  tests.test_executor_registry tests.test_coordination_supervisor
```

Then run the remaining static gates:

```bash
compile_cache=/tmp/twinfinity-sprint-orchestrator-pycompile
PYTHONPYCACHEPREFIX="$compile_cache" python3 -m py_compile scripts/*.py tests/*.py
python3 /home/ubuntu/.codex/skills/.system/skill-creator/scripts/quick_validate.py \
  /home/ubuntu/.codex/skills/twinfinity-sprint-orchestrator
python3 scripts/executor_registry.py \
  --config references/twinfinity-executor-registry.toml \
  --profile-root "$(pwd -P)/references" \
  audit-config
```

Also validate all Markdown links and scan installed Markdown for stale routing and historical executable terminology.

### Self-governing harness baseline

`references/twinfinity-harness-baseline-catalog-v1.json` is the sole ordered
membership authority for the eleven skill validators and the final executor
registry audit. The baseline runner rejects a missing, substituted, duplicated,
or reordered entry and emits a deterministic receipt only after every declared
command returns zero without timing out or exceeding the complete-output bound.
The receipt binds the engine runner, trusted tool root, target byte root,
catalog, command manifest, ordered results, root-relative argument roles,
return codes, bounded complete-output digests, and both root identities.

From a clean exact source candidate, compare immutable accepted-main bytes with
the candidate head and place the owner-local receipt outside the checkout:

```bash
receipt_root="$(mktemp -d /tmp/twinfinity-harness-baseline.XXXXXX)"
chmod 0700 "$receipt_root"
python3 skills/twinfinity-sprint-orchestrator/scripts/run_harness_baseline_validations.py \
  --base-sha '<accepted-main-sha>' \
  --receipt "$receipt_root/source-pair.json"
```

The first catalog landing retains the immutable legacy accepted-base run, then
uses the v1 candidate engine with accepted-base validator and registry-tool
bytes against both the accepted tree and candidate inputs. That bootstrap
exception is explicit in the pair receipt. Once v1 is accepted, the immutable
accepted-base runner and tools validate both the accepted tree and the exact
candidate inputs; the candidate runner and tools separately validate the same
candidate. The pair verifier resolves the accepted commit from fixed
`refs/remotes/origin/main`, resolves the candidate from `HEAD`, and derives
both trees, runner Git blobs, and runner SHA-256 values through scrubbed Git;
caller-asserted base, head, tool-commit, or runner identities cannot select the
trust anchor. The pair verifier requires all three root receipts and their
cross-bindings. Byte-identical base and candidate catalog bytes are mandatory.
Catalog membership changes require a separately reviewed successor contract;
they do not fail open as an ordinary source edit. Pre-push writes the pair to
an owner-only path outside the checkout, reads and verifies it, and binds the
complete canonical receipt and its component digests into exact-head evidence.
Its outer baseline timeout is derived from the complete catalog execution
budget and cannot be shortened by a smaller general pre-push timeout.

Staged-install and installed-runtime validation use runner and validator-tool
bytes from the clean reviewed source commit, never from the target being
attested. The reviewed `twinfinity-source-install-atom/v2` manifest must cover
every catalog input derived from the reviewed source tree, even when a required
file is absent from the target. The validator proves every
manifest source and destination byte, mode, owner, schema-v2 manifest digest,
source commit, and sealed `destination_root_identity`. Schema v1 is rejected.
It also verifies each state receipt's `receipt_sha256` and binds the actual
target directory identity to the sealed manifest. A staged root requires its exact fixed
`.twinfinity-source-install-stage.json`; an installed root requires the
external `INSTALLED` rollback receipt whose destination-parent identities
match the target, and it rejects a staged marker. Unrelated mutable files or
sockets elsewhere in the destination root are outside that finite
manifest-owned byte set. Each state has a separate identity, and neither
receipt can substitute for source evidence or for the other runtime state:

```bash
python3 '<reviewed-source-root>/skills/twinfinity-sprint-orchestrator/scripts/run_harness_baseline_validations.py' \
  --single-root '<staged-root>' \
  --root-kind staged-install-atom \
  --root-identity 'install:<manifest-atom-id>' \
  --tool-root-identity 'git:<reviewed-source-commit>' \
  --install-manifest '<sealed-schema-v2-install-manifest.json>' \
  --installer-evidence '<staged-root>/.twinfinity-source-install-stage.json' \
  --receipt "$receipt_root/staged.json"

python3 '<reviewed-source-root>/skills/twinfinity-sprint-orchestrator/scripts/run_harness_baseline_validations.py' \
  --single-root /home/ubuntu \
  --root-kind installed-runtime \
  --root-identity 'install:<manifest-atom-id>' \
  --tool-root-identity 'git:<reviewed-source-commit>' \
  --install-manifest '<sealed-schema-v2-install-manifest.json>' \
  --installer-evidence '<rollback-root>/rollback.json' \
  --receipt "$receipt_root/installed.json"
```

These commands are validation only. They do not install source, change an
endpoint, mutate SQLite, start a service or timer, or prove that reviewed source
is active.

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
| `attempt_responses_proxy.py` | Dormant credential-free attempt proxy contract, hashed owner ledger, framed relay, Responses request limits, and fail-closed replay states. |
| `executor_registry.py` | Endpoint config, pointers, aliases, attempts, migration ledger, and recovery. |
| `coordination_store.py` | Shared source, item, allocation, lease, inbox, outbox, watch, event, admission, closeout, and artifact transactions. |
| `portfolio_graph.py` / `portfolio_graph_supervisor.py` | Milestone- or issue-set-scoped dependency graph, coverage, collisions, scheduling decisions, refresh, and recovery. |
| `kanban_pull_buffer.py` / `kanban_readiness.py` / `portfolio_convergence.py` | Zero-WIP candidates, one-phase all-gates readiness, bounded resolution, READY binding, dirty events, and atomic successor admission. |
| `approval_ledger.py` / `approval_guard.py` | Material proposal, user decision, delivery, revocation, and execution-effectivity checks. |
| `prepush_control.py` / `delivery_guard.py` | Repository-derived exact-head gate receipts, guarded publication, and native delivery command enforcement. |
| `run_harness_baseline_validations.py` / `twinfinity-harness-baseline-catalog-v1.json` | Fixed ordered validator catalog, accepted-base/candidate comparison, and noninterchangeable source/staged/installed receipts. |
| `hosted_operation_control.py` / `hosted_operation_clearance.py` | Exact SRE provider-operation lifecycle and clearance. |
| `coordination_supervisor.py` | Due work selection, wake ledger, and fresh role-attempt scheduling. |
| `role_executor_transport.py` / `run_role_executor.py` | Target-specific transient systemd transport and attempt process lifecycle. |
| `publish_coordination_outbox.py` | Sparse GitHub publication, idempotency, and exact readback. |
| `reconcile_routing_artifacts.py` / `archive_readiness_audit.py` | Endpoint migration/rollback planning and read-only retirement gating. |
| `environment_rebuild_control.py` | Typed issue-owned environment recovery execution and evidence. |
| `environment_restore_control.py` | Dry-run-first owner-safe coordination SQLite disaster restore and forensic preservation. |
| `issue_body_cas.py` / validators | Provider-atomic body mutation contract and document/control receipt validation. |

Keep dependencies inward toward owner-safe SQLite and focused domain modules. Provider publication, process transport, approval policy, hosted operations, and repository execution remain outside the shared store.

## Routing-deprecation inventory generations

Routing inventories are append-only generations. `preview` binds the promoted
current generation and every fresh scan/source digest; `prepare` inserts the
successor and its idempotent issue-179 outbox envelope without changing routing
authority; `promote` advances the single current pointer only after the exact
COMPLETE comment is read back and all compare-and-swap fences still match.
Superseded generations remain immutable provenance and archive readiness audits
their complete lineage. Legacy-v1 recognition and any owner-database cutover are
separate stopped-state installation work; source validation never performs that
migration or publishes a receipt.
