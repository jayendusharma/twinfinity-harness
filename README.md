# Twinfinity Codex harness

This repository is the versioned source for Twinfinity's Codex skills and its pinned Product Planner goal.

## Layout

- `skills/` mirrors the complete clean source tree under `~/.codex/skills`, including `.system` and all Twinfinity role skills.
- `coordination/product-planner-goal.md` is the pinned durable Product Planner objective.

Generated caches, bytecode, databases, credentials, live receipts, spools, and other machine-local coordination state are intentionally excluded. Runtime state remains in Twinfinity's owner-only SQLite control plane; Git records the reviewed logic and documentation, not live control-plane data.

## Branch model

- `main` is the last reviewed baseline suitable for installation.
- `change/*` branches isolate one bounded coordination behavior and its tests.
- `integration/*` branches combine compatible changes and resolve shared state-machine surfaces.
- `audit/*` branches contain audit-driven documentation or remediation prepared from a fixed integration head.

Changes that share SQLite transitions or supervisor behavior may be developed separately, but they are installed only from a validated integration head. Live endpoint installation, service activation, and database replacement remain explicit Planner-controlled operations; a pushed branch is not an installation or deployment. The reviewed source-catalog target is Planner v2 / Development v6 / SRE v6. Development and SRE v3 remain their exact direct-writer rollback endpoints, v4 is retained historical hardening, and v5 alone remains dormant broker-only readiness hardening.

Reviewed and merged source is not installed or live state. Source maintenance reaches `SOURCE_COMPLETE` only under [the shared harness contract](skills/twinfinity-sprint-orchestrator/references/harness-self-maintenance.md); installation, registration, cutover, and runtime attestation remain separate explicitly authorized operations.

## Safety rules

- Never commit the coordination database, approval contents, live receipts, launch tokens, provider credentials, or worktree-local evidence.
- Preserve exact endpoint/profile hashes and update registry bindings atomically.
- Validate the complete skill set and obtain an independent Governor disposition before promoting an integration branch to `main`.
- Do not resume legacy Codex session UUIDs; every admitted Development or SRE attempt starts through a fresh bounded current role endpoint.

## Validation

Run the complete orchestrator suite through its hermetic source-bound runner:

```bash
python3 skills/twinfinity-sprint-orchestrator/scripts/run_hermetic_tests.py
```

The runner uses a private temporary `CODEX_HOME` populated only with the exact
versioned profiles declared by the checked-in schema-v2 registry; it never
depends on or mutates installed profiles.

Audit the catalog directly from source bytes with:

<!-- source-profile-audit:start -->
```bash
python3 skills/twinfinity-sprint-orchestrator/scripts/executor_registry.py \
  --config skills/twinfinity-sprint-orchestrator/references/twinfinity-executor-registry.toml \
  --profile-root "$(pwd -P)/skills/twinfinity-sprint-orchestrator/references" \
  audit-config
```
<!-- source-profile-audit:end -->
