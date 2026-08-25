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

Changes that share SQLite transitions or supervisor behavior may be developed separately, but they are installed only from a validated integration head. Live endpoint cutover, service activation, and migration remain explicit Planner-controlled operations; a pushed branch is not an installation or deployment.

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
