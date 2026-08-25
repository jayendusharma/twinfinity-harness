# Dependabot reconciliation

Use this workflow for the full live Dependabot queue, not just the newest or greenest pull request.

## Build the current inventory

At the start of a bounded reconciliation attempt and after accepted main moves:

1. List every open bot-authored dependency PR, its labels, ecosystem/directory, dependency family, old and new versions, base/head, changed paths, draft state, mergeability, reviews, threads, and checks.
2. Include `area:devops` PRs in the SRE maintenance portfolio. Record unlabeled or mislabeled bot PRs separately and route by actual impact rather than label alone.
3. Compare each PR with current accepted main and active Development/SRE leases and attempts. A stale-base green run is historical evidence only.
4. Group collisions so only one PR may mutate a given manifest, lockfile, workflow, container reference, runtime, database generation, provider SDK family, or compatibility surface at a time.
5. Reconcile the owning maintenance issue or durable queue record whenever a PR opens, closes, merges, is superseded, changes head/base, or moves between classifications.

## Classify every PR

Give every open PR exactly one current disposition:

- **SAFE CANDIDATE:** bounded routine update with understood compatibility, current-main convergence, no material application boundary, and a complete focused validation plan.
- **REPAIRABLE SRE:** maintenance-owned update whose failure is confined to manifests, lockfiles, workflows, container references, operational configuration, tests, or documentation. Freeze a bounded lease before repair.
- **HOLD:** insufficient compatibility evidence, stale/conflicting base, unsupported target, failed gate, coupled dependency family, or predecessor required.
- **TRANSFER / FOLLOW-UP ISSUE:** the update can change application behavior, UX/navigation, persistent schema/public contracts, authorization/privacy/security policy, provider semantics, or a broad core framework/runtime. Create a size-S/M owning issue with impact surface, acceptance evidence, rollback, and explicit non-goals; route it to the Product Planner for a fresh Development admission.
- **CLOSE / SUPERSEDE:** obsolete, duplicate, unsafe target, replaced dependency, or proposal that should be regenerated from current reviewed configuration. Preserve the reason durably.

Major-version or core-component updates are never automatically safe. Evaluate direct and transitive breaking changes, runtime and platform support windows, repository imports/usages, generated artifacts, build/test tooling, deployment workflow behavior, data/migration compatibility, security advisories, and rollback. Examples include React and routing, TypeScript/build tools, Python or Node runtimes, PostgreSQL, GitHub Actions used for deployment/authentication, AI/provider SDKs, and grouped packages spanning multiple ownership boundaries.

## Safe-merge gates

A SAFE CANDIDATE may merge routinely only when all are true:

- exact current head/base and changed-file inventory are frozen and converge on current accepted main;
- the diff is limited to the classified dependency surface and contains no generated, application, workflow, or configuration surprise;
- upstream release and migration guidance supports the repository's runtime/platform versions;
- vulnerability and compatibility impact, including transitive changes, is understood;
- focused install/import/build/runtime or container tests cover the dependency's real repository use, not merely unrelated CI;
- natural exact-head CI is terminal green, required generated-contract checks are current, independent review accepts, and unresolved thread count is zero;
- no active lease or sibling dependency-family candidate collides;
- rollback is the ordinary reviewed revert or pinned prior version, with no hosted migration/deployment implied;
- the merge is non-deploying and terminal branch/worktree/cache cleanup plus an owning-issue receipt follow.

If any gate fails, reclassify rather than forcing, weakening, skipping, or using legacy-resolution flags.

## Capacity and sequencing

Read the current immutable SRE ceiling from SQLite. It remains separate from the product Development/Shared tier defined in the sprint orchestrator's adaptive capacity policy. Passive bot PRs and read-only inventory consume zero capacity. A PR begins consuming its declared SRE capacity when a fresh endpoint attempt claims the admitted rebase/repair/review/merge lineage; it releases only after merge or safe closure, terminal cleanup, owning-issue receipt, and SQLite release.

Prioritize in this order unless a live security or reliability risk changes it:

1. exploitable security fixes with bounded compatibility;
2. supported patch/minor maintenance with direct test coverage;
3. repairable CI/workflow/container maintenance;
4. deliberate major/core migrations through their own issues;
5. obsolete or unsupported proposals for closure/supersession.

Do not run two updates concurrently when they alter the same dependency family or when one changes the runtime used to validate the other.

## Durable receipt

Record a concise queue reconciliation containing:

- accepted-main SHA and observation time;
- complete open bot PR inventory and one disposition per PR;
- selected active SRE attempts and current-policy capacity before/after;
- exact safe-merge candidates and their missing gates;
- follow-up issues/transfers for core or application-impacting updates;
- merges/closures performed, exact heads, CI/review/thread evidence, and cleanup;
- explicit confirmation that no deployment, provider, hosted database, IAM/secret, traffic, production, or private-data action occurred.
