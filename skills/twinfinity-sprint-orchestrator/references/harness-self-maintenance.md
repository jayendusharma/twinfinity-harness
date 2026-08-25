# Harness source self-maintenance

Use this contract only to maintain the versioned Twinfinity Codex harness repository. It authorizes no installed-skill, live-goal, endpoint, broker, control-plane, GitHub-configuration, provider, or hosted mutation. Keep the source lane distinct from installation and runtime activation.

## Preserve one bounded lane

Run at most one active harness-maintenance lane. Charge it to Shared writer WIP, reserve one exact `change/*` branch and sibling worktree from a fetched starting-main SHA, and reject collisions with any open branch, pull request, lease, or changed path. Re-fetch exact main, open branches, open pull requests, and collisions at each decision boundary; cached or chat-only state is insufficient.

Keep the workflow coarse:

`DETECTED -> BRANCH_RESERVED -> AUDITED -> VALIDATED -> GOVERNOR_APPROVED -> PR_OPEN -> MERGE_READY -> MERGED -> MAIN_GREEN -> CLEANUP_COMPLETE`

- `DETECTED`: record the evidence-backed maintenance need, exact repository, intended paths, source-only outcome, and authority boundary.
- `BRANCH_RESERVED`: bind the fetched starting-main SHA, one collision-free `change/*` branch and worktree, the Shared writer allocation, and one terminal watch.
- `AUDITED`: identify the smallest shared-source change, confirm every changed path is in scope, and stop on any human boundary below.
- `VALIDATED`: validate the exact candidate head and preserve a digest-bound validation manifest. Starting-main validators remain the trusted baseline. If the candidate changes a validator, workflow, Governor contract, or merge guard, run both the starting-main and candidate versions and retain both results.
- `GOVERNOR_APPROVED`: obtain the independent exact-head source receipt defined below. A writer's review or Planner judgment cannot substitute.
- `PR_OPEN`: open the bounded source-only pull request without implying installation or activation.
- `MERGE_READY`: re-fetch exact main, head, pull request, checks, reviews, threads, branches, and collisions; require current-head CI green, zero unresolved material threads, the independent approval still exact, and registered match-head protection.
- `MERGED`: prove the registered merge used the approved exact head and record the resulting main SHA.
- `MAIN_GREEN`: require the applicable post-merge checks to be terminal green on that exact main SHA.
- `CLEANUP_COMPLETE`: verify exact branch, worktree, lease, watch, and Shared writer cleanup and release. Ambiguous or destructive cleanup stops for human direction.

Do not create a separate attempt or handoff for each state. One fresh bounded Development writer attempt and one exact terminal watch span authoring, validation, and at most one same-scope repair. Changed scope, authority, diagnosis, collision, or safety effect returns to Planner disposition instead of opening another repair cycle.

## Keep roles independent

The same Product Planner orchestrates the lane, owns admission and Shared writer accounting, revalidates evidence, and may request a registered match-head merge after every gate passes. The Planner cannot author the candidate, approve its source head, or treat its own verification as Governor approval.

One fresh bounded Development writer owns the admitted `change/*` branch and worktree through exact-head validation and at most one bounded repair. It may prepare the source commit and bounded pull request under the admission, but it cannot self-approve, merge, install, cut over, or change the effective runtime.

One fresh low-context Skill Governor attempt independently reviews the exact candidate head. It is read-only: it cannot patch, commit, push, open or edit a pull request, resolve threads, merge, install, cut over, change capacity, or invoke a mutation. Give it only the starting-main contract, exact candidate evidence, and the smallest artifacts needed to judge the change.

## Require an exact-head Governor receipt

The Governor returns exactly one terminal verb: `APPROVE_SOURCE_HEAD`, `REJECT_SOURCE_HEAD`, or `HOLD`.

- `APPROVE_SOURCE_HEAD` means only that the bound source head is acceptable for the remaining source-only pull-request gates.
- `REJECT_SOURCE_HEAD` identifies exact evidence-backed source findings. The current writer may perform the single allowed same-scope repair; a changed head requires a new independent receipt.
- `HOLD` identifies missing evidence, drift, a human stop, lost independence, or an unavailable guard. It grants no repair, merge, installation, or cutover authority.

The immutable receipt must bind the exact repository identity; starting-main ref and SHA; starting-main contract digest; base ref and SHA; head ref and SHA; canonical diff digest; validation-manifest digest; Governor contract digest; Governor report digest; and fresh independent Governor attempt identity. It must also state the terminal verb and evidence-backed findings. Any field drift invalidates the receipt. A receipt is evidence, never mutation authority.

## Stop for human authority

Set the lane to `HOLD` before any weakening, expansion, replacement, or mutation involving:

- authority, roles, policy, capacity, topics, broker actions, approvals, or safety boundaries;
- credentials, secrets, customer/private data, or sensitive access;
- providers, billing, hosted systems, cloud, deployments, persistent data, traffic, production, or releases;
- repository or organization permissions, GitHub Actions authority, rulesets, or branch protection;
- skill installation or any installed-skill mutation;
- the effective Product Planner goal, goal hash, or other live contract replacement;
- endpoint/profile pointers, role registration, or immutable endpoint versions;
- systemd units, timers, services, or host activation;
- SQLite schema, data, policy, migration, restore, or cutover; or
- ambiguous, destructive, or difficult-to-recover cleanup.

Do not translate a source proposal into authority for one of these effects. If the intended outcome requires a broker, controller, installer, endpoint, or other live mechanism, keep that effective-runtime portion at `HOLD` until it is separately reviewed, explicitly authorized where required, installed, and attested. A source contract must not claim that absent automation is live.

## Separate source completion from installation

A merged source pull request becomes `SOURCE_COMPLETE` only after `MAIN_GREEN` and `CLEANUP_COMPLETE`. `SOURCE_COMPLETE` never means `INSTALLED`, active, registered, cut over, or effective. Installation and live activation require their own current authority, controls, evidence, and terminal receipt.

The following is proposed future goal wording only. It is inactive, does not modify `coordination/product-planner-goal.md`, and becomes effective only through a separate explicit user-approved goal replacement:

> Maintain Twinfinity's versioned Codex harness through one bounded, independently governed source-maintenance lane; treat source completion as distinct from separately authorized, installed, and attested live state.
