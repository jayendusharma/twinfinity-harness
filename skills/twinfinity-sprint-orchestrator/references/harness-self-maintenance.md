# Harness source self-maintenance

Use this contract only for source maintenance in exact repository
`jayendusharma/twinfinity-harness`. Every source mutation in that repository
uses one direct, Product-Planner-fenced maintenance packet outside the
harness's own SQLite delivery loop. A defect in readiness, admission,
capacity, lease, messaging, watching, publication, or closeout must never
prevent or falsely authorize repair of that control plane.

This exception authorizes no TwinfinityApp or other application delivery and
no installed-skill, live-goal, SQLite, endpoint, profile, broker, systemd,
GitHub-configuration, provider, hosted, deployment, traffic, production, or
release mutation. Normal application delivery still requires its normal
Planner admission and SQLite claim. Keep source review, source completion,
installation, activation, and operational restoration as separate states.

## Freeze one exact direct-maintenance packet

Before the first repository mutation, the Product Planner must refresh the
live owning issue, current main, open branches, open pull requests,
dependencies, and path and semantic collisions, then freeze one canonical
packet. The packet and the exact owning-issue body it digest-binds form one
authority envelope. That envelope is complete only when it binds all of the
following:

- schema and packet digest; exact repository and owning issue; the complete
  live issue-body digest and observation time;
- starting-main ref and SHA; dependency and collision proof; exact
  `change/<issue>-<slug>` branch, isolated worktree path, and opaque worktree
  identity;
- a closed mutable-path set, semantic scope, named safety invariants,
  non-goals, and the rule that any fourth path or changed diagnosis stops;
- direct owner instruction and Planner fencing, one fresh accountable Development
  writer identity, direct harness-writer units, the current owner-authorized
  direct ceiling, and zero SQLite allocation units;
- authorized stages and their terminal boundary, required focused and full
  gates, independent exact-head Governor review, bounded repair rule, and the
  required evidence contracts for publication, match-head merge, cleanup, and
  the source terminal receipt; and
- excluded effects and hard stops, including application delivery,
  installation, runtime activation, SQLite mutation, raw or force publication
  as standing authority, and every provider or hosted effect.

The starting head equals the packet's starting-main SHA. The validation
manifest binds the later candidate head and tree; every remote continuation
must bind that exact accepted candidate head plus the unchanged packet digest.
Do not infer a later stage from authority for an earlier one. A local-authoring
packet does not authorize push, pull-request mutation, merge, cleanup, or
terminal publication.

At every decision boundary, re-fetch the issue body, main, branches, pull
requests, exact head when present, and collisions and compare them with the
packet. Before `MERGED`, main must remain the starting-main SHA. The registered
match-head receipt alone may advance that binding to its recorded merge-result
main SHA; after `MERGED`, live main must equal that result. Any other
repository, issue, body, main, branch, worktree, opaque identity, writer, path,
semantic scope, authority, capacity, stage, head, dependency, or collision
drift is `HOLD`. Do not repair the packet in place, fall back to SQLite, select
another branch or worktree, or broaden scope.

Do not create or mutate SQLite readiness, candidate, item, allocation, lease,
message, attempt, watch, approval, outbox, artifact, or closeout rows for the
direct lane. SQLite may be inspected only when the packet explicitly requires
non-authorizing diagnostic evidence; its contents can neither authorize,
veto, reserve, acknowledge, publish, nor close direct source maintenance.

## Reserve direct capacity and isolate the lane

Each packet consumes one directly accounted harness-source writer unit. The
Planner counts it outside SQLite and must remain within the exact
owner-authorized ceiling recorded in the packet; no Shared, Development, or
SRE allocation row or lease is created. Parallel direct packets are allowed
only when their branches, worktrees, changed paths, semantic surfaces, and
review capacity are provably disjoint. One packet has exactly one active
writer and one mutable worktree.

For the harness repository, use the packet's exact
`change/<issue>-<slug>` branch. The worktree basename is
`twinfinity-harness-issue<issue>` or that prefix plus one lowercase hyphenated
owner suffix, and the opaque worktree ID equals the basename. Reject an active
branch, pull request, writer, worktree, path, or semantic collision. Preserve
dirty, ambiguous, historical, or foreign workspaces; their cleanup is not
implied by a new packet.

## Run the direct source lifecycle

Keep the workflow coarse and GitHub-bound:

`DETECTED -> PACKET_FROZEN -> BRANCH_RESERVED -> AUDITED -> VALIDATED -> GOVERNOR_APPROVED -> PR_OPEN -> MERGE_READY -> MERGED -> MAIN_GREEN -> CLEANUP_COMPLETE -> SOURCE_COMPLETE`

- `DETECTED`: record the evidence-backed maintenance need, exact repository,
  intended paths, source-only outcome, and authority boundary.
- `PACKET_FROZEN`: preserve the complete canonical direct packet and its
  digest after the fresh collision and capacity check.
- `BRANCH_RESERVED`: create only the packet's non-force branch and isolated
  worktree from the exact fetched starting-main SHA.
- `AUDITED`: identify the smallest source change, map every changed path to
  the issue or a named safety invariant, and stop on any boundary below.
- `VALIDATED`: validate the exact candidate head and preserve a digest-bound
  validation manifest. The repository-derived harness gate profile runs
  root-local focused hermetic selectors, the fixed complete eleven-skill
  quick-validator catalog, and the full hermetic suite without application,
  browser, Docker, installation, or runtime activation. Starting-main
  validators remain the trusted baseline. If the candidate changes a
  validator, workflow, Governor contract, or merge guard, run both the
  starting-main and candidate versions and retain both results.
- `GOVERNOR_APPROVED`: obtain the independent exact-head source receipt below.
  Writer or Planner judgment cannot substitute.
- `PR_OPEN`: only an exact publication continuation may publish the accepted
  head and open the bounded source-only pull request. Use the registered
  non-SQLite source guard when one exists. Otherwise require explicit current
  owner authority for one exact non-force remote, ref, and head update and
  preserve a direct before/after/readback receipt. This fallback creates no
  reusable raw-push or caller-selected publication authority.
- `MERGE_READY`: re-fetch exact main, head, pull request, checks, reviews,
  threads, branches, and collisions. Require natural exact-head CI green,
  zero unresolved material threads, the independent approval still exact,
  and registered match-head protection.
- `MERGED`: the Product Planner invokes the registered match-head mechanism;
  prove it used the approved exact head and record the resulting main SHA. The
  Development writer never merges its own candidate.
- `MAIN_GREEN`: require the applicable post-merge checks to be terminal green
  on that exact main SHA.
- `CLEANUP_COMPLETE`: only an exact cleanup continuation may reclaim the
  packet's clean branch, worktree, and directly accounted writer unit. Prove
  absence without touching an ambiguous, dirty, foreign, installed, or live
  resource.
- `SOURCE_COMPLETE`: publish one packet-bound, GitHub-safe source terminal
  receipt and prove its exact GitHub readback. The receipt binds merge, main
  checks, review, cleanup, direct-capacity disposition, residual risks, and
  the negative installed/runtime/SQLite inventory. It never uses the SQLite
  outbox or terminal-closeout APIs.

Do not create a separate attempt or handoff for each state. One fresh bounded
Development writer owns authoring, exact-head validation, and at most one
same-scope repair. Changed scope, authority, diagnosis, collision, or safety
effect requires a fresh Planner disposition and packet rather than another
repair cycle.

## Keep roles independent

The Product Planner scopes the issue, freezes and revalidates the packet,
accounts direct capacity, may issue exact later-stage continuations, and may
invoke the registered match-head mechanism after every gate passes. It cannot
author the candidate, approve its source head, or treat its own verification
as Governor approval.

One fresh Development writer owns only the packet's branch, worktree, paths,
and authorized stages. It cannot self-review, infer a later stage, merge,
install, cut over, change effective runtime, or use the packet for application
work.

One fresh low-context Skill Governor attempt independently reviews the exact
candidate head. It is read-only: it cannot patch, commit, push, open or edit a
pull request, resolve threads, merge, install, cut over, change capacity, or
invoke any mutation. Give it only the starting-main contract, packet digest,
exact candidate evidence, and smallest artifacts needed to judge the change.

SRE owns any separately authorized installation or activation. No source
packet grants that authority.

## Bind validation and Governor evidence

The validation manifest must bind the exact repository, issue and body digest,
direct packet digest, base ref and SHA, head ref and SHA, head tree, canonical
diff digest, changed paths, validation tool provenance, exact commands and
results, generated-file cleanliness, and excluded-effect inventory. Forward
tests must exercise realistic routing decisions: a complete harness packet
takes the direct route, application work keeps normal admission, and an
incomplete or substituted packet fails before mutation. Wording or regex
presence alone is not behavioral evidence.

The Governor returns exactly one terminal verb: `APPROVE_SOURCE_HEAD`,
`REJECT_SOURCE_HEAD`, or `HOLD`.

- `APPROVE_SOURCE_HEAD` means only that the bound source head is acceptable
  for the remaining source-only pull-request gates.
- `REJECT_SOURCE_HEAD` identifies exact evidence-backed source findings. The
  current writer may perform the single allowed same-scope repair; a changed
  head requires a new independent receipt.
- `HOLD` identifies missing evidence, drift, a human stop, lost independence,
  or an unavailable guard. It grants no repair, merge, installation, or
  cutover authority.

The immutable receipt must bind the exact repository identity; owning issue
and body digest; packet digest; starting-main ref and SHA; starting-main
contract digest; base ref and SHA; head ref, SHA, and tree; canonical diff
digest; validation-manifest digest; Governor contract digest; Governor report
digest; and fresh independent Governor attempt identity. It must also state
the terminal verb and evidence-backed findings. Any field drift invalidates
the receipt. A receipt is evidence, never mutation authority.

## Stop for human authority

Set the lane to `HOLD` before any weakening, expansion, replacement, or
mutation beyond the exact packet involving:

- authority, roles, policy, capacity, topics, broker actions, approvals, or
  safety boundaries;
- credentials, secrets, customer or private data, or sensitive access;
- providers, billing, hosted systems, cloud, deployments, persistent data,
  traffic, production, or releases;
- repository or organization permissions, GitHub Actions authority, rulesets,
  or branch protection;
- skill installation or any installed-skill mutation;
- the effective Product Planner goal, goal hash, or other live contract;
- endpoint or profile pointers, role registration, or immutable endpoint
  versions;
- systemd units, timers, services, or host activation;
- SQLite schema, data, policy, migration, restore, cleanup, or cutover;
- a fourth path, changed diagnosis, application exception, standing raw-push
  authority, missing independent review, or missing natural CI; or
- ambiguous, destructive, or difficult-to-recover cleanup.

Do not translate a source proposal into authority for one of these effects.
If the intended outcome requires an installer, endpoint, service, provider,
or other live mechanism, keep that effective-runtime portion at `HOLD` until
it is separately reviewed, explicitly authorized, installed, and attested. A
source contract must not claim that absent automation is live.

## Separate source completion from operational restoration

`SOURCE_COMPLETE` never means `INSTALLED`, active, registered, cut over, or
effective. Installation and live activation require their own current SRE
authority, controls, evidence, and terminal receipt.

After separately authorized installation and activation, operational
restoration requires issue #80 to run one real current-v6 source canary through
the normal harness path from preparation and SQLite admission through guarded
publication, independent review, merge, cleanup, terminal publication,
lease/capacity release, and successor evaluation. The #80 canary must use no
direct-maintenance bypass. A failed canary reopens the exact causal source
issue; source merge or timer activity alone never proves restoration.

The following is proposed future goal wording only. It is inactive, does not
modify `coordination/product-planner-goal.md`, and becomes effective only
through a separate explicit user-approved goal replacement:

> Maintain Twinfinity's versioned Codex harness through one bounded, independently governed source-maintenance lane; treat source completion as distinct from separately authorized, installed, and attested live state.
