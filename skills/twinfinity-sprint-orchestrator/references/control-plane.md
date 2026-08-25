# Twinfinity delivery control plane

Use this reference for shared Product Planner, Development, and SRE invariants. Live GitHub facts, current SQLite state, repository instructions, and exact user authority override static examples.

## Authority order and canonical locations

Use this evidence order:

1. direct current user and Product Manager authority;
2. live GitHub issue, pull-request, milestone, review, check, release, and published-decision facts;
3. owner-only SQLite rows bound to exact refreshed GitHub snapshot digests;
4. repository `AGENTS.md` and `docs/development/`;
5. approved artifacts linked from owning issues; and
6. this reference.

Canonical locations:

- repository: `https://github.com/twinfinityai/twinfinityapp`;
- native checkout: `/home/ubuntu/code/twinfinityapp`;
- issue worktrees: unique sibling directories under `/home/ubuntu/code`;
- branches: `codex/<issue>-<slug>`; and
- SQLite store: `/home/ubuntu/.codex/twinfinity-coordination/ack-transactions.sqlite3`.

Do not perform repository work from a Windows-mounted or synchronized-cloud checkout. Use native Ubuntu for controlled Git, toolchain, network, and Docker operations.

## Role and product boundaries

- Product Manager owns vision, roadmap, material scope tradeoffs, success measures, and product acceptance.
- Product Planner is the sole durable non-coding delivery controller. It owns issue design, dependency sequencing, queue state, capacity application, leases, admissions, attempts, watches, approvals, outbox, and canonical tracker truth.
- Development owns one fresh bounded admitted repository attempt through `twinfinity-development-executor`.
- SRE owns one fresh bounded admitted maintenance or operational attempt through `twinfinity-devops-sre`.
- Portfolio, capacity, and skill-governor evaluations are optional one-shot read-only advice. They never mutate, claim, lease, consume capacity, or remain resident for liveness.

Preserve #131 as complete Twin Studio. Preserve #120 as the bounded Introships pilot and first-customer configuration. Product delivery must not encode Introships-specific runtime models, schema, routes, services, components, connectors, policies, or authorization paths when typed tenant configuration over a reusable Twinfinity capability is the correct boundary.

## Separate GitHub and SQLite responsibilities

GitHub owns external facts, collaboration, authority publication, and audit. SQLite owns same-host queue, claim, capacity, lease, attempt, terminal-watch, acknowledgement, approval-ledger, outbox, scheduling, and artifact-lifecycle state.

Never use GitHub comments as a local queue, lock, heartbeat, scheduler, or acknowledgement mechanism. Never infer current authority or liveness from chat, archived conversations, process discovery, or historical endpoint identity. If SQLite is unavailable, stale, unsafe, or on another machine, stop local orchestration and establish a separately reviewed transport; do not substitute comments.

Use `scripts/sync_github_coordination.py` to normalize current GitHub issue and PR facts before a decision and before every material mutation. A source digest, source timestamp, expected row version, capacity, lease, endpoint, topic, generation, or authority mismatch is `HOLD`.

The coordination root must be an owner-owned nonsymlink directory with mode `0700`. The database must be an owner-owned nonsymlink single-link regular file with mode `0600`. Controlled writers use WAL, `synchronous=FULL`, foreign keys, bounded busy timeout, and `BEGIN IMMEDIATE`. Use `sqlite3 -readonly` for diagnostics and never ad hoc SQL writes.

## SQLite ownership by module

- `coordination_store.py`: GitHub snapshots, delivery items, allocations, leases, typed inbox, outbox, terminal watches, events, atomic admissions/recovery/closeout, and registered-artifact lifecycle.
- `executor_registry.py`: immutable role endpoint versions, current pointers, aliases used only for historical compatibility, migration ledger, and target-bound attempts.
- `portfolio_graph.py`: immutable graph revisions, hard dependencies, ranking order, collisions, source coverage, and dependency-aware scheduling decisions.
- `portfolio_graph_supervisor.py`: bounded graph refresh, accepted-main cursor reconciliation, and scheduler recovery.
- `kanban_pull_buffer.py`: zero-WIP prepared and ready candidate packets bound to current source, graph, policy, artifacts, and admission checks.
- `kanban_readiness.py`: one candidate-level PREPARED-to-READY phase, immutable all-gates receipts, bounded resolution cycles, and approval-only waits.
- `portfolio_convergence.py`: dirty-event consumption and atomic selection of an already-reviewed READY candidate.
- `approval_ledger.py`: immutable material proposals, user decisions, revocations, recipient deliveries, and effectivity guards.
- `prepush_control.py`: exact-head lower/Compose gate receipt, guarded-publication reservation, and push readback.
- `hosted_operation_control.py`: exact provider-operation preparation, claim, capacity, verification, and receipt lifecycle.
- `publish_coordination_outbox.py`: sparse idempotent GitHub publication with exact readback and readback-only ambiguity recovery.
- `coordination_supervisor.py`: due local work selection and fresh role-attempt wakeup.

Keep policy-specific parsing and external side effects out of the shared store. Prefer focused modules at existing transaction seams.

## Capacity policy invariants

The active immutable versioned SQLite policy is the sole current ceiling. Documentation, scheduler code, issue bodies, and endpoint definitions must not embed a named numeric tier. A policy change records exact authority and expected prior version atomically, rejects a ceiling below current active plus retained occupancy, and recomputes feasible work without changing dependency, FIFO, lease, collision, review, or safety semantics.

Capacity is a safety ceiling, not a utilization target. Report separately:

- active Development allocation;
- active Shared-integration allocation;
- active SRE allocation;
- retained HOLD or collision allocation;
- independent READY depth; and
- PREPARED or QUEUED zero-WIP depth.

An admitted branch, repair/review lineage, exact final review window, or merged change awaiting mandatory cleanup consumes its declared allocation. A retained lease consumes the applicable allocation until it is safely parked or released. Read-only planning, one-shot advice, external monitoring, packet preparation without a branch or lease, and PREPARED/QUEUED candidates consume no writer capacity.

Shared-integration includes migrations, ownership manifests, central models or registries, shared factories, public/generated contracts, global shell or theme, shared infrastructure, and jointly owned documentation. Treat uncertain classification as shared until proven disjoint.

Parallel work requires exact disjoint path and semantic leases. Only one mutator may own a dependency family, database generation, provider target, service, IAM boundary, secret set, deployment/traffic surface, or other shared operational target. Unknown overlap blocks admission.

Keep a bounded useful prepared buffer only while each candidate has a current source, outcome, dependency or activation event, collision boundary, policy binding, and revalidation rule. `READY` means immediate atomic admission is possible; `PREPARED` means a named gate remains; `QUEUED` means ordered future work. None is a capacity target.

Scale a capacity policy only from exact reviewed authority and measured readiness, review bandwidth, collision, repair, CI, cleanup, and release evidence. Scale down when the active policy's safety conditions fail. A reduction freezes new admissions and drains or parks existing lineages through their safe closeout rules; it never authorizes cancellation, lease theft, or destructive cleanup.

## Portfolio graph and candidate flow

Milestones are projections over one repository-wide graph. Store only true acceptance precedence as `HARD_BLOCK`, ranking preference as `ORDER_AFTER`, and symmetric overlap as `COLLISION`. Only hard edges affect topological readiness.

Every covered open issue must be a node or a reasoned exclusion. Mark intentional roots and independently valuable standalone outcomes explicitly. Source, milestone membership, coverage, dependency, or relation drift makes the graph stale and blocks graph-derived admission until a reviewed replacement is applied.

Derive the queue by releasing only nodes whose hard predecessors are accepted, preserving lane order among equal priority, selecting the earliest collision-free set that fits current policy, recording skip reasons, and continuing independent lanes so one blocked head does not block the portfolio.

The prepared buffer may hold reviewed zero-WIP candidates. A distinct READY packet must bind the exact candidate artifact, source digest, issue generation/version, observed main, graph revision, capacity policy, lane, allocation demand, collision matrix, activation contract, lease manifest, and complete atomic-admission transaction. Any source, main, graph, policy, item, artifact, lease, or admission drift retires the current packet without changing historical evidence.

Kanban owns the missing middle between a prepared candidate and a READY packet. Discover structurally ready, current-main, zero-WIP candidates; register one immutable readiness campaign per candidate; and dispatch at most one fresh read-only Development or SRE attempt for the campaign. That attempt evaluates the complete source, dependency, lease, collision, scope/boundary, scenario/evidence, and operational checklist and returns one all-gates receipt. Gates are checklist entries, never independently queued micro-handoffs. Parallelism is across disjoint candidates. Readiness attempts consume no Development, Shared, or SRE writer allocation.

The readiness states are `PENDING -> RUNNING`, followed by exactly one of:

- `PASS -> READY_ELIGIBLE`, then one Planner continuation closes volatile projection, label, endpoint-transport, refreshed-binding, packet, and atomic-admission guards;
- `ACTIONABLE_HOLD -> RESOLUTION_PENDING`, then one consolidated Planner-owned resolution cycle applies every safe in-authority correction and registers one changed-evidence campaign;
- `APPROVAL_REQUIRED -> APPROVAL_PENDING`, after an exact proposal is recorded in the approval ledger, then resumes only from an effective published decision; or
- `TERMINAL_HOLD -> HOLD`, preserving the blocker for portfolio disposition.

Do not ask a human to close stale dashboard state, refresh current facts, choose an already-authorized collision-free sequence, strengthen delivery-control text, verify endpoint transport, publish the READY label, or perform other routine Planner controls. Human approval is reserved for a material product-behavior, UX, persistent-data, public-contract, security/privacy, hosted/provider, destructive, external-commitment, or capacity-policy decision. An unchanged campaign cannot be requeued. Permit no more than two changed-evidence resolution cycles before terminal HOLD. Source, main, graph, policy, item, candidate, dependency, or endpoint drift makes the campaign `STALE` and returns it to fresh discovery.

When a terminal allocation release commits, append a dirty event in the same transaction. Convergence may select only an already-reviewed READY packet and must commit successor admission with event completion atomically. It never promotes PREPARED or QUEUED work. Failure to admit a successor records the exact guard; it does not roll back a verified predecessor release.

## Typed admissions, claims, and watches

Inbox work follows `PREPARED -> CLAIMED -> COMPLETE`; outbox publication follows `PREPARED -> INFLIGHT -> COMPLETE`. The claim is the local execution handshake. Completion records local consumption, not product delivery.

Generic `coordination.notice` rows are non-authorizing observations, planning requests, evidence, or terminal receipts. Mutating work uses `development.*` or `sre.*` topics with strict recipient/profile separation. Development messages reject SRE allocation; SRE messages reject Development/Shared allocation. The matching item, source, generation, allocation, lease, role endpoint, and capacity policy must agree.

Use `activate-admission` so the READY-to-ACTIVE item transition, allocation, exact typed message, lease, and terminal watch commit as one transaction. The admission names the authorized routine chain and hard stops. It does not require Planner interaction after each successful routine stage.

Every ACTIVE lineage has one exact-generation terminal watch. A fresh endpoint wake revalidates that watch and continues immediately executable authorized work toward terminal outcome. A completed attempt, inbox row, local gate, push, PR update, or review phase does not complete the watch. The item transition after accepted outcome, publication, cleanup, lease release, and capacity release completes it.

After source, authority, scope, base, head, branch, worktree, path, lease, capacity, endpoint, dependency, collision, or required-evidence drift, stop the affected mutation and preserve the lineage. A corrected plan creates a fresh current transaction; do not create duplicate branches, worktrees, or writers.

## Endpoint attempts

Read [executor-registry.md](executor-registry.md) for the focused routing protocol. Each launch targets the current immutable `planner`, `development`, or `sre` endpoint and one exact message, watch, or hosted-operation key. Attempts are ephemeral and target-bound. Endpoint state never grants authority or capacity.

`coordination_supervisor.py` uses systemd and `run_role_executor.py` to reserve the exact role-target attempt before launching a fresh `codex exec`. Identical active targets deduplicate; different targets may run only when their SQLite items and active policy already permit them. Each supervisor pass has an explicit transport-only launch policy of four total attempts, three base message attempts, and one terminal-watch reserve. A due eligible terminal watch is guaranteed the reserve and suppresses a colliding message lineage for that pass; when no due eligible watch exists, a fourth message may borrow it. Failed transports consume that pass's budget, and rows beyond the selected budget remain unchanged for a later pass. This launch policy is not Development, Shared, or SRE capacity. Mechanical liveness comes from systemd timers, supervisor ledgers, attempts, and terminal watches, not model workers.

Development and SRE native actions run only through their fresh endpoint skills and strict profiles. Do not delegate execution-row claims or native Docker, outbound Git, GitHub, dependency download, provider, hosted, or cleanup actions outside the accountable role endpoint.

## Repository publication and exact-head evidence

For an application or workflow head:

1. confirm current source, item, admission, lease, branch, worktree, and clean exact head;
2. use the issue-owned toolchain and run the complete affected lower gate;
3. run applicable final-head local Docker Compose acceptance and prove owned-resource cleanup;
4. require a canonical exact-head PASS receipt;
5. publish only with `scripts/prepush_control.py guarded-push`; and
6. wait for natural exact-head CI and independent exact-head review.

The shared pre-push hook revalidates the live reserved publication, canonical remote, branch, head, and sole ref update. Raw or bypassed publication is prohibited. Ambiguous transport is readback-only recovery. A changed head invalidates prior head-bound evidence.

Read [environment-isolation.md](environment-isolation.md) for toolchain and cleanup rules and [ui-evidence.md](ui-evidence.md) for visual changes.

## Approval ledger and outbox

Only the Product Planner solicits user decisions. Development or SRE may submit one strict secret-safe proposal and pause only the affected mutation. A proposal or local decision grants no authority.

An approved decision becomes effective for an exact fresh attempt only after its owning-issue outbox row is published and read back, current source remains compatible, and the attempt claims its exact delivery. Revocation invalidates unconsumed execution guards and creates an owning-issue publication record. Read [approval-ledger.md](approval-ledger.md) for the schema and lifecycle.

GitHub publication is sparse: product decisions, material authority, PR collaboration, acceptance evidence, terminal receipts, operational receipts, and canonical tracker truth. Do not publish local queue state, claim chatter, scheduler state, routine stage completion, or process liveness.

Before publication, re-fetch the target, compare the source digest, reserve the outbox row, perform at most one external write, and require exact readback. An ambiguous result remains readback-only. Use the GitHub-safe projection: publish public issue/PR identities, exact public heads, repository-relative leases, opaque run IDs, counts, verdicts, residual blockers, and one manifest fingerprint; keep absolute paths, tool locations, per-file hashes, cleanup targets, and archives owner-local.

## Issue-body mutation

Use `scripts/issue_body_cas.py` only with a provider transport that makes the expected body bytes/digest/timestamp precondition atomic with the body update. Bind expected and desired bytes and digests, reserve the desired-digest key, perform at most one update, and do one no-cache canonical readback. Without a provider-supported atomic primitive, return `POSTCONDITION_FAILED`; never approximate it with read-then-unconditional-write.

A validated append-only state/lease overlay is an exceptional read model for an otherwise authoring-complete historical body during a proven provider capability gap. It may supersede only volatile control state such as accepted main, dependency state, readiness, capacity, exact lease, endpoint state, controlling receipts, and next action. It never changes product scope, Gherkin, safety, approval, non-goals, or definition of done; never authorizes hosted work; and never makes a comment alone admission authority. New issues receive no exception and must validate before creation and after rendered readback.

## Hosted operations

Read [hosted-operations.md](hosted-operations.md) for worktree-free provider actions. Every operation binds the owning GitHub source and published authority, exact provider/target/operation tuple, closed scope, exclusions, stop conditions, SRE capacity, and terminal receipt. A fresh SRE attempt claims only after revalidation. Provider ambiguity is readback-only; never blindly retry.

Repository evidence does not authorize deployment, data, IAM, secret, access, traffic, billing, or production operations. Each boundary requires its own exact authority and predecessor evidence.

## Terminal closeout and artifacts

Accepted delivery requires the exact final head or operational state, natural gates, independent review or operational verdict, owning-issue receipt, exact resource cleanup, terminal-watch completion, lease release, and capacity release.

Register owner-local artifacts with exact digest, inode, issue, generation, and retention class. The guarded collector alone moves or purges eligible files after terminal item, watch, control, and outbox guards pass. It never scans arbitrary files or deletes the database, locks, symlinks, changed bytes, active/retained evidence, or another generation.

If terminal outcome and SQLite release are proven but an owning-issue receipt is missing, prepare one terminal-closeout transaction. It may publish and read back only that receipt and consumes no writer capacity.

Canonical tracker publication follows verified state transitions. Publication failure keeps the projection pending but never reopens accepted work, restores a safely released lease, or blocks separately safe preparation.

## Durable safety rules

- Preserve user-owned and dirty worktrees; never overwrite, absorb, or destructively clean ambiguous state.
- Keep one accountable lineage and one exclusive mutable-surface lease.
- Require exact-head CI, review, and issue-owned evidence proportional to risk.
- Keep default tests deterministic, offline, synthetic, and tenant-safe.
- Never test schema changes against shared, staging, or production databases.
- Never put private data, credentials, secrets, restricted content, or sensitive local paths in GitHub.
- Treat sandbox network denial as an execution-boundary fact, not invalid credentials.
- Stop on contradictory current authority, Product Manager HOLD, changed material scope, collision, drift, destructive uncertainty, or missing evidence.
- Do not optimize for issue count, comment count, model activity, or nominal capacity use. Optimize for accepted owner-visible outcomes and safe release learning.
