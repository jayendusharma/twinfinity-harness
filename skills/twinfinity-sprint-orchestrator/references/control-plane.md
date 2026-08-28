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

Those repository, checkout, worktree, and branch values are the application
defaults. Exact repository `jayendusharma/twinfinity-harness` instead uses the
repository-derived `change/<issue>-<slug>` and sibling harness-worktree policy
defined in [harness-self-maintenance.md](harness-self-maintenance.md); neither
repository may use the other's identity.

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
- `role_executor_broker.py`: dormant experimental v5 readiness isolation; it is not current routing or a production prerequisite.
- `portfolio_graph.py`: immutable milestone- or issue-set-scoped graph revisions, hard dependencies, ranking order, collisions, source coverage, and dependency-aware scheduling decisions.
- `portfolio_graph_supervisor.py`: bounded graph refresh, accepted-main cursor reconciliation, and scheduler recovery.
- `kanban_make_ready.py`: bounded, idempotent Planner preparation notices for structurally ready zero-WIP work that lacks a current packet or readiness plan.
- `kanban_pull_buffer.py`: zero-WIP prepared and ready candidate packets bound to current source, graph, policy, artifacts, and admission checks.
- `kanban_readiness.py`: one candidate-level PREPARED-to-READY phase, immutable all-gates receipts, bounded resolution cycles, and approval-only waits.
- `portfolio_convergence.py`: dirty-event consumption and atomic selection of an already-reviewed READY candidate.
- `approval_ledger.py`: immutable material proposals, user decisions, revocations, recipient deliveries, and effectivity guards.
- `prepush_control.py`: repository-derived exact-head gate receipt, guarded-publication reservation, and push readback. Existing lower/Compose receipt slots remain compatibility fields for repository-specific profiles.
- `repository_git_registry.py`: immutable bootstrap-provenance-bound repository Git-directory registration and owner-safe read-only remote-main resolution.
- `hosted_operation_control.py`: exact provider-operation preparation, claim, capacity, verification, and receipt lifecycle.
- `publish_coordination_outbox.py`: sparse idempotent GitHub publication with exact readback and readback-only ambiguity recovery.
- `coordination_supervisor.py`: due local work selection and fresh role-attempt wakeup.

Keep policy-specific parsing and external side effects out of the shared store. Prefer focused modules at existing transaction seams.

## Capacity policy invariants

The active immutable versioned SQLite policy is the sole current ceiling. Documentation, scheduler code, issue bodies, and endpoint definitions must not embed a named numeric tier. Every non-bootstrap policy change requires one current, published, effective, claimed, nonrevoked human `APPROVE` decision delivered to the exact current Planner endpoint with boundary `CAPACITY_POLICY`. Its decision digest is the policy authority and its execution-scope digest binds exactly `{kind: CAPACITY_POLICY, repository, expected_prior_version, development_limit, shared_limit, sre_limit}`. The store validates that ledger authority inside the same transaction that records the exact prior version, rejects a ceiling below current active plus retained occupancy, and recomputes feasible work without changing dependency, FIFO, lease, collision, review, or safety semantics. No public API or CLI bypass exists.

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

Every covered open issue must be a node or a reasoned exclusion. A normal application graph uses exact milestone scope. An unmilestoned harness source portfolio may instead use the explicit `ISSUE_SET` scope, which binds the full member inventory, digest-bound exclusions, and current endpoint issue evidence for every relation without inventing milestone truth. Mark intentional roots and independently valuable standalone outcomes explicitly. Source, scope membership, coverage, dependency, exclusion, or relation drift makes the graph stale and blocks graph-derived admission until a reviewed replacement is applied.

Derive the queue by releasing only nodes whose hard predecessors are accepted, preserving lane order among equal priority, selecting the earliest collision-free set that fits current policy, recording skip reasons, and continuing independent lanes so one blocked head does not block the portfolio.

The prepared buffer may hold reviewed zero-WIP candidates. For the exact harness repository, the owner preparation operation composes one repository-local graph revision, `PREPARED/NONE` item, registered owner-only artifact, and `PREPARED_NOT_READY` pointer under one `BEGIN IMMEDIATE`; exact replay creates no row or event growth and no message, watch, attempt, branch, worktree, publication, lease, allocation, or writer WIP. It requires bracketed current-main evidence, an existing reviewed capacity policy, exact issue-set sources and exclusions, graph-derived collisions, and the harness source demand `{Development: 0, Shared: 1, SRE: 0}`. A distinct READY packet must bind the exact candidate artifact, source digest, issue generation/version, observed main, graph revision, capacity policy, lane, allocation demand, collision matrix, activation contract, lease manifest, and complete atomic-admission transaction. Any source, main, graph, policy, item, artifact, lease, or admission drift retires the current packet without changing historical evidence.

Kanban owns the missing middle between a prepared candidate and a READY packet. Discover structurally ready, current-main, zero-WIP candidates; register one immutable readiness campaign per candidate; and dispatch at most one fresh read-only Development or SRE attempt for the campaign. That attempt evaluates the complete source, dependency, lease, collision, scope/boundary, scenario/evidence, and operational checklist and returns one all-gates receipt. Gates are checklist entries, never independently queued micro-handoffs. Parallelism is across disjoint candidates. Readiness attempts consume no Development, Shared, or SRE writer allocation.

The portfolio supervisor refills Kanban in two bounded phases after a successful pull-buffer audit. Phase A preserves the existing convergence, graph scheduling, and pull-buffer result. Phase B gives existing `PENDING` readiness campaigns first use of the fixed two-candidate review limit, then uses only unused slots for exact-binding, non-authorizing Planner make-ready notices. Those notices reuse graph priority and stable ordering, allocate no writer, and are idempotent over source, main, graph, policy, item, candidate or campaign absence, and current Planner endpoint evidence. Hard predecessors, mutable collisions, existing campaigns, drift, or missing routing produce typed no-write results. A Phase B failure remains nested and cannot undo or misreport committed Phase A work.

Production readiness uses a fresh direct current Development or SRE `coordination.notice` attempt. It claims and completes only that exact non-authorizing row and stages its all-gates receipt through the existing authenticated readiness path; it receives no writer allocation, lease, branch, hosted authority, or mutation authority beyond the exact receipt lifecycle. The v5 broker implementation is dormant experimental hardening: its credential transport and writer/terminal/hosted RPCs are incomplete, so it is neither current nor required for readiness or delivery throughput.

The readiness states are `PENDING -> RUNNING`, followed by exactly one of:

- `PASS -> READY_ELIGIBLE`, then one Planner continuation closes volatile projection, endpoint-transport, refreshed-binding, packet, and atomic-finalization guards;
- `ACTIONABLE_HOLD -> RESOLUTION_PENDING`, then one consolidated Planner-owned resolution cycle applies every safe in-authority correction and registers one changed-evidence campaign;
- `APPROVAL_REQUIRED -> APPROVAL_PENDING`, after terminal pickup atomically binds and submits the receipt's exact closed `READINESS` proposal input, then resumes only through the exact effective published-decision consumer; or
- `TERMINAL_HOLD -> HOLD`, preserving the blocker for portfolio disposition.

`readiness-reopen-terminal-hold` is the sole narrow recovery edge from that protected `HOLD`. The current Planner may use it only when an exact terminal-HOLD receipt is current, the old campaign/message/attempt are terminal and unallocated, and a strictly newer zero-WIP `PREPARED` item generation already has a current-main, current-graph, current-policy `PREPARED_NOT_READY` candidate. The command takes exact campaign, readiness-version, receipt-ID, and receipt-digest fences and atomically derives one `REFRESH` successor with those live structured bindings and a canonical value-free readiness checklist. It never copies parent prose that may name superseded graph versions, branches, worktrees, or path counts. It cannot reopen same-generation, arbitrary, approval-pending, or finalized holds; generic evaluation and registration continue to protect `HOLD`.

Every dispatched campaign notice carries one deterministic owner-local receipt locator bound to its campaign, plan, candidate, and source. The endpoint claims the exact notice, attaches its current target-bound attempt, evaluates every gate internally, and uses `readiness-stage-receipt` while the message remains `CLAIMED` and the attempt remains `RUNNING`. That CLI accepts no token argument: it hashes the wrapper-injected `TWINFINITY_EXECUTOR_TOKEN`, constant-time verifies the exact attempt token plus role, endpoint, message target, and campaign bindings, writes or reopens one canonical artifact, and atomically changes the pickup row from `PENDING` to `STAGED` with immutable digest and stable file identity. This is the only expressly authorized coordination mutation for the otherwise non-authorizing notice, and there is no public arbitrary receipt-ingestion route. The worker cannot record the verdict, fabricate future terminal state, or emit a gate-level handoff. It completes the notice and exits only after authenticated staging; the attempt wrapper then makes the exact attempt terminal.

The coordination supervisor alone considers `STAGED` evidence after both the message and attached attempt are `COMPLETE`. It reopens the locator and revalidates campaign, plan, candidate, source, message, attempt, stored token digest, locator digest, artifact digest, and the complete immutable owner-only file identity, then atomically records the verdict transition and emits exactly one Planner continuation. For `APPROVAL_REQUIRED`, the worker's one receipt must contain one closed proposal input whose requester is that exact authenticated Development/SRE endpoint and attempt, recipient is the current Planner, workstream is `READINESS`, and scope binds the repository, issue, source, campaign/generation/item version, main/graph/policy/candidate, worker identity, parent plan, boundary, and fixed decision mapping. Pickup submits that input and creates only the central proposal-review notice; it never lets the worker impersonate Planner or creates a duplicate generic result notice. Exact staged replay is idempotent. Terminal `PENDING` means the worker did not authenticate a submission even when a file is present. That condition, or a missing, noncanonical, unsafe, substituted, or invalid `STAGED` artifact, follows the durable bounded pickup retry ledger and ends in readiness `HOLD` without consuming writer capacity or fabricating a Planner verdict notice. This ordering prevents a worker from attesting to its own future terminal state. Do not ask a human to close stale dashboard state, refresh current facts, choose an already-authorized collision-free sequence, strengthen delivery-control text, verify endpoint transport, reconcile a non-authoritative READY projection, or perform other routine Planner controls. Human approval is reserved for a material product-behavior, UX, persistent-data, public-contract, security/privacy, hosted/provider, destructive, external-commitment, or capacity-policy decision. An unchanged campaign cannot be requeued. Every successor binds the exact parent campaign/version and a canonical digest of the changed control fields or effective approval. Permit no more than two changed-evidence resolution cycles before terminal HOLD. Generic evaluation may report drift for `APPROVAL_PENDING`, `HOLD`, or `FINALIZED`, but it cannot rewrite those states to `STALE`; their exact decision, disposition, revocation, or finalized-recovery handlers own the next mutation.

`ACTIONABLE_HOLD` resolution actions are closed objects with exactly `kind`, `target`, `expected_digest`, `desired_digest`, `authority_class`, and `evidence_required`. The routine registry contains only `REFRESH_SOURCE_SNAPSHOT`, `RECOMPUTE_DEPENDENCY_GRAPH`, and `REBUILD_PREPARED_CANDIDATE`, all with authority class `PLANNER_OWNER_API`. Their named coordination-store, graph, and pull-buffer APIs are direct Planner-owner prerequisites; a readiness evaluator receives no database or mutation authority. The current Planner claims the exact notice with `readiness-resolution-context`, which returns the immutable parent plan, prepared candidate, receipt, complete action bytes and digest, current bindings, and frozen approval reference. Claim atomically compares every live target with its frozen expected digest; pre-claim mutation ends the cycle on terminal HOLD with no successor. Each owner call then uses `readiness-execute-resolution-action` with the exact notice, context, action identity, expected digest, and closed input, and stores immutable before/after bindings. An ordered source refresh may wait for its graph-recompute prerequisite, but cannot claim completion early. After every prerequisite has authoritative readback, `readiness-apply-resolution` requires the complete exact receipt set and atomically binds changed evidence, registers at most one successor, records the cycle, and completes the notice. Replay returns the immutable result. Missing or digest-drift routine evidence ends that cycle on terminal HOLD and never becomes implicit approval. `REQUEST_MATERIAL_APPROVAL` is approval-ledger-only and cannot execute through the routine resolution handler.

After `record_decision` and the exact owning-issue outbox publication/readback are both `COMPLETE`, the supervisor creates exactly one idempotent decision notice routed to the current Planner. `readiness-apply-decision --message-id <id> --planner-session-id <current-planner> --source <fresh-owning-issue-json>` is the only consumer. In one transaction it claims the exact message and historical role-equivalent delivery, compares the caller observation with the in-transaction `github_current` stable source without advancing the planning pointer for comment/projection-only churn, revalidates request/submission/receipt/publication/scope/boundary/actor/revocation, applies the fixed disposition, records immutable consumption, acknowledges the delivery, and completes the message. `APPROVE` derives one deterministic v2 `APPROVAL_RESUME` successor from the stored parent plan. `REJECT` and `COURSE_CORRECT` stay on durable `HOLD` and require a fresh proposal for materially changed execution. Readiness `DEFER` requires a strict RFC3339 UTC `AT` trigger, stays on `HOLD`, and creates exactly one current-Planner re-review notice when due; it never becomes approval automatically. Material stable-source drift becomes `STALE`. Revocation holds unconsumed waits and stops `PENDING`, `RUNNING`, `READY_ELIGIBLE`, or `FINALIZED` approval-resumed lineages before convergence. Generic message claim, caller-authored successor data, and unpublished decisions fail closed.

`finalize-ready` is the exclusive PREPARED-to-READY gateway. In one transaction it requires the exact READY_ELIGIBLE campaign and canonical PASS receipt, revalidates all source/main/graph/policy/item/candidate/endpoint/artifact/lease/admission/scheduler guards, and re-runs any approval-resume effectivity/revocation guard. It registers the new immutable READY candidate and finalization provenance, marks the campaign FINALIZED, changes the zero-WIP item to READY only after that attestation is transactionally present, and appends exactly one dirty event. It creates no allocation, writer message, active lease, or terminal watch. Public item-state calls cannot manufacture READY or writer-active state, including before readiness schema installation. At cutover, run `quarantine-unattested-ready` before enabling convergence; it atomically moves every pre-existing READY row without exact immutable finalization to `HOLD` and preserves valid attested READY rows. A GitHub `agent-ready` label is optional projection only; it is never authority or an input to this source-bound transaction.

The same projection rule applies at claim: an exact `PREPARED` admission may be claimed while `agent-ready` or body readiness text is absent or stale. The immutable SQLite admission and its exact stored GitHub source digest authorize the handshake; projection cannot add authority, hide material source drift, or veto an otherwise exact claim.

When finalization or a terminal allocation release commits, append its dirty event in the same transaction. Convergence may select only a finalization-attested READY packet and must commit successor admission with event completion atomically. It never promotes PREPARED or QUEUED work. Failure to admit a successor records the exact guard; it does not roll back a verified predecessor release or READY finalization.

## Typed admissions, claims, and watches

Inbox work follows `PREPARED -> CLAIMED -> COMPLETE`; outbox publication follows `PREPARED -> INFLIGHT -> COMPLETE`. The claim is the local execution handshake. Completion records local consumption, not product delivery.

Generic `coordination.notice` rows are non-authorizing observations, planning requests, readiness phases, evidence, or terminal receipts. Mutating work uses `development.*` or `sre.*` topics with strict recipient/profile separation. Development messages reject SRE allocation; SRE messages reject Development/Shared allocation. Both admission types must carry nonempty writer, reviewer, collision, environment, routine-chain, and hard-stop controls. The matching item, source, generation, allocation, lease, role endpoint, and capacity policy must agree.

Use `activate-admission` so the attested READY-to-ACTIVE item transition, allocation, exact typed message, lease, and terminal watch commit as one transaction. Activation requires the prior item to be exactly READY, revalidates its immutable finalization attestation, and re-runs any approval-resume effectivity/revocation guard inside the admission transaction; a missing readiness schema, revoked authority, or unattested legacy READY row fails closed. The supervisor stops revoked readiness lineages before convergence, while this in-transaction check closes the race before allocation. The admission names the authorized routine chain and hard stops. It does not require Planner interaction after each successful routine stage.

An ordinary unclaimed Development or SRE admission that makes no target progress across three bounded supervisor attempts exhausts atomically: its admission message, prepared wake, and bound watch become `HOLD`, its item becomes `HOLD/RETAINED` without changing demand or lease provenance, and exactly one idempotent notice goes to the current Planner. No writer is launched from that state. `recover-unclaimed-admission` is the sole owner CLI for the exact notice-bound recovery. It requires that notice already be claimed by the current Planner and authenticates the wrapper-injected token against the exact current `role.planner` RUNNING attempt targeted to that notice. In one transaction it rejects any claim evidence, active attempt, closeout packet, pre-push/publication row, terminal message, source drift, stale fence, unclaimed notice, or attempt/token mismatch; retires the already-admitted pull-buffer candidate exactly once; advances the item generation and version; restores `PREPARED/NONE`; clears owner and lease; preserves Development, Shared, and SRE demand; changes the prior readiness pointer from `FINALIZED` to `STALE`; completes the recovery notice; and appends one non-capacity-release refill event. Receipt-first replay is idempotent even after a genuine successor progresses. One-time historical compatibility remains Development-only and is admitted only through its separate closed, digest-bound descriptor, whose stored normalization events, sole terminal attempt, immutable finalization bindings and timestamps, and applied endpoint-rotation proof all agree relationally; it permits only projection-only source delta. A distinct Development-or-SRE descriptor covers only a never-claimed admission held solely for same-role endpoint cutover: it must bind the exact zero-claim history, one terminal no-progress attempt, held message/watch/item, completed wake, immutable finalization/events, unchanged source/lease/demand, and applied rotation to the current same-role endpoint. It reuses the same atomic recovery outcome and receipt-first replay. Neither descriptor grants notice or executor authority.

Every `ACTIVE` or `PUBLICATION_PENDING` lineage has one exact-generation terminal watch. A fresh endpoint wake revalidates the watch's immutable admission message, payload digest, original claim attempt and historical endpoint, current accountable endpoint, role, source, generation, and lease before it continues immediately executable authorized work toward terminal outcome. Exact applied endpoint rotation changes the mutable watch/item owner without rewriting original admission provenance. A completed attempt, inbox row, local gate, push, PR update, or review phase does not complete the watch. The terminal commit after accepted outcome, publication readback, cleanup, lease release, and capacity release completes it.

An immutable claimed admission may continue after endpoint rotation only when the intact `APPLIED` registry-change ledger proves the exact same-role item identity/version and terminal-watch transition from its historical recipient to the current endpoint. Source, generation, lease, capacity, payload digest, claimant, original claim attempt, and exact watch binding remain mandatory. If the older runtime produced the exact paired holds `MESSAGE_ITEM_STATE_MISMATCH` and `TERMINAL_WATCH_ADMISSION_BINDING_DRIFT`, use `preview-endpoint-rotation-admission-rearm` and then `apply-endpoint-rotation-admission-rearm` with the returned preview digest and exact message/watch `updated_at` fences. The apply transaction changes only the message back to `CLAIMED`, the watch back to `ACTIVE`, and their bounded retry/error fields; it never edits admission provenance, capacity, item version, leases, branches, or processes. Any different HOLD, ledger, binding, active attempt, closeout packet, or CAS state remains `HOLD`.

A claimed active admission held only by `SOURCE_SNAPSHOT_DRIFT` plus its paired terminal-watch binding HOLD may use `preview-source-equivalent-admission-rearm` followed by `apply-source-equivalent-admission-rearm`. The owner-only preview requires one exact completed owner-comment outbox receipt and one-event fresh timeline, and compares normalized snapshots after removing only top-level `updated_at` and top-level `_projection_*` keys. Apply records one immutable admission-, item-, generation-, claim-, endpoint-, lease-, capacity-, outbox-, and source-pair-bound receipt while atomically restoring only `CLAIMED/ACTIVE`. Material source change, later source drift, ambiguous activity, changed lineage, active delivery work, or unrelated graph staleness remains `HOLD`; the receipt never updates the item's admitted source or masks another graph defect.

After source, authority, scope, base, head, branch, worktree, path, lease, capacity, endpoint, dependency, collision, or required-evidence drift, stop the affected mutation and preserve the lineage. A corrected plan creates a fresh current transaction; do not create duplicate branches, worktrees, or writers.

## Endpoint attempts

Read [executor-registry.md](executor-registry.md) for the focused routing protocol. Each launch targets the current immutable `planner`, `development`, or `sre` endpoint and one exact message, watch, or hosted-operation key. Attempts are ephemeral and target-bound. Endpoint state never grants authority or capacity.

`coordination_supervisor.py` uses systemd and `run_role_executor.py` to reserve the exact role-target attempt before launching a fresh `codex exec`. Before portfolio convergence and ordinary inbox scheduling, it performs bounded terminal readiness-receipt pickup, published decision-notice creation, due typed-DEFER re-review creation, and revocation stopping. Identical active targets deduplicate; Planner notices are additionally single-flight per repository while disjoint Development and SRE lineages remain parallel only when their SQLite items and active policy already permit them. Each supervisor pass has an explicit transport-only launch policy of four total attempts, three base message attempts, and one terminal-watch reserve. A due eligible terminal watch is guaranteed the reserve and suppresses a colliding message lineage for that pass; when no due eligible watch exists, a fourth message may borrow it. Within the message budget, one stable FIFO slot serves the oldest eligible due retry before fresh messages, so sustained fresh arrivals cannot starve an `INFLIGHT` retry; later retry and fresh rows remain deterministic. Failed transports consume that pass's budget, rows beyond the selected budget remain unchanged for a later pass, and claimed notices remain recoverable after a terminal attempt. Unchanged transport or receipt-artifact failure reaches a durable HOLD after finite retries. Terminal-watch heartbeats reset their retry budget; a missing heartbeat eventually holds the watch rather than producing an infinite retry storm. This launch policy is not Development, Shared, or SRE capacity. Mechanical liveness comes from systemd timers, supervisor ledgers, attempts, receipt locators, immutable approval request and consumption rows, and terminal watches, not model workers.

Development and SRE native actions run only through their fresh endpoint skills and strict profiles. Do not delegate execution-row claims or native Docker, outbound Git, GitHub, dependency download, provider, hosted, or cleanup actions outside the accountable role endpoint.

## Repository publication and exact-head evidence

For a repository head:

1. confirm current source, item, admission, lease, branch, worktree, and clean exact head;
2. use the issue-owned toolchain and run the complete affected lower gate;
3. run the closed repository-derived final-head gate profile and prove its applicable cleanup contract; application or workflow heads retain local Docker Compose acceptance, while a harness source head runs only its focused hermetic selectors, complete fixed quick-validator catalog, and full hermetic suite;
4. require a canonical exact-head PASS receipt;
5. publish only by invoking the canonical installed `prepush_control.py guarded-push` directly through `/usr/bin/python3`, without a shell wrapper or leading environment assignment, and pass the active owning issue rather than a retained transfer surface issue; and
6. wait for natural exact-head CI and independent exact-head review.

The shared pre-push hook revalidates the live reserved publication, canonical remote, branch, head, and sole ref update. Raw or bypassed publication is prohibited. Ambiguous transport is readback-only recovery. A changed head invalidates prior head-bound evidence.

Pull-buffer preparation and convergence resolve remote main only through one
immutable exact-repository Git-directory registration. The registered directory
is read-only evidence and never expands the writable canonical-checkout,
worktree, branch, or Git-command authority enforced by the delivery guard.

Read [environment-isolation.md](environment-isolation.md) for toolchain and cleanup rules and [ui-evidence.md](ui-evidence.md) for visual changes.

## Approval ledger and outbox

Only the Product Planner solicits user decisions. Development or SRE may submit one strict secret-safe proposal and pause only the affected mutation. A proposal or local decision grants no authority.

An approved decision exists only inside one immutable review batch that freezes source, execution scope, recipient set, option map, and option-to-machine-outcome mapping; the user event binds the exact canonical batch answer map, and the ledger derives the decision from the selected frozen option. It becomes effective for an exact fresh attempt only after its owning-issue outbox row is published and read back, current source remains compatible, and the attempt claims its exact delivery. Revocation invalidates unconsumed execution guards and creates an owning-issue publication record. Read [approval-ledger.md](approval-ledger.md) for the schema and lifecycle.

GitHub publication is sparse: product decisions, material authority, PR collaboration, acceptance evidence, terminal receipts, operational receipts, and canonical tracker truth. Do not publish local queue state, claim chatter, scheduler state, routine stage completion, or process liveness.

Before publication, re-fetch the target, compare the source digest, reserve the outbox row, perform at most one external write in that publication round, and require exact readback. An ambiguous result remains readback-only; the terminal protocol alone may re-arm the same immutable envelope after its bounded exact-marker absence proof and unchanged source/graph revalidation. Use the GitHub-safe projection: publish public issue/PR identities, exact public heads, repository-relative leases, opaque run IDs, counts, verdicts, residual blockers, and one manifest fingerprint; keep absolute paths, tool locations, per-file hashes, cleanup targets, and archives owner-local.

## Issue-body mutation

Use `scripts/issue_body_cas.py` only with a provider transport that makes the expected body bytes/digest/timestamp precondition atomic with the body update. Bind expected and desired bytes and digests, reserve the desired-digest key, perform at most one update, and do one no-cache canonical readback. Without a provider-supported atomic primitive, return `POSTCONDITION_FAILED`; never approximate it with read-then-unconditional-write.

A validated append-only state/lease overlay is an exceptional read model for an otherwise authoring-complete historical body during a proven provider capability gap. It may supersede only volatile control state such as accepted main, dependency state, readiness, capacity, exact lease, endpoint state, controlling receipts, and next action. It never changes product scope, Gherkin, safety, approval, non-goals, or definition of done; never authorizes hosted work; and never makes a comment alone admission authority. New issues receive no exception and must validate before creation and after rendered readback.

## Hosted operations

Read [hosted-operations.md](hosted-operations.md) for worktree-free provider actions. Every operation binds the owning GitHub source and published authority, exact provider/target/operation tuple, closed scope, exclusions, stop conditions, SRE capacity, and terminal receipt. A fresh SRE attempt claims only after revalidation. Provider ambiguity is readback-only; never blindly retry.

Repository evidence does not authorize deployment, data, IAM, secret, access, traffic, billing, or production operations. Each boundary requires its own exact authority and predecessor evidence.

## Terminal closeout and artifacts

Accepted delivery requires the exact final head or operational state, natural gates, independent review or operational verdict, owning-issue receipt, exact resource cleanup, terminal-watch completion, lease release, and capacity release. These controls are one role-generic, attempt-authenticated two-phase terminal protocol on the original admission/watch lineage; they are not a second role handoff.

`prepare-terminal-closeout` accepts exactly one `twinfinity-terminal-closeout-packet/v1`. It revalidates the current role endpoint and `RUNNING` target-bound attempt, original admission and claim, active watch, item/source/generation/lease, exact current graph version/digest/main/node binding, typed `twinfinity-terminal-receipt/v1`, typed `twinfinity-terminal-cleanup/v1`, and the deterministic owning-issue publication. In one transaction it records the immutable packet, enqueues exactly one idempotent comment outbox row, and moves the item to persisted `PUBLICATION_PENDING`. The admission deliberately remains `CLAIMED`; `development.recovery_commit` likewise remains `CLAIMED` after recovery activation. Generic message completion cannot complete `development.admission`, `development.recovery_commit`, or `sre.admission`. Allocation remains `ACTIVE`, and role/shared units, lease, accountable endpoint, and watch remain held. Exact replay by the original completed preparer or a fresh current watcher returns the same packet and outbox without republishing.

Before reservation or POST, the terminal outbox records one immutable original publisher identity. The outbox must reach `COMPLETE` with an immutable exact-marker `comment:<id>` readback from that publisher. Its envelope, publisher binding, and completed readback cannot be rewritten. Ambiguous publication stays readback-only first; a rotated current actor may reconcile the exact original publisher's marker, but marker absence identity-HOLDs without re-arming or publishing. Only the original publisher may advance bounded absence attempts, and only after repeated proven absence may it re-arm the same immutable outbox against the unchanged current source/graph binding. Until then the derived terminal state is `PUBLICATION_PENDING` or `PUBLICATION_HOLD`, never `DONE`.

Once readback is exact, invoke `commit-terminal-closeout` without an evidence payload. The commit orchestration uses one fixed production acquisition path to fetch the normalized live owning issue, exact `refs/heads/main`, exact receipt comment, and owning-issue timeline before opening the final SQLite transaction; no caller may supply evidence bytes, observation time, or fetcher override. The paginated timeline must be the exact nonempty `--paginate --slurp` list-of-nonempty-list-pages shape with only nonempty dictionary events; flat, mixed, empty, or partially invalid results fail closed without filtering entries. The orchestration internally timestamps and self-digests one `twinfinity-terminal-live-evidence/v1` packet binding the immutable closeout packet, repository, issue, normalized source digest and source timestamp, stable material issue projection, current-main SHA, exact comment ID/body/original publisher/issue URL/timestamps, post-packet activity slice, and observation time. Inside the final transaction it re-reads the packet, cached full source digest, graph/main binding, endpoint, attempt, publisher, and readback; the internally acquired evidence must be no more than 60 seconds old and exactly equal those bindings. The terminal comment may account for only the issue's top-level `updated_at` delta: every other normalized issue field must remain byte-identical, the live issue timestamp must equal the unedited exact comment timestamp, and the publication-window timeline must contain only that comment. Material drift, a later timestamp, or any concurrent/unattributed activity is a zero-terminal-write HOLD; the live evidence digest and canonical packet become immutable fields of the terminal commit. The commit also revalidates the publication body and digest, current fresh watcher, immutable original admission/claim lineage, item, receipt, cleanup, lease, and absence of pending pre-push or artifact-GC work. An exact applied endpoint-rotation chain may advance the mutable item/watch owner while preserving the packet's original admission provenance. It then commits one SQLite transaction containing admission `COMPLETE`, `DONE/NONE`, terminal-watch `COMPLETE`, lease/allocation/capacity release, one immutable terminal commit, and one refill dirty event. A fresh exact same-lineage terminal-watch attempt may commit an immutable packet that a prior attempt already published; an exact completed finalizer may replay the receipt after acknowledgement loss without requiring a new live observation. Generic item-state calls cannot move `ACTIVE`, `RETAINED`, or `PUBLICATION_PENDING` work to allocation `NONE` or `DONE`; `development.terminal_closeout` is retired for new enqueue/claim and remains readable only for historical audit.

Register owner-local artifacts with exact digest, inode, issue, generation, and retention class. The guarded collector alone moves or purges eligible files after terminal item, watch, control, and outbox guards pass. It never scans arbitrary files or deletes the database, locks, symlinks, changed bytes, active/retained evidence, or another generation.

Canonical tracker publication follows verified state transitions. Terminal publication failure keeps the exact lineage in `PUBLICATION_PENDING` with its already-held capacity and lease; it never fabricates `DONE`, releases the watch, or emits a refill event. The supervisor recovers stale `RESERVED` attempts and only exact-systemd-proven inactive `LAUNCHING` or `RUNNING` attempts before scheduling. If a crash occurs after prepare, the packet suppresses admission relaunch and a fresh current watcher continues the retained lineage. Separately safe preparation can continue within the remaining policy capacity.

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
