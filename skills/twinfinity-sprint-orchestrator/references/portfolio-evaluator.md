# Independent one-shot portfolio evaluator

Use this reference only when the Product Planner commissions a bounded read-only portfolio audit for a material trigger. The evaluator returns one terminal report and closes. It never controls queue order, capacity, leases, admission, attempts, GitHub, SQLite, repositories, CI, providers, or acceptance.

## Evidence and independence

- Give the evaluator the repository identity, material trigger, audit window, this rubric, and the smallest relevant source set. Do not provide the Planner's intended answer.
- Use live GitHub issues, rendered bodies, milestones, labels, PRs, exact heads, checks, reviews, threads, accepted main, releases, and published receipts.
- Read only compact current SQLite graph, policy, capacity, lease, attempt, watch, and queue summaries needed for the question.
- Treat chat, model history, and historical endpoint identity as out of scope.
- Separate verified facts, inference, unknowns, and data limitations. Never fabricate timestamps or metrics.
- Judge owner-visible outcomes and release learning, not issue, comment, PR, model, or acknowledgement volume.

## Scorecard

Score each affected dimension with evidence, trend where available, confidence, and the smallest corrective action:

1. **Product direction:** progress toward complete Twin Studio #131 while #120 remains a bounded Introships configuration and pilot.
2. **Portfolio design:** vertical value, outcome coverage, foundation-to-owner-visible balance, scope quality, and issue decomposition.
3. **Sequence and dependencies:** critical path, hard-edge correctness, cross-milestone constraints, collisions, orphan coverage, and avoidable gates.
4. **Delivery flow:** current active/retained/available allocation from SQLite, READY versus PREPARED/QUEUED depth, WIP and blocker age, handoff, review, CI, merge, cleanup, and successor latency.
5. **Throughput:** accepted and cleaned owner-visible outcomes over an evidence-supported bounded window, separated from enablers, preparation, maintenance, and dependency work.
6. **Quality and rework:** repair cycles, repeated gates, review churn, head moves, stale evidence, invalid environments, collision waste, and accepted-versus-discarded effort.
7. **Release and SRE readiness:** accepted-main convergence, dependency health, staging isolation, migration/recovery, access, synthetic journeys, observability, rollback/rebuild, and exact operational receipts.
8. **Milestone learning:** accepted outcomes, active critical-path leaves, remaining exit gates, and whether progress produces product/customer learning.
9. **Sustainability:** shared-surface concentration, control-plane churn, retained work, stale dependencies, evidence expiry, operational debt, and customer-specific runtime leakage.

Classify each product Development or Shared candidate:

- `END_TO_END`: independently demonstrable Twin user or owner/operator outcome with its minimum necessary surfaces;
- `BOUNDED_ENABLER`: cannot yet be vertical but names an immediate owner-visible consumer and activation evidence; or
- `RESTRUCTURE`: architecture-layer or broad scope that is not safe to admit as written.

Judge SRE maintenance and release outcomes separately; do not fabricate a product-feature consumer for operational work.

## Capacity evaluation

Read the active immutable SQLite policy rather than assuming limits. Capacity is a ceiling, not a utilization target. Distinguish active Development, Shared, and SRE allocation; retained allocation; independent READY depth; and PREPARED/QUEUED zero-WIP depth.

Recommend a policy change only from current measured readiness, disjoint ownership, review/merge bandwidth, repair frequency, CI latency, cleanup latency, incident/release posture, and rollback safety. State the evidence window, expected effect, guardrails, recheck event, and scale-down condition. Never recommend maximizing occupancy.

## Output

Return:

- executive verdict and confidence;
- a compact affected-dimension scorecard;
- verified throughput and latency table with window, numerator, denominator, and limitations;
- `Now / Next / Later / Hold` judgment;
- product lane table with beneficiary-visible outcome, minimum surfaces, allocation class, dependencies, collision boundary, activation event, successor, and verticality disposition;
- separate SRE/release-readiness verdict and shortest evidence gaps;
- at most three highest-value planning corrections with expected effect and recheck; and
- explicit unknowns that prevent a reliable conclusion.

If no evidence-supported correction exists, return `NO CHANGE`. The Product Planner independently refreshes the cited facts and decides every mutation. Do not re-arm the evaluator automatically; a later material trigger requires a new one-shot commission.

When a high-confidence finding identifies a repeated operating-model, role, goal, skill, or enforcement defect rather than portfolio sequencing, return one compact Governor input with the verified mechanism, recurrence or criticality, measurable effect, affected artifact, and recheck. Do not propose skill wording or edit anything.
