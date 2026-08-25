# Evidence-led skill and goal evaluation

Use this rubric only when `twinfinity-skill-governor` is triggered.

## Audit modes

### Targeted delta audit

Inspect the triggering event, the directly affected skill, current Planner-goal clause, endpoint profile, admission template, or shared authority reference, and the observable outcome. Avoid inventorying unrelated artifacts.

### Comprehensive audit

At an explicitly requested weekly or sprint boundary, inventory all installed `twinfinity-*` skills, the exact current Product Planner goal, current immutable role endpoints and profiles, typed Development/SRE admission and recovery templates, implicated mechanical guards, and end-to-end portfolio evidence. Do not invent durable Development/SRE goals.

## Evidence thresholds

Classify evidence before recommending an update:

- `CRITICAL`: one verified security, privacy, destructive-action, authority, production, or release-containment failure. A narrow immediate correction may be justified.
- `REPEATED`: at least two independent occurrences of the same mechanism, or recurrence after a prior correction.
- `TREND`: a measured deterioration across a declared window, such as repair cycles, duplicate gates, WIP age, merge latency, or release-gate stagnation.
- `DRIFT`: a current skill or goal contradicts live role, tool, product, or control-plane truth.
- `SPECULATION`: preference, hypothetical risk, or isolated ordinary defect without a reusable mechanism. Do not update.

Do not treat issue/comment volume as evidence. Separate code defects, execution noncompliance, instruction defects, and missing enforcement.

## Lean scorecard

Score only affected artifacts, using `0` poor to `3` strong:

| Dimension | Question |
|---|---|
| Outcome alignment | Does it improve owner-visible product or release learning? |
| Current relevance | Do its triggers, tools, and responsibilities match current reality? |
| Role clarity | Are ownership, authority, handoffs, and non-goals exact? |
| Observed effectiveness | Is there evidence that it improved outcomes or prevented recurrence? |
| Flow efficiency | Does it reduce latency, WIP, repeated gates, and coordination cost? |
| Enforceability | Are critical invariants mechanically guarded where feasible? |
| Consistency | Is it free of contradiction and duplication? |
| Context efficiency | Does each instruction materially change a decision? |

Any `0` requires `UPDATE`, `DELETE`, `MERGE`, `SPLIT`, or `RETIRE` consideration. A low score does not itself authorize a patch; the evidence threshold must also pass.

## Dispositions

- `KEEP`: current guidance remains relevant and effective.
- `UPDATE`: smallest evidence-supported correction.
- `DELETE`: stale or ineffective guidance with no surviving invariant.
- `MERGE`: duplicated guidance belongs in one shared authority source.
- `SPLIT`: one skill or goal combines responsibilities that need different triggers or owners.
- `RETIRE`: capability or role is no longer used or aligned.
- `MECHANIZE`: prose is already correct; enforcement belongs in a tool wrapper, admission guard, or workflow.
- `PROPOSE GOAL CHANGE`: the user-authored Product Planner goal or a material role boundary needs explicit approval.
- `NO UPDATE`: evidence does not justify change.

## End-to-end coverage map

Check that the operating model has accountable coverage without redundant agents for:

1. Product Manager vision, outcomes, roadmap, and product acceptance;
2. Product Planner issue design, dependency sequencing, capacity, admission, leases, attempts, watches, acknowledgements, and tracker truth;
3. fresh bounded Development execution with an exact worktree/branch and issue-owned environment;
4. focused evidence, applicable final-head Compose acceptance, guarded publication, CI, independent exact-head review, bounded repair, merge, cleanup, receipt, and capacity release;
5. accepted-main convergence and successor activation;
6. fresh bounded SRE maintenance, dependency health, and release engineering;
7. staging isolation, migration/recovery, access, observability, rollback, and production authorization;
8. customer learning and owner-visible outcome measurement; and
9. optional bounded portfolio, capacity, and skill-system advice on material triggers.

An uncovered stage may need a skill, endpoint contract, or mechanical guard. A covered stage with competing owners usually needs consolidation, not another durable agent.

## Update economics

For each proposed patch, state:

- evidence class and source;
- expected effect on one or more metrics;
- files and approximate instruction-size delta;
- why deletion, mechanical enforcement, or no change is insufficient;
- re-evaluation trigger and rollback/removal condition.

Prefer neutral or negative net instruction growth. New text must replace ambiguity, establish a proven missing invariant, or route a genuinely new capability.

For endpoint or admission changes, also state whether the fix belongs in the Development skill, SRE skill, endpoint profile, typed validator/template, hook, or shared transaction. Prefer the narrowest mechanically enforceable layer and keep Development/SRE permissions mutually exclusive.

## Self-correction and optimization

For each applied update, preserve a compact experiment record:

| Field | Requirement |
|---|---|
| Baseline | Pre-change metric or verified failure mechanism |
| Hypothesis | Why this skill change should alter an agent decision |
| Prediction | One falsifiable expected outcome |
| Guardrail | Product Manager, Product Planner, Development, SRE, safety, and authority boundaries that must remain unchanged |
| Recheck | Exact event or bounded window |
| Result | Observed outcome without coached evaluation |
| Disposition | `KEEP`, `REVISE`, `REVERT`, or `DELETE` |

Assess the governor itself at comprehensive audits:

- recommendations adopted versus rejected;
- repeated failures after an update;
- false alarms that caused unnecessary churn;
- material gaps it failed to identify;
- net instruction and context growth;
- measured flow, quality, or release effect.

Do not train on wording similarity or compliance theater. Use held-out realistic requests and live outcome evidence without leaking the intended answer. A critical invariant may remain even when rarely exercised, but redundant implementation detail should be removed.

## Compact output

Return one table:

| Artifact | Evidence | Diagnosis | Disposition | Change | Expected effect | Recheck |
|---|---|---|---|---|---|---|

Then list:

- updates applied;
- changes proposed but requiring approval;
- instructions deleted or growth avoided;
- validation/forward-test results;
- unresolved evidence gaps.

Do not produce a large narrative when the table is sufficient.
