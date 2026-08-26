# Twinfinity issue-authoring contract and template

Use this contract whenever Twinfinity work creates a GitHub issue or materially decomposes an epic into an executable, decision, monitor, operational, or follow-up leaf. The original creation body must be complete. Comments and later edits may record history or current state but never substitute for a skeletal original body.

## Required body content

Every new issue must contain these visible sections:

1. **User story** — `As a <beneficiary>, I want <capability or control>, so that <observable value or risk reduction>.` Name the actual Twin user, Twin owner/operator, customer organization, platform engineer, release operator, or other concrete beneficiary.
2. **Product or operational outcome** — one independently reviewable outcome classified as core platform, tenant configuration, DevOps/SRE maintenance, material decision, external gate, or out of product pending a reusable capability. Name parent and related issues.
3. **Current evidence and assumptions** — live or repository-declared facts, explicit inference, and bounded unknowns. Record exact main/head when drift matters. Keep secrets, private/customer data, sensitive payloads, and local topology out of GitHub.
4. **Dependencies and sequencing** — predecessors, approvals, shared surfaces, collision rule, capacity class, activation event, and deterministic successor or handoff.
5. **In scope** — bounded behavior, contracts, repository paths, or operational targets. If discovery is required, state the discovery boundary and stop before mutation.
6. **Out of scope and hard stops** — adjacent behavior, paths, providers, environments, data, refactors, migrations, UX, policy, or destructive actions the leaf may not absorb.
7. **Delivery plan** — ordered preflight, implementation/evaluation, evidence, independent acceptance, publication, cleanup, and Planner reconciliation steps.
8. **Gherkin BDD specification** — one fenced `gherkin` block beginning with `Feature:` and named scenarios using concrete `Given / When / Then` steps. Cover primary success and relevant fail-closed, authorization/privacy/tenant, dependency-failure, recovery/cleanup, and no-side-effect behavior.
9. **Scenario-to-evidence map** — map every named scenario to the lowest useful focused evidence and any distinct integration, UI, operational, full-gate, exact-head CI/review, cleanup, or receipt proof.
10. **Risks, safety, and approval boundary** — data classification, security/privacy/authorization impact, hosted/provider impact, rollback/recovery, abort conditions, and material decisions requiring direct user authority.
11. **Definition of done** — accepted outcome, scenario evidence, required gates, exact-head independent review, resolved material threads, owning-issue receipt, cleanup, capacity/lease release, and Planner-owned tracker delta.
12. **Ownership, readiness, and capacity** — current state, accountable role endpoint or activation event, declared allocation effect, and next deterministic action.

## Gherkin quality

- Use one capability-level `Feature:` per executable leaf and stable scenario names copied exactly into the evidence map.
- Describe observable behavior or control outcomes, not internal helper steps.
- Make actor, tenant, role, inputs, preconditions, trigger, result, and forbidden side effects unambiguous.
- Put representative bounded values in `Given` steps or a `Scenario Outline` `Examples:` table.
- Include applicable malformed, unauthorized, cross-tenant, stale, unavailable, partial, recovery, and cleanup behavior.
- Keep Introships vocabulary and values in typed tenant configuration. A scenario must prove a reusable Twinfinity capability or remain an external/configuration gate.
- Every scenario needs one credible evidence path before READY. Do not add ceremonial layers that prove no distinct failure mode.

## Issue-type adaptations

### Executable product or platform leaf

Require a bounded size, one-PR outcome, exact dependency state, collision-free lease proposal, concrete scenarios, scenario-to-test map, and a complete current-main admission plan. Do not mark READY until the body is complete and material decisions are effective.

### DevOps/SRE or dependency-maintenance leaf

Use the same structure. Name the operator or reliability outcome, exact repository or operational target, rollback and cleanup, no-hosted-side-effect behavior for non-deploying work, and every provider authorization boundary. Green CI alone is not the plan or acceptance evidence.

### Material decision

Use `DECISION REQUIRED` without a lease or writer allocation. Include options, tradeoffs, recommendation, exact user-authority source, downstream effect, Gherkin acceptance for the selected end state, and non-goals.

### Monitor, epic, or external gate

Do not fabricate an implementation lease. Retain the user story, measurable outcome, evidence, dependency or child plan, capability-level Gherkin, activation event, and definition of done. Parent acceptance never collapses into one child merge.

## Copyable issue body template

Copy the following block into the local body file. Remove instructional placeholders, not required headings. Use `Not applicable - <reason>` only when a section genuinely does not apply.

````markdown
## User story

As a <concrete beneficiary>, I want <capability or control>, so that <observable value or risk reduction>.

## Product or operational outcome

<One independently reviewable outcome and its scope class.>

## Parent and related issues

- Parent: #<issue>
- Related or successor: #<issue>

## Current evidence and assumptions

- Problem/context: <observable gap or risk>
- Verified: <live or repository fact and observation time or exact revision when relevant>
- Inferred: <explicitly labeled inference>
- Unknown: <bounded unknown and resolution path>

## Dependencies and sequencing

- Predecessors: <issues, decisions, or external gates>
- Shared surfaces and collision rule: <paths, contracts, or operational targets>
- Activation event: <decision, dependency, capacity, or external event>
- Successor or handoff: <deterministic next role and action>

## In scope

- <bounded behavior, path, contract, or operational target>

## Out of scope and hard stops

- <excluded behavior, environment, provider, data, refactor, migration, UX, or policy>

## Delivery plan

1. Revalidate current parent, dependencies, authority, main/head, policy, capacity, and collisions.
2. <Implement, evaluate, decide, or monitor the smallest complete outcome.>
3. Produce the scenario-mapped evidence and proportional full gates.
4. Obtain exact-head independent review or operational acceptance and resolve material findings.
5. Publish the owning-issue receipt, clean owned resources, release capacity/lease, and return the exact tracker delta to the Product Planner.

## Gherkin BDD specification

```gherkin
Feature: <capability or control outcome>

  Scenario: <primary observable success>
    Given <actor, tenant, concrete inputs, and preconditions>
    When <behavior or control is exercised>
    Then <observable outcome>
    And <required invariant>

  Scenario: <negative or fail-closed behavior>
    Given <concrete invalid, unauthorized, stale, unavailable, or conflicting state>
    When <behavior or control is exercised>
    Then <safe observable result>
    And <forbidden side effect does not occur>
```

## Scenario-to-evidence map

| Gherkin scenario | Evidence layer | Required proof |
| --- | --- | --- |
| `<primary observable success>` | <unit/integration/BDD/UI/operational> | <test, artifact, query, screenshot, or receipt> |
| `<negative or fail-closed behavior>` | <negative/security/recovery> | <test, artifact, audit, or no-side-effect proof> |

## Risks, safety, and approval boundary

- Data/security/privacy: <classification and fail-closed behavior>
- Recovery/rollback: <bounded recovery>
- Direct user authority required for: <material product, data, security, destructive, or hosted boundary; or none>
- Abort conditions: <conditions that stop work>

## Definition of done

- [ ] The independently reviewable outcome is complete without absorbing non-goals.
- [ ] Every named scenario has accepted evidence from the map.
- [ ] Proportional full gates and exact-head CI pass when applicable.
- [ ] Independent exact-head review or operational acceptance passes with no unresolved material finding.
- [ ] Owning-issue receipt and Product Planner tracker delta are complete.
- [ ] Branch, worktree, environment, resource, lease, watch, and capacity closeout are complete when applicable.

## Ownership, readiness, and capacity

- State: `MONITOR | DECISION REQUIRED | QUEUED | PREPARED | READY | ACTIVE | HOLD | BLOCKED | DONE`
- Accountable role or activation event: <planner, development, sre, or named external event>
- Capacity effect: Development <units>, Shared <units>, SRE <units>, or none
- Next deterministic action: <one specific event or action>
````

## Creation and verification transaction

1. Read live parent, tracker, dependency, decision, policy, capacity, and collision state.
2. Copy the embedded template into an owner-local body file and replace every placeholder. Make unknowns explicit.
3. Run `python3 references/validate_issue_body.py <body-file>` before creation and review product correctness after the structural check passes.
4. Create the issue from that exact file with accurate type, area, size, priority, readiness, milestone, and relationships. Do not use a shell-interpolated inline body or placeholder creation.
5. Re-fetch the rendered body into a fresh file, run the validator again, and verify the required headings, Gherkin names, evidence map, hard stops, definition of done, ownership, capacity effect, next action, and labels agree exactly once.
6. Repair any truncation, quoting damage, lost code fence, shell expansion, or concurrent replacement before readiness, admission, branch, lease, or tracker claims.
7. Reconcile later material state changes through the authorized body-mutation path while preserving decision and delivery history in append-only comments.

An issue title, label, parent link, or comment cannot supply missing original-body authority. A historical authoring-complete body may use only the narrow volatile-control overlay defined in [control-plane.md](control-plane.md#issue-body-mutation); new issue creation never receives that exception.

Keep volatile queue, readiness, and capacity state outside the stable product-and-delivery contract; publish it only through the bounded dashboard projection or authorized volatile-control overlay. Readiness labels and readiness-status prose are presentation, not delivery-control authority. Never write an issue so `agent-ready` or exact READY wording is a claim precondition: immutable readiness finalization, admission, source digest, generation, lease, endpoint, attempt, and watch rows own that handshake. Missing or stale projection cannot authorize work and does not veto an otherwise exact claim; any material body change produces source drift and still fails closed.
