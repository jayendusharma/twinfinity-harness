# Central user approval ledger

Use this workflow only for material user decisions. Routine reversible engineering choices remain autonomous.

## Roles and authority

- A bounded read-only advisor may draft a packet but cannot submit, decide, publish, claim, or acknowledge it.
- During admitted execution, the accountable fresh Development or SRE endpoint attempt submits its own packet.
- During a non-authorizing readiness phase, a Development or SRE worker may only stage one strict proposal input inside its terminal `APPROVAL_REQUIRED` receipt. It neither submits the proposal nor asks the human. After that exact message and attempt are `COMPLETE`, supervisor pickup authenticates provenance and submits/binds the exact input.
- Only the Product Planner records the user's decision.
- A proposal and a locally recorded decision grant no mutation authority.
- The decision becomes claimable only after its exact owning-issue outbox record is published and read back.
- Semantically identical packets from multiple canonical parents cluster into one user question while preserving every immutable submission and workstream interest.
- A decision creates one exact delivery per interested canonical recipient; each recipient claims and acknowledges only its own delivery. A `READINESS` delivery is addressed to the historical Planner recipient and consumed by the current role-equivalent Planner through the readiness decision gateway.
- #179 is an asynchronous external index. It is not a queue, acknowledgement channel, or authority source.

## Proposal schema

Submit one strict JSON object with exactly these fields:

```json
{
  "schema": "twinfinity.approval-proposal.v2",
  "decision_key": "issue-000:stable-semantic-key",
  "repository": "twinfinityai/twinfinityapp",
  "owning_issue": 1,
  "source_snapshot_sha256": "<64 lowercase hex characters>",
  "execution_scope_sha256": "<digest of the exact admission or hosted-operation scope>",
  "requester_session_id": "<current accountable role endpoint ID>",
  "recipient_session_id": "<same current accountable role endpoint ID>",
  "workstream": "DEVELOPMENT",
  "boundary": "PRODUCT_BEHAVIOR",
  "priority": "P0",
  "urgency": "ACTIVE_BLOCKER",
  "summary": "One plain-language decision summary.",
  "question": "One independently answerable question?",
  "requested_action": "The exact bounded action if approved.",
  "target": "The exact issue, repository surface, or hosted target class.",
  "affected_issues": [1],
  "blocked_mutation": "The exact material mutation currently paused.",
  "immediate_beneficiary": "The owner or operator who receives the outcome.",
  "evidence": ["Secret-safe evidence reference or digest."],
  "risk": "Consequence of the wrong decision.",
  "drift_guards": ["The source and exact target must remain unchanged."],
  "prohibited_side_effects": ["Explicit non-goal or adjacent action."],
  "options": [
    {"id": "OPTION_A", "label": "Option A", "effect": "Bounded effect.", "machine_outcome": "APPROVE"},
    {"id": "OPTION_B", "label": "Option B", "effect": "Bounded effect.", "machine_outcome": "REJECT"}
  ],
  "recommendation": "OPTION_A",
  "expires_at": null
}
```

Allowed workstreams are `DEVELOPMENT`, `SRE`, `READINESS`, `PLANNER`, `PORTFOLIO`, and `CLIENT`. Ordinary Development/SRE packets use the same endpoint for requester and recipient. `READINESS` is narrowly reserved for terminal supervisor pickup: requester is the exact authenticated Development/SRE readiness endpoint and attempt, recipient is the current Planner, urgency is `READY_BLOCKER`, and the immutable request additionally binds campaign, generation, item version, accepted main, graph/policy versions, candidate, worker role/endpoint/attempt, parent plan, material boundary, fixed decision mapping, and exact execution-scope digest. Allowed boundaries are `PRODUCT_BEHAVIOR`, `UX_FLOW`, `PERSISTENT_DATA`, `PUBLIC_CONTRACT`, `SECURITY_PRIVACY`, `HOSTED_PROVIDER`, `DESTRUCTIVE`, `EXTERNAL_COMMITMENT`, `CAPACITY_POLICY`, and `OTHER_MATERIAL`. Urgency is `ACTIVE_BLOCKER`, `READY_BLOCKER`, `FUTURE`, or `INFORMATIONAL`.

Never store secrets, private rows, Auth identities, Storage objects, customer data, bearer tokens, credential values, or URLs containing secret query parameters.

### Versioned semantic identity

`twinfinity.approval-proposal.v2` is the current source contract for newly
issued authority. Its immutable semantic identity includes every field shown
above, including the ordered, secret-safe `evidence` list. Consequently an
evidence-only substitution produces a different semantic and proposal digest;
recomputing an outer packet digest cannot preserve the former authority.

Historical `twinfinity.approval-proposal.v1` packets, identifiers, decisions,
and rows remain byte-immutable audit evidence. Before an explicitly authorized
v2 activation they retain their legacy behavior. After the monotonic semantic
contract pointer is activated to v2, every authority-bearing v1 current,
pending, publication-waiting, deliverable, claimed-but-unacknowledged, or
effective lineage fails closed with
`APPROVAL_LEGACY_V1_AUTHORITY_QUARANTINED` before it can authorize new work.
Do not relabel, rekey, reinterpret, or automatically convert v1 history. An
explicit revoke or HOLD may terminalize it; continued work requires a fresh v2
proposal, review batch, user decision, publication/readback, claim,
acknowledgement, and exact-scope effectivity. Source support for v2 does not
itself activate the pointer or migrate a live database; those are separately
authorized stopped-state operations.

### Fenced semantic-contract v2 activation

The registered activation surface is fixed to the owner coordination database,
this harness repository, the v1-to-v2 transition, and the existing approval
schema. It accepts no database, SQL, Python function, endpoint, or target-version
selector. A separately authorized stopped-state SRE packet must first produce
one canonical request with exactly these fields:

```json
{
  "accepted_harness_main_sha": "<40 lowercase hex characters>",
  "expected_v1_pointer": {
    "activated_at": "<exact existing pointer timestamp>",
    "authority_sha256": "<exact existing v1 authority digest>",
    "schema": "twinfinity.approval-proposal.v1",
    "singleton": 1
  },
  "legacy_authority_inventory_sha256": "<64 lowercase hex characters>",
  "operation_key": "<unique bounded operation key>",
  "repository": "jayendusharma/twinfinity-harness",
  "schema": "twinfinity.approval-semantic-contract-v2-activation-request.v1",
  "schema_sentinel_sha256": "<digest emitted by the matching reviewed source>",
  "stopped_state_evidence_sha256": "<64 lowercase hex characters>",
  "v2_authority_sha256": "<64 lowercase hex characters>"
}
```

The request file must contain the canonical compact JSON bytes. The accepted
harness source, legacy-authority inventory, stopped-state proof, and v2
authority digests are closed evidence assertions from that SRE packet; this
command binds them atomically but does not invent or broaden their authority.
The expected pointer binds all four existing row fields, not only the schema
name. An absent pointer is not implicit v1 for this operation.

Preview with the fixed non-mutating command:

```bash
python3 scripts/approval_ledger.py semantic-contract-v2-preview \
  --request <owner-local-canonical-request.json>
```

Before opening SQLite mutably, preview requires an owner-only existing database
with no rollback journal, WAL, or SHM sidecar; exact compiled table, column,
foreign-key, and trigger sentinels for
`approval_semantic_contract_current` and `approval_events`; the exact explicit
v1 pointer; and no prior activation receipt. It returns a canonical request
digest and preview digest and creates no database, table, row, sidecar, event,
or receipt. An exact already-applied operation may reproduce the same preview
only after its v2 pointer and durable receipt both validate.

Apply consumes both preview bindings:

```bash
python3 scripts/approval_ledger.py semantic-contract-v2-apply \
  --request <owner-local-canonical-request.json> \
  --expected-request-sha256 <request digest> \
  --expected-preview-sha256 <preview digest>
```

Apply repeats the sidecar-free read-only preflight, then opens only the fixed
existing database. One `BEGIN IMMEDIATE` transaction revalidates the sentinel
and full pointer, compare-and-swaps that exact v1 row to the request's v2
authority, and appends one fixed `APPROVAL_SEMANTIC_CONTRACT_V2_ACTIVATED`
operation receipt to `approval_events`. Pointer and receipt commit together or
both roll back. The receipt digest binds the complete request, request and
preview digests, schema sentinel, exact result pointer, and original activation
time. A byte-identical replay returns that same receipt without a mutable open;
another authority, source, inventory, stopped-state proof, pointer, operation
key, request digest, preview digest, missing receipt, or duplicate receipt is a
zero-write HOLD.

Stable preflight failures include
`APPROVAL_SEMANTIC_CONTRACT_SCHEMA_SENTINEL_REQUIRED`,
`APPROVAL_SEMANTIC_CONTRACT_SCHEMA_SENTINEL_INVALID`,
`APPROVAL_SEMANTIC_CONTRACT_EXPLICIT_V1_POINTER_REQUIRED`,
`APPROVAL_SEMANTIC_CONTRACT_ACTIVATION_POINTER_DRIFT`, and
`APPROVAL_SEMANTIC_CONTRACT_ACTIVATION_NOT_QUIESCENT`. The command never seeds
an absent v1 pointer, creates or migrates schema, installs reviewed source,
starts services or timers, changes endpoints, or launches an application
canary. Those effects retain their separate authority and evidence boundaries.

## Transaction sequence

1. Refresh and ingest the owning issue snapshot.
2. Submit: `python3 scripts/approval_ledger.py submit --packet <owner-local-json>`. The same transaction enqueues one non-authorizing, idempotent Planner planning notice, so the coordination supervisor can wake a fresh Planner endpoint attempt without GitHub queue traffic.
3. Planner furnishes one ranked bundle covering every source-current pending proposal: `python3 scripts/approval_ledger.py review-batch --repository twinfinityai/twinfinityapp`. The immutable batch freezes each proposal's exact source, execution scope, recipient set, full option map, and option-to-machine-outcome mapping.
4. Planner captures the user's answers in one canonical `twinfinity.approval-batch-answer-map.v1` file bound to the returned batch digest, then records each selected option with `decide --batch-sha256 <digest> --batch-answer-map <owner-local-json>`. The ledger derives `APPROVE`, `REJECT`, `DEFER`, or `COURSE_CORRECT` only from the frozen option; a caller-supplied outcome mismatch fails closed. The same exact user event may support multiple answers from that one answer map, but an unbatched decision, late recipient, changed source/scope/option map, conflicting answer bytes, or cross-batch event reuse is rejected. `DEFER` also requires a concrete revisit trigger and remains a durable `HOLD`; it is never hidden as completed work. The event source is `CODEX_DIRECT_USER_TURN`, `GITHUB_USER_COMMENT`, or `EXTERNAL_CLIENT_RECORD`.
5. Publish the returned `owner_outbox_id` through `publish_coordination_outbox.py` with its required confirmation and verify `COMPLETE` readback.
6. Every interested exact recipient uses `claim` for its own delivery. Claim refreshes the owning issue, permits only publication timestamp/projection drift, records or revalidates one immutable effectivity source digest, and places material source drift on durable HOLD. The returned payload is the bounded decision handoff.
7. After ingesting and acting on the decision state—not necessarily executing an approved mutation—the exact recipient uses `ack` with the decision digest.
8. Planner asynchronously reconciles #179 and any affected sprint tracker. Until provider-safe body reconciliation succeeds, report `TRACKER_BODY_PENDING` without invalidating the exact owning-issue receipt.

### Readiness-specific sequence

1. The readiness worker discovers an unanticipated material gate while completing its one candidate phase. Its one `APPROVAL_REQUIRED` receipt carries the closed proposal input and fixed mapping `APPROVE -> APPROVAL_RESUME`; `REJECT`, `DEFER`, and `COURSE_CORRECT -> HOLD`. It does not call `submit` or solicit the user.
2. Only after the exact worker message and attempt are `COMPLETE`, receipt pickup verifies the authenticated staged artifact and atomically records the receipt, immutable readiness request, proposal/submission, and `APPROVAL_PENDING`. The proposal-review notice is the only Planner notice for this verdict; no generic receipt-result notice is duplicated.
3. Only the Product Planner reviews the proposal and asks the user. For readiness `DEFER`, `decide` requires a strict RFC3339 UTC timestamp with no fractional seconds. The initial delivery remains `WAITING_PUBLICATION`, including `DEFER`.
4. After the exact owning-issue outbox publication and readback are `COMPLETE`, the supervisor creates one idempotent decision notice routed to the current Planner. No polling messages are emitted.
5. The Planner runs `python3 scripts/kanban_pull_buffer.py readiness-apply-decision --message-id <id> --planner-session-id <current-planner-endpoint> --source <fresh-owning-issue-json>`. One transaction claims the exact message and historical role-equivalent delivery, verifies the immutable request/submission/receipt/campaign/version/source/scope/boundary/publication/revocation bindings, applies the fixed disposition, records immutable consumption, acknowledges the delivery, and completes the message. The generic message claimant and caller-authored `readiness-resume` path are prohibited.
6. `APPROVE` derives one deterministic v2 successor from the stored parent campaign/plan and registers no writer WIP. `REJECT` remains terminal `HOLD`. `COURSE_CORRECT` remains `HOLD` and any materially changed execution requires a fresh proposal. `DEFER` remains `HOLD`; when its typed `AT` trigger becomes due, the supervisor creates exactly one Planner re-review notice and never treats it as approval. Material stable-source drift becomes `STALE`.
7. Comment, projection, and timestamp-only source churn may be recorded as immutable stable equivalence without advancing the readiness claim's planning source pointer. The in-transaction `github_current` snapshot and its expected digest remain authoritative; caller-supplied bytes cannot hide material drift. The same approval guard runs again before readiness dispatch/finalization and READY admission. A revocation stops an unconsumed wait or any `PENDING`, `RUNNING`, `READY_ELIGIBLE`, or `FINALIZED` approval-resumed successor and creates at most one Planner disposition wake before convergence.

## Lifecycle and drift

- Exact submission resubmission is idempotent. Within one semantic-contract version, requester-independent semantic identity clusters matching workstreams without losing their immutable packets, priorities, urgency, or recipient interests. v1 and v2 are never interchangeable authority. Once a decision is recorded, its recipient set is frozen: an existing recipient may append immutable workstream evidence, but a new recipient requires a successor proposal and publication.
- Changed packet bytes create a monotonic successor generation and preserve the predecessor.
- A decided proposal cannot be superseded while any non-held delivery remains in flight. A user reversal uses `revoke`; it appends immutable provenance and an owning-issue outbox receipt, atomically holds unconsumed deliveries, and invalidates the old authority guard before a corrected successor is admitted.
- Source drift before decision excludes the proposal from a review batch and requires a refreshed successor; it does not create another user question.
- `COURSE_CORRECT` never authorizes the original execution; readiness keeps the exact lineage on durable `HOLD`, and changed execution requires a fresh proposal. Ordinary non-readiness `DEFER` remains a durable delivery `HOLD` with its concrete revisit evidence. Readiness `DEFER` alone stays claimable after publication, is consumed into a readiness `HOLD`, and requires the strict typed `AT` trigger described above.
- Publication ambiguity or failure is a HOLD. Never deliver from a local decision alone.
- Recipient/requester mismatch, workstream mismatch, boundary mismatch, execution-scope mismatch, proposal supersession, missing or drifted review-batch/answer-map bindings, conflicting decision bytes, wrong current Planner, missing publication, material current-source drift, or revocation fails closed. Role-equivalent consumption preserves the frozen historical recipient row across a reviewed endpoint cutover while requiring the current Planner as actor; it never rewrites the immutable batch. Development/SRE admission scope binds the exact issue, generation, item version, action, base, branch, worktree, lease, and capacity; hosted scope additionally binds provider, target kind/key, operation kind, and normalized operation scope.
- New Development material admissions bind the effective decision digest as their authority digest. Once a current proposal exists, an unrelated authority hash cannot bypass it. Mutating hosted operations always require the effective owning-decision publication comment; read-only hosted inventory remains outside that mutation guard.

Use `python3 scripts/approval_ledger.py summary --repository twinfinityai/twinfinityapp` for compact pending, stale, publication, deliverable, claimed, and acknowledged counts.
