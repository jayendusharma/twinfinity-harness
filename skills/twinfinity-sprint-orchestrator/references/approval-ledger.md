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
  "schema": "twinfinity.approval-proposal.v1",
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
    {"id": "OPTION_A", "label": "Option A", "effect": "Bounded effect."},
    {"id": "OPTION_B", "label": "Option B", "effect": "Bounded effect."}
  ],
  "recommendation": "OPTION_A",
  "expires_at": null
}
```

Allowed workstreams are `DEVELOPMENT`, `SRE`, `READINESS`, `PLANNER`, `PORTFOLIO`, and `CLIENT`. Ordinary Development/SRE packets use the same endpoint for requester and recipient. `READINESS` is narrowly reserved for terminal supervisor pickup: requester is the exact authenticated Development/SRE readiness endpoint and attempt, recipient is the current Planner, urgency is `READY_BLOCKER`, and the immutable request additionally binds campaign, generation, item version, accepted main, graph/policy versions, candidate, worker role/endpoint/attempt, parent plan, material boundary, fixed decision mapping, and exact execution-scope digest. Allowed boundaries are `PRODUCT_BEHAVIOR`, `UX_FLOW`, `PERSISTENT_DATA`, `PUBLIC_CONTRACT`, `SECURITY_PRIVACY`, `HOSTED_PROVIDER`, `DESTRUCTIVE`, `EXTERNAL_COMMITMENT`, `CAPACITY_POLICY`, and `OTHER_MATERIAL`. Urgency is `ACTIVE_BLOCKER`, `READY_BLOCKER`, `FUTURE`, or `INFORMATIONAL`.

Never store secrets, private rows, Auth identities, Storage objects, customer data, bearer tokens, credential values, or URLs containing secret query parameters.

## Transaction sequence

1. Refresh and ingest the owning issue snapshot.
2. Submit: `python3 scripts/approval_ledger.py submit --packet <owner-local-json>`. The same transaction enqueues one non-authorizing, idempotent Planner planning notice, so the coordination supervisor can wake a fresh Planner endpoint attempt without GitHub queue traffic.
3. Planner furnishes one ranked bundle covering every source-current pending proposal: `python3 scripts/approval_ledger.py review-batch --repository twinfinityai/twinfinityapp`.
4. For each user answer, Planner records the exact outcome with `decide`, including the proposal digest, `APPROVE`, `REJECT`, `DEFER`, or `COURSE_CORRECT`, the selected option ID, the frozen recipient-set digest, the exact execution-scope digest, a secret-safe decision note, the direct user-input digest, one stable user-event source/ID, and the current Planner role endpoint. `DEFER` also requires a concrete revisit trigger and remains a durable `HOLD`; it is never hidden as completed work. The event source is `CODEX_DIRECT_USER_TURN`, `GITHUB_USER_COMMENT`, or `EXTERNAL_CLIENT_RECORD`. The same exact user event may support multiple decisions in one review bundle, but conflicting reuse fails closed.
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

- Exact submission resubmission is idempotent. Requester-independent semantic identity clusters matching workstreams without losing their immutable packets, priorities, urgency, or recipient interests. Once a decision is recorded, its recipient set is frozen: an existing recipient may append immutable workstream evidence, but a new recipient requires a successor proposal and publication.
- Changed packet bytes create a monotonic successor generation and preserve the predecessor.
- A decided proposal cannot be superseded while any non-held delivery remains in flight. A user reversal uses `revoke`; it appends immutable provenance and an owning-issue outbox receipt, atomically holds unconsumed deliveries, and invalidates the old authority guard before a corrected successor is admitted.
- Source drift before decision excludes the proposal from a review batch and requires a refreshed successor; it does not create another user question.
- `COURSE_CORRECT` never authorizes the original execution; readiness keeps the exact lineage on durable `HOLD`, and changed execution requires a fresh proposal. Ordinary non-readiness `DEFER` remains a durable delivery `HOLD` with its concrete revisit evidence. Readiness `DEFER` alone stays claimable after publication, is consumed into a readiness `HOLD`, and requires the strict typed `AT` trigger described above.
- Publication ambiguity or failure is a HOLD. Never deliver from a local decision alone.
- Recipient/requester mismatch, workstream mismatch, boundary mismatch, execution-scope mismatch, proposal supersession, conflicting decision bytes, wrong current Planner, missing publication, material current-source drift, or revocation fails closed. Role-equivalent consumption preserves immutable historical Planner delivery rows across v2+ endpoint cutovers while requiring the current Planner as actor. Development/SRE admission scope binds the exact issue, generation, item version, action, base, branch, worktree, lease, and capacity; hosted scope additionally binds provider, target kind/key, operation kind, and normalized operation scope.
- New Development material admissions bind the effective decision digest as their authority digest. Once a current proposal exists, an unrelated authority hash cannot bypass it. Mutating hosted operations always require the effective owning-decision publication comment; read-only hosted inventory remains outside that mutation guard.

Use `python3 scripts/approval_ledger.py summary --repository twinfinityai/twinfinityapp` for compact pending, stale, publication, deliverable, claimed, and acknowledged counts.
