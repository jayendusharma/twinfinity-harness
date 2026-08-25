# Central user approval ledger

Use this workflow only for material user decisions. Routine reversible engineering choices remain autonomous.

## Roles and authority

- A bounded read-only advisor may draft a packet but cannot submit, decide, publish, claim, or acknowledge it.
- The accountable fresh Development or SRE endpoint attempt submits its own packet.
- Only the Product Planner records the user's decision.
- A proposal and a locally recorded decision grant no mutation authority.
- The decision becomes claimable only after its exact owning-issue outbox record is published and read back.
- Semantically identical packets from multiple canonical parents cluster into one user question while preserving every immutable submission and workstream interest.
- A decision creates one exact delivery per interested canonical recipient; each recipient claims and acknowledges only its own delivery.
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

Allowed workstreams are `DEVELOPMENT`, `SRE`, `PLANNER`, `PORTFOLIO`, and `CLIENT`. Allowed boundaries are `PRODUCT_BEHAVIOR`, `UX_FLOW`, `PERSISTENT_DATA`, `PUBLIC_CONTRACT`, `SECURITY_PRIVACY`, `HOSTED_PROVIDER`, `DESTRUCTIVE`, `EXTERNAL_COMMITMENT`, `CAPACITY_POLICY`, and `OTHER_MATERIAL`. Urgency is `ACTIVE_BLOCKER`, `READY_BLOCKER`, `FUTURE`, or `INFORMATIONAL`.

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

## Lifecycle and drift

- Exact submission resubmission is idempotent. Requester-independent semantic identity clusters matching workstreams without losing their immutable packets, priorities, urgency, or recipient interests. Once a decision is recorded, its recipient set is frozen: an existing recipient may append immutable workstream evidence, but a new recipient requires a successor proposal and publication.
- Changed packet bytes create a monotonic successor generation and preserve the predecessor.
- A decided proposal cannot be superseded while any non-held delivery remains in flight. A user reversal uses `revoke`; it appends immutable provenance and an owning-issue outbox receipt, atomically holds unconsumed deliveries, and invalidates the old authority guard before a corrected successor is admitted.
- Source drift before decision excludes the proposal from a review batch and requires a refreshed successor; it does not create another user question.
- `COURSE_CORRECT` is delivered like any other decision. Changed execution requires a fresh successor proposal. `DEFER` remains queryable with its revisit trigger until a successor is justified.
- Publication ambiguity or failure is a HOLD. Never deliver from a local decision alone.
- Recipient mismatch, execution-scope mismatch, proposal supersession, conflicting decision bytes, or wrong Planner fails closed. Development/SRE admission scope binds the exact issue, generation, item version, action, base, branch, worktree, lease, and capacity; hosted scope additionally binds provider, target kind/key, operation kind, and normalized operation scope.
- New Development material admissions bind the effective decision digest as their authority digest. Once a current proposal exists, an unrelated authority hash cannot bypass it. Mutating hosted operations always require the effective owning-decision publication comment; read-only hosted inventory remains outside that mutation guard.

Use `python3 scripts/approval_ledger.py summary --repository twinfinityai/twinfinityapp` for compact pending, stale, publication, deliverable, claimed, and acknowledged counts.
