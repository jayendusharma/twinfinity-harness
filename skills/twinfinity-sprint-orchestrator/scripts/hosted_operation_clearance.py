#!/usr/bin/env python3
"""Clear one approved hosted operation in one idempotent recipient window."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from actions_rerun_scope import (
    GitHubReader,
    build_scope_in_transaction,
    read_scope_inputs,
)
from approval_ledger import (
    acknowledge_decision_in_transaction,
    claim_decision_in_transaction,
    delivery_recipient_for_role,
)
from coordination_store import (
    CoordinationError,
    canonical_json,
    canonicalize_coordination_identity,
    coordination_identity_role,
    digest_json,
    utc_now,
)
from hosted_operation_control import HostedOperationControl
from sync_github_coordination import fetch_object


def _decision_row(
    control: HostedOperationControl,
    proposal_sha256: str,
    recipient_session_id: str,
) -> Any:
    stored_recipient = delivery_recipient_for_role(
        control.store, proposal_sha256, recipient_session_id
    )
    row = control.connection.execute(
        """
        SELECT x.state, x.decision_sha256, d.execution_scope_sha256,
               d.owner_outbox_id, o.state AS outbox_state, o.remote_receipt,
               p.repository, p.owning_issue
        FROM approval_deliveries x
        JOIN approval_decisions d USING(proposal_sha256, decision_sha256)
        JOIN approval_proposals p USING(proposal_sha256)
        JOIN approval_current c
          ON c.repository=p.repository AND c.owning_issue=p.owning_issue
         AND c.decision_key=p.decision_key AND c.proposal_sha256=p.proposal_sha256
        JOIN github_outbox o ON o.id=d.owner_outbox_id
        LEFT JOIN approval_revocations r USING(proposal_sha256, decision_sha256)
        WHERE x.proposal_sha256=? AND x.recipient_session_id=?
          AND r.decision_sha256 IS NULL
        """,
        (proposal_sha256, stored_recipient),
    ).fetchone()
    if row is None:
        raise CoordinationError("HOSTED_CLEARANCE_DECISION_INVALID")
    if row["outbox_state"] != "COMPLETE" or not row["remote_receipt"]:
        raise CoordinationError("APPROVAL_PUBLICATION_INCOMPLETE")
    return row


def clear_actions_rerun(
    control: HostedOperationControl,
    *,
    request: object,
    proposal_sha256: str,
    decision_sha256: str,
    authority_comment_id: int,
    idempotency_key: str,
    recipient_session_id: str,
    github: GitHubReader,
    source_refresher: Callable[[str, str, int], dict[str, Any]] = fetch_object,
    now: Callable[[], str] = utc_now,
) -> dict[str, Any]:
    if coordination_identity_role(control.connection, recipient_session_id) != "sre":
        raise CoordinationError("HOSTED_CLEARANCE_RECIPIENT_INVALID")
    recipient_session_id = canonicalize_coordination_identity(
        control.connection, recipient_session_id
    )
    row = _decision_row(control, proposal_sha256, recipient_session_id)
    if row["decision_sha256"] != decision_sha256:
        raise CoordinationError("APPROVAL_DELIVERY_BINDING_MISMATCH")
    if row["state"] not in {"WAITING_PUBLICATION", "CLAIMED", "ACKNOWLEDGED"}:
        raise CoordinationError("APPROVAL_DELIVERY_STATE_CONFLICT")

    scope_inputs = read_scope_inputs(request, github)
    refreshed_payload = source_refresher(
        row["repository"], "issue", int(row["owning_issue"])
    )
    if not isinstance(refreshed_payload, dict):
        raise CoordinationError("APPROVAL_SOURCE_REFRESH_INVALID")
    refreshed_payload_sha256 = digest_json(refreshed_payload)
    comment = control._fetch_authority_comment(
        row["repository"], int(row["owning_issue"]), authority_comment_id
    )
    authority_comment_sha256 = digest_json(comment)
    authority_body_sha256 = hashlib.sha256(comment["body"].encode("utf-8")).hexdigest()
    observed_at = now()

    with control.store.transaction():
        claimed = claim_decision_in_transaction(
            control.store,
            proposal_sha256=proposal_sha256,
            recipient_session_id=recipient_session_id,
            refreshed_payload=refreshed_payload,
            refreshed_payload_sha256=refreshed_payload_sha256,
            now=observed_at,
            allow_acknowledged_replay=True,
        )
        if claimed["decision_sha256"] != decision_sha256:
            raise CoordinationError("APPROVAL_DELIVERY_BINDING_MISMATCH")
        built = build_scope_in_transaction(
            control,
            request,
            scope_inputs["payload"],
            scope_inputs["payload_sha256"],
        )
        if (
            built["repository"] != row["repository"]
            or built["issue_number"] != int(row["owning_issue"])
            or built["hosted_execution_scope_sha256"]
            != claimed["execution_scope_sha256"]
        ):
            if control.connection.execute(
                "SELECT 1 FROM hosted_operations WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone() is not None:
                raise CoordinationError("HOSTED_IDEMPOTENCY_CONFLICT")
            raise CoordinationError("HOSTED_CLEARANCE_SCOPE_MISMATCH")
        transaction = {
            "idempotency_key": idempotency_key,
            "repository": built["repository"],
            "issue_number": built["issue_number"],
            "source_payload_sha256": built["source_payload_sha256"],
            "provider": built["provider"],
            "target_kind": built["target_kind"],
            "target_key": built["target_key"],
            "operation_kind": built["operation_kind"],
            "authority_comment_id": authority_comment_id,
            "authority_body_sha256": authority_body_sha256,
            "recipient_session_id": recipient_session_id,
            "sre_units": 1,
            "blocked_by_issue_number": None,
            "scope": built["scope"],
        }

        def acknowledge() -> None:
            acknowledge_decision_in_transaction(
                control.store,
                proposal_sha256=proposal_sha256,
                decision_sha256=decision_sha256,
                recipient_session_id=recipient_session_id,
                now=observed_at,
            )

        operation = control.prepare_in_transaction(
            transaction,
            observed_at,
            authority_comment=comment,
            authority_comment_sha256=authority_comment_sha256,
            retire_eligible_predecessors=True,
            require_prepared=True,
            before_apply=acknowledge,
        )
    return {
        "phase": "CLEARED",
        "proposal_sha256": proposal_sha256,
        "decision_sha256": decision_sha256,
        "execution_scope_sha256": built["hosted_execution_scope_sha256"],
        "operation_id": operation["id"],
        "operation_state": operation["state"],
        "idempotency_key": operation["idempotency_key"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-file", type=Path, required=True)
    parser.add_argument("--proposal-sha256", required=True)
    parser.add_argument("--decision-sha256", required=True)
    parser.add_argument("--authority-comment-id", type=int, required=True)
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--recipient-session-id", required=True)
    args = parser.parse_args()
    control = HostedOperationControl()
    try:
        request = json.loads(args.request_file.read_text(encoding="utf-8"))
        result = clear_actions_rerun(
            control,
            request=request,
            proposal_sha256=args.proposal_sha256,
            decision_sha256=args.decision_sha256,
            authority_comment_id=args.authority_comment_id,
            idempotency_key=args.idempotency_key,
            recipient_session_id=args.recipient_session_id,
            github=GitHubReader(),
        )
        print(canonical_json(result))
        return 0
    except (CoordinationError, json.JSONDecodeError, OSError) as exc:
        error = str(exc) if isinstance(exc, CoordinationError) else "HOSTED_CLEARANCE_FAILED"
        print(canonical_json({"phase": "HOLD", "error": error}))
        return 1
    finally:
        control.close()


if __name__ == "__main__":
    raise SystemExit(main())
