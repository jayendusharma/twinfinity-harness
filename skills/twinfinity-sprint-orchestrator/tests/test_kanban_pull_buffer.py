from __future__ import annotations

import hashlib
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SKILL_ROOT))

from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    canonical_json,
)
from executor_registry import (  # noqa: E402
    load_registry_config,
    registry_config_scope,
)
import kanban_pull_buffer as pull_buffer  # noqa: E402
from kanban_pull_buffer import (  # noqa: E402
    PullBufferError,
    _park_matching_open_pull_requests,
    audit_pull_buffer,
    ensure_pull_buffer_schema,
    main as pull_buffer_main,
    quarantine_unattested_ready,
    ready_quarantine_inventory,
    register_candidate,
    show_pull_buffer,
)
from kanban_readiness import ensure_schema as ensure_readiness_schema  # noqa: E402
from portfolio_graph import replace_graph, sync_head  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan as apply_routing_plan,
    build_plan as build_routing_plan,
    load_legacy_alias_fixture,
)
from tests.canonical_ready_fixture import (  # noqa: E402
    finalize_canonical_ready_item,
)


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "1" * 40


class KanbanPullBufferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "coordinator"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        self.sources: dict[int, str] = {}
        self._issue(115, "Sprint 1")
        self._issue(251, "Sprint 2")
        self._issue(76, "Sprint 2")
        self._item(115, "QUEUED")
        self._item(251, "PREPARED")
        self._item(76, "HOLD")
        replace_graph(
            self.store.connection,
            self._plan(),
            now="2026-08-24T02:00:01Z",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _issue(self, number: int, milestone: str) -> None:
        snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=number,
            payload={
                "_projection_version": 3,
                "number": number,
                "title": f"Issue {number}",
                "state": "open",
                "updated_at": "2026-08-24T02:00:00Z",
                "milestone": {"number": 1, "title": milestone, "state": "open"},
            },
            source_updated_at="2026-08-24T02:00:00Z",
            fetched_at="2026-08-24T02:00:00Z",
        )
        self.sources[number] = snapshot.payload_sha256

    def _item(self, number: int, status: str) -> None:
        self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=number,
            status=status,
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=self.sources[number],
            expected_version=0,
            now="2026-08-24T02:00:01Z",
        )

    def _node(self, number: int, lane: str, order: int) -> dict:
        return {
            "node_key": f"issue:{number}",
            "issue_number": number,
            "role": "DELIVERY",
            "root_kind": "STANDALONE",
            "root_reason": "Independent test outcome",
            "lane_key": lane,
            "lane_order": order,
            "dispatchable": True,
            "priority_rank": order + 1,
            "estimate_units": 1,
            "development_units": 1,
            "shared_units": 1,
            "sre_units": 0,
            "source_payload_sha256": self.sources[number],
            "ready_at": "2026-08-24T02:00:00Z",
        }

    def _plan(self) -> dict:
        return {
            "repository": REPOSITORY,
            "accepted_main_sha": MAIN,
            "expected_current_version": 0,
            "scope_milestones": [
                {"title": "Sprint 1", "rank": 1},
                {"title": "Sprint 2", "rank": 2},
            ],
            "excluded_issues": [],
            "nodes": [
                self._node(115, "gate-a", 0),
                self._node(251, "studio-wave3a", 0),
                self._node(76, "durable-jobs", 0),
            ],
            "relations": [
                {
                    "left_node_key": "issue:251",
                    "right_node_key": "issue:76",
                    "relation_kind": "COLLISION",
                    "reason": "Shared migration family",
                    "source_payload_sha256": self.sources[251],
                }
            ],
        }

    def test_park_open_pull_matching_requires_branch_and_repository_identity(self) -> None:
        rows = [
            {
                "number": 145,
                "head": {
                    "ref": "change/144-exact",
                    "repo": {"full_name": "JayEnduSharma/Twinfinity-Harness"},
                },
            },
            {
                "number": 146,
                "head": {
                    "ref": "change/144-exact",
                    "repo": {"full_name": "fork-owner/twinfinity-harness"},
                },
            },
            {
                "number": 147,
                "head": {
                    "ref": "change/other",
                    "repo": {"full_name": "jayendusharma/twinfinity-harness"},
                },
            },
        ]
        self.assertEqual(
            [145],
            _park_matching_open_pull_requests(
                rows,
                branch="change/144-exact",
                repository="jayendusharma/twinfinity-harness",
            ),
        )

    def test_park_open_pull_matching_ignores_missing_or_deleted_head_repository(self) -> None:
        rows = [
            {"number": 145},
            {"number": 146, "head": {"ref": "change/144-exact"}},
            {
                "number": 147,
                "head": {"ref": "change/144-exact", "repo": None},
            },
            {
                "number": 148,
                "head": {"ref": "change/144-exact", "repo": {}},
            },
            {
                "number": 149,
                "head": {
                    "ref": "change/144-exact",
                    "repo": {"full_name": 149},
                },
            },
            {
                "number": 150,
                "head": {
                    "ref": "change/144-exact",
                    "repo": {"full_name": "not-a-repository"},
                },
            },
        ]
        self.assertEqual(
            [],
            _park_matching_open_pull_requests(
                rows,
                branch="change/144-exact",
                repository="jayendusharma/twinfinity-harness",
            ),
        )

    def test_park_open_pull_matching_rejects_invalid_target_repository(self) -> None:
        with self.assertRaisesRegex(
            PullBufferError, "PARK_REPOSITORY_OBSERVER_TARGET_DRIFT"
        ):
            _park_matching_open_pull_requests(
                [],
                branch="change/144-exact",
                repository=" jayendusharma/twinfinity-harness ",
            )

    def _packet(self, number: int, verticality: str, mutator=None) -> Path:
        item = self.store.connection.execute(
            "SELECT version FROM coordination_items WHERE repository=? AND issue_number=?",
            (REPOSITORY, number),
        ).fetchone()
        packet = {
            "schema": "twinfinity-kanban-pull-buffer/v2",
            "repository": REPOSITORY,
            "issue_number": number,
            "generation": 1,
            "item_version_at_preparation": int(item["version"]),
            "source_payload_sha256": self.sources[number],
            "accepted_main_at_preparation": MAIN,
            "portfolio_graph_version": 1,
            "capacity_policy": {
                "version": 1,
                "development_limit": 5,
                "shared_limit": 2,
                "sre_limit": 5,
            },
            "state": "PREPARED_NOT_READY",
            "verticality": verticality,
            "owner_visible_outcome": f"Outcome {number}",
            "capacity_on_activation": {
                "development_units": 1,
                "shared_units": 1,
                "sre_units": 0,
            },
            "precomputed_collision_matrix": [
                {
                    "other_issue": 76 if number != 76 else 251,
                    "disposition": "AUDIT",
                    "reason": "Exact path audit required",
                }
            ],
            "preparation_complete": ["Outcome and activation trigger are explicit."],
            "promotion_checks_after_predecessor": ["Refresh main and lease."],
            "hard_stops": ["No mutation before admission."],
            "promotion_trigger": "Promote after predecessor terminal release.",
        }
        if verticality == "BOUNDED_ENABLER":
            packet["immediate_product_consumer"] = "Issue #298"
        if mutator is not None:
            mutator(packet)
        plans = self.root / "plans"
        plans.mkdir(exist_ok=True)
        path = plans / f"issue-{number}-packet.json"
        path.write_text(json.dumps(packet, sort_keys=True), encoding="utf-8")
        self.store.register_artifacts(
            [
                {
                    "repository": REPOSITORY,
                    "issue_number": number,
                    "generation": 1,
                    "path": str(path),
                    "retention_class": "CLOSEOUT_EVIDENCE",
                }
            ],
            now="2026-08-24T02:00:02Z",
        )
        return path

    def _seed_ready_item(
        self,
        number: int,
        *,
        repository: str = REPOSITORY,
        with_candidate: bool = True,
        readiness_state: str | None = None,
    ) -> dict:
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        snapshot = self.store.ingest_snapshot(
            repository=repository,
            object_kind="issue",
            object_number=number,
            payload={
                "_projection_version": 3,
                "number": number,
                "title": f"Legacy READY {number}",
                "state": "open",
                "updated_at": "2026-08-24T02:00:00Z",
                "milestone": None,
            },
            source_updated_at="2026-08-24T02:00:00Z",
            fetched_at="2026-08-24T02:00:00Z",
        )
        self.store.connection.execute(
            "INSERT INTO coordination_items("
            "repository,issue_number,status,allocation_class,generation,"
            "accountable_session_id,lease_manifest_sha256,development_units,"
            "shared_units,sre_units,source_payload_sha256,version,updated_at) "
            "VALUES (?,?,'READY','NONE',1,NULL,NULL,1,0,0,?,1,?)",
            (
                repository,
                number,
                snapshot.payload_sha256,
                "2026-08-24T02:00:01Z",
            ),
        )
        candidate = None
        if with_candidate:
            candidate_sha = hashlib.sha256(
                f"legacy-ready:{repository}:{number}".encode()
            ).hexdigest()
            artifact_sha = hashlib.sha256(
                f"legacy-artifact:{repository}:{number}".encode()
            ).hexdigest()
            self.store.connection.execute(
                "INSERT INTO portfolio_pull_buffer_candidates("
                "repository,issue_number,generation,item_version,"
                "source_payload_sha256,accepted_main_sha,graph_version,"
                "capacity_policy_version,lane_key,state,verticality,"
                "development_units,shared_units,sre_units,promotion_trigger,"
                "artifact_relative_path,artifact_content_sha256,"
                "candidate_sha256,registered_at) "
                "VALUES (?,?,1,1,?,?,1,1,?,'READY','END_TO_END',1,0,0,"
                "'Legacy cutover',?,?,?,?)",
                (
                    repository,
                    number,
                    snapshot.payload_sha256,
                    MAIN,
                    f"lane-{number}",
                    f"legacy-{number}.json",
                    artifact_sha,
                    candidate_sha,
                    "2026-08-24T02:00:01Z",
                ),
            )
            candidate = self.store.connection.execute(
                "SELECT * FROM portfolio_pull_buffer_candidates "
                "WHERE repository=? AND issue_number=? ORDER BY id DESC LIMIT 1",
                (repository, number),
            ).fetchone()
            self.store.connection.execute(
                "INSERT INTO portfolio_pull_buffer_current("
                "repository,issue_number,candidate_id,updated_at) VALUES (?,?,?,?)",
                (
                    repository,
                    number,
                    int(candidate["id"]),
                    "2026-08-24T02:00:01Z",
                ),
            )
        if readiness_state is not None:
            plan_sha = hashlib.sha256(
                f"legacy-plan:{repository}:{number}".encode()
            ).hexdigest()
            self.store.connection.execute(
                "INSERT INTO portfolio_readiness_campaigns("
                "repository,issue_number,generation,item_version,"
                "source_payload_sha256,accepted_main_sha,graph_version,"
                "capacity_policy_version,candidate_sha256,worker_role,"
                "phase_summary,plan_sha256,plan_json,created_at) "
                "VALUES (?,?,1,1,?,?,1,1,?,'development',?,?,?,?)",
                (
                    repository,
                    number,
                    snapshot.payload_sha256,
                    MAIN,
                    "0" * 64 if candidate is None else candidate["candidate_sha256"],
                    "Legacy readiness",
                    plan_sha,
                    "{}",
                    "2026-08-24T02:00:01Z",
                ),
            )
            campaign_id = int(self.store.connection.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()[0])
            self.store.connection.execute(
                "INSERT INTO portfolio_readiness_current("
                "repository,issue_number,campaign_id,state,version,updated_at) "
                "VALUES (?,?,?,?,1,?)",
                (
                    repository,
                    number,
                    campaign_id,
                    readiness_state,
                    "2026-08-24T02:00:01Z",
                ),
            )
        return {
            "repository": repository,
            "issue_number": number,
            "source_payload_sha256": snapshot.payload_sha256,
            "candidate_id": None if candidate is None else int(candidate["id"]),
        }

    def _install_executor_registry(self) -> None:
        skill_root = Path(__file__).resolve().parents[1]
        config = load_registry_config(
            skill_root / "tests" / "fixtures" / "twinfinity-executor-registry-v4.toml"
        )
        aliases, alias_sha = load_legacy_alias_fixture(
            skill_root / "tests" / "fixtures" / "legacy-role-aliases.json"
        )
        plan = build_routing_plan(
            self.store.connection,
            config,
            aliases,
            alias_fixture_sha256=alias_sha,
        )
        apply_routing_plan(
            self.store.connection,
            plan=plan,
            operation_key="ready-quarantine-tests",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T02:00:01Z",
        )
        self.registry_config = config

    def _add_prepared_graph_item(self, number: int) -> None:
        self._issue(number, "Sprint 2")
        self._item(number, "PREPARED")
        plan = self._plan()
        plan["expected_current_version"] = 1
        plan["nodes"].append(self._node(number, f"ready-{number}", 0))
        replace_graph(
            self.store.connection,
            plan,
            now="2026-08-24T02:00:02Z",
        )

    def _finalize_canonical_ready(self, number: int, suffix: str) -> dict:
        with registry_config_scope(self.registry_config):
            result = finalize_canonical_ready_item(
                self.store,
                database=self.database,
                artifact_root=self.root,
                repository=REPOSITORY,
                issue_number=number,
                source_payload_sha256=self.sources[number],
                accepted_main_sha=MAIN,
                worker_role="development",
                worker_endpoint_id="role.development.v4",
                now="2026-08-24T02:00:03Z",
                suffix=suffix,
            )
        return {
            **result,
            "issue_number": number,
            "candidate_id": int(result["finalized"]["candidate_id"]),
        }

    def _quarantine_request(
        self, repository: str = REPOSITORY, *, operation_key: str = "cutover"
    ) -> dict:
        inventory = ready_quarantine_inventory(self.store.connection, repository)
        return {
            "schema": "twinfinity-ready-quarantine-request/v1",
            "repository": repository,
            "operation_key": operation_key,
            "source_harness_repository": "jayendusharma/twinfinity-harness",
            "source_harness_main_sha": "2" * 40,
            "expected_ready_inventory_sha256": inventory["inventory_sha256"],
            "cutover_authority_sha256": "3" * 64,
        }

    def _database_snapshot(self) -> dict[str, tuple[tuple, ...]]:
        names = [
            str(row[0])
            for row in self.store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        return {
            name: tuple(
                tuple(row)
                for row in self.store.connection.execute(
                    f'SELECT * FROM "{name}" ORDER BY rowid'
                )
            )
            for name in names
        }

    def _assert_quarantine_rejected_without_write(
        self, request: dict, pattern: str
    ) -> None:
        before = self._database_snapshot()
        with self.assertRaisesRegex(PullBufferError, pattern):
            quarantine_unattested_ready(
                self.store, request, now="2026-08-24T02:00:07Z"
            )
        self.assertEqual(before, self._database_snapshot())

    def _seed_pre_push_publication(
        self,
        repository: str,
        issue_number: int,
        *,
        state: str = "RESERVED",
    ) -> tuple[int, int]:
        source_sha256 = self.sources.get(issue_number, "8" * 64)
        payload = {
            "source": {
                "repository": repository,
                "object_kind": "issue",
                "object_number": issue_number,
                "payload_sha256": source_sha256,
            },
            "issue_number": issue_number,
            "generation": 1,
        }
        payload_json = canonical_json(payload)
        payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()
        message_id = int(
            self.store.connection.execute(
                "INSERT INTO coordination_messages("
                "idempotency_key,recipient_session_id,topic,payload_sha256,"
                "payload_json,state,created_at,updated_at) "
                "VALUES (?,?,?,?,?,'COMPLETE',?,?)",
                (
                    f"quarantine-prepush:{repository}:{issue_number}:{state}",
                    "role.development.v6",
                    "development.admission",
                    payload_sha256,
                    payload_json,
                    "2026-08-24T02:00:04Z",
                    "2026-08-24T02:00:04Z",
                ),
            ).lastrowid
        )
        gate_id = int(
            self.store.connection.execute(
                "INSERT INTO coordination_pre_push_gates("
                "repository,issue_number,generation,accountable_session_id,"
                "source_payload_sha256,lease_manifest_sha256,"
                "admission_message_id,admission_payload_sha256,branch,"
                "worktree_path,base_sha,head_sha,changed_paths_sha256,"
                "changed_path_count,lower_gate,lower_gate_exit_code,"
                "compose_gate,compose_gate_exit_code,compose_run_id,"
                "head_unchanged,cleanup_proven,state,evidence_sha256,"
                "environment_provenance_sha256,started_at,completed_at,last_error) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    repository,
                    issue_number,
                    1,
                    "role.development.v6",
                    source_sha256,
                    "4" * 64,
                    message_id,
                    payload_sha256,
                    f"change/{issue_number}-synthetic",
                    f"/tmp/issue-{issue_number}",
                    "5" * 40,
                    "6" * 40,
                    "7" * 64,
                    1,
                    "PASS",
                    0,
                    "NOT_APPLICABLE",
                    None,
                    f"synthetic-{issue_number}",
                    1,
                    1,
                    "PASS",
                    "9" * 64,
                    "a" * 64,
                    "2026-08-24T02:00:04Z",
                    "2026-08-24T02:00:05Z",
                    None,
                ),
            ).lastrowid
        )
        publication_id = int(
            self.store.connection.execute(
                "INSERT INTO coordination_pre_push_publications("
                "gate_id,repository,issue_number,generation,"
                "accountable_session_id,source_payload_sha256,"
                "lease_manifest_sha256,admission_message_id,branch,head_sha,"
                "remote_name,remote_url_sha256,state,created_at,updated_at,last_error) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,'origin',?,?,?,?,?)",
                (
                    gate_id,
                    repository,
                    issue_number,
                    1,
                    "role.development.v6",
                    source_sha256,
                    "4" * 64,
                    message_id,
                    f"change/{issue_number}-synthetic",
                    "6" * 40,
                    "b" * 64,
                    state,
                    "2026-08-24T02:00:06Z",
                    "2026-08-24T02:00:06Z",
                    None,
                ),
            ).lastrowid
        )
        return gate_id, publication_id

    def _seed_terminal_claimed_message(
        self,
        *,
        key: str,
        payload_json: str,
        state: str,
        topic: str = "development.admission",
        payload_sha256: str | None = None,
    ) -> tuple[int, int]:
        message_id = int(
            self.store.connection.execute(
                "INSERT INTO coordination_messages("
                "idempotency_key,recipient_session_id,topic,payload_sha256,"
                "payload_json,state,claimed_by,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    key,
                    "role.development.v6",
                    topic,
                    payload_sha256
                    if payload_sha256 is not None
                    else hashlib.sha256(payload_json.encode()).hexdigest(),
                    payload_json,
                    state,
                    "role.development.v6",
                    "2026-08-24T02:00:01Z",
                    "2026-08-24T02:00:01Z",
                ),
            ).lastrowid
        )
        claim_payload = {"session_id": "role.development.v6"}
        event_id = int(
            self.store.connection.execute(
                "INSERT INTO coordination_events("
                "event_type,entity_key,payload_sha256,created_at) "
                "VALUES ('MESSAGE_CLAIMED',?,?,?)",
                (
                    f"message:{message_id}",
                    hashlib.sha256(
                        canonical_json(claim_payload).encode()
                    ).hexdigest(),
                    "2026-08-24T02:00:01Z",
                ),
            ).lastrowid
        )
        return message_id, event_id

    def _run_quarantine_cli(
        self, request_path: Path, *, database: Path | None = None
    ) -> tuple[int, dict]:
        output = io.StringIO()
        with (
            patch(
                "kanban_pull_buffer.DEFAULT_DATABASE",
                self.database if database is None else database,
            ),
            patch(
                "kanban_pull_buffer.utc_now",
                return_value="2026-08-24T02:00:07Z",
            ),
            patch.object(
                sys,
                "argv",
                [
                    "kanban_pull_buffer.py",
                    "quarantine-unattested-ready",
                    "--request",
                    str(request_path),
                ],
            ),
            redirect_stdout(output),
        ):
            return pull_buffer_main(), json.loads(output.getvalue())

    def test_two_distinct_registered_candidates_are_healthy_and_idempotent(self) -> None:
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(115, "BOUNDED_ENABLER"),
            now="2026-08-24T02:00:03Z",
        )
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(251, "END_TO_END"),
            now="2026-08-24T02:00:04Z",
        )
        first = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:05Z",
        )
        second = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:06Z",
        )
        self.assertEqual("PULL_BUFFER_DEFICIT", first["state"])
        self.assertEqual([115, 251], [item["issue_number"] for item in first["selected"]])
        self.assertEqual(2, first["reviewed_candidate_depth"])
        self.assertEqual(2, first["prepared_or_queued_depth"])
        self.assertEqual(0, first["executable_ready_depth"])
        self.assertEqual(0, first["dispatchable_now_depth"])
        self.assertIn("READY_DEPTH_ZERO", first["deficit_reasons"])
        self.assertEqual(first["audit_sha256"], second["audit_sha256"])
        count = self.store.connection.execute(
            "SELECT COUNT(*) FROM portfolio_pull_buffer_audits"
        ).fetchone()[0]
        self.assertEqual(1, count)
        triggers = {
            json.loads(row[0])["trigger_kind"]
            for row in self.store.connection.execute(
                "SELECT payload_json FROM portfolio_dirty_events"
            )
        }
        self.assertEqual(set(), triggers)

    def test_ready_registration_fails_closed_on_incomplete_admission(self) -> None:
        packet = self._packet(
            251,
            "END_TO_END",
            lambda value: value.update(
                {
                    "state": "READY",
                    "admission_transaction": {"item": {}, "message": {}},
                }
            ),
        )

        with self.assertRaisesRegex(
            PullBufferError, "PULL_BUFFER_READY_FINALIZER_REQUIRED"
        ):
            register_candidate(
                self.store.connection,
                self.database,
                packet,
                now="2026-08-24T02:00:03Z",
            )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current WHERE issue_number=251"
            ).fetchone()[0],
        )

    def test_direct_ready_transition_requires_atomic_finalizer(self) -> None:
        ensure_readiness_schema(self.store.connection)
        current = self.store.connection.execute(
            "SELECT version FROM coordination_items WHERE repository=? AND issue_number=251",
            (REPOSITORY,),
        ).fetchone()

        with self.assertRaisesRegex(
            CoordinationError, "READY_FINALIZATION_REQUIRED"
        ):
            self.store.set_issue_status(
                repository=REPOSITORY,
                issue_number=251,
                status="READY",
                allocation_class="NONE",
                generation=1,
                accountable_session_id=None,
                lease_manifest_sha256=None,
                development_units=1,
                shared_units=1,
                sre_units=0,
                expected_source_sha256=self.sources[251],
                expected_version=int(current["version"]),
                now="2026-08-24T02:00:02Z",
            )

        unchanged = self.store.connection.execute(
            "SELECT status, version FROM coordination_items "
            "WHERE repository=? AND issue_number=251",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("PREPARED", unchanged["status"])
        self.assertEqual(int(current["version"]), int(unchanged["version"]))

    def test_missing_second_lane_records_typed_deficit(self) -> None:
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(115, "BOUNDED_ENABLER"),
            now="2026-08-24T02:00:03Z",
        )
        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:05Z",
        )
        self.assertEqual("PULL_BUFFER_DEFICIT", audit["state"])
        self.assertEqual(
            ["PULL_BUFFER_DEPTH_1_OF_2", "READY_DEPTH_ZERO"],
            audit["deficit_reasons"],
        )

    def test_main_and_policy_drift_invalidate_registered_candidates(self) -> None:
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(115, "BOUNDED_ENABLER"),
            now="2026-08-24T02:00:03Z",
        )
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(251, "END_TO_END"),
            now="2026-08-24T02:00:04Z",
        )
        self.store._set_capacity_policy_for_test_fixture(
            repository=REPOSITORY,
            development_limit=6,
            shared_limit=3,
            sre_limit=5,
            authority_sha256="a" * 64,
            expected_version=1,
            now="2026-08-24T02:00:05Z",
        )
        sync_head(
            self.store.connection,
            REPOSITORY,
            "2" * 40,
            expected_version=1,
            expected_observed_main_sha=MAIN,
            now="2026-08-24T02:00:06Z",
        )
        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=False,
            now="2026-08-24T02:00:07Z",
        )
        self.assertEqual("PULL_BUFFER_DEFICIT", audit["state"])
        reasons = {reason for item in audit["invalid"] for reason in item["reasons"]}
        self.assertTrue({"MAIN_DRIFT", "CAPACITY_POLICY_DRIFT"} <= reasons)
        self.assertNotIn("GRAPH_STALE", reasons)
        self.assertEqual(
            2,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_retirements"
            ).fetchone()[0],
        )

    def test_topology_review_staleness_retires_current_pointer(self) -> None:
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(115, "BOUNDED_ENABLER"),
            now="2026-08-24T02:00:03Z",
        )
        changed = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=115,
            payload={
                "_projection_version": 3,
                "number": 115,
                "title": "Issue 115 changed during topology review",
                "state": "open",
                "updated_at": "2026-08-24T02:00:04Z",
                "milestone": {"number": 1, "title": "Sprint 1", "state": "open"},
            },
            source_updated_at="2026-08-24T02:00:04Z",
            fetched_at="2026-08-24T02:00:04Z",
        )
        self.sources[115] = changed.payload_sha256
        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:05Z",
        )

        self.assertEqual("PULL_BUFFER_DEFICIT", audit["state"])
        self.assertIn("GRAPH_STALE", audit["invalid"][0]["reasons"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current"
            ).fetchone()[0],
        )

    def test_audit_reopens_artifact_and_retires_inode_replacement(self) -> None:
        packet_path = self._packet(115, "BOUNDED_ENABLER")
        register_candidate(
            self.store.connection,
            self.database,
            packet_path,
            now="2026-08-24T02:00:03Z",
        )
        original = packet_path.read_bytes()
        preserved = packet_path.with_suffix(".preserved")
        packet_path.rename(preserved)
        packet_path.write_bytes(original)

        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=True,
            now="2026-08-24T02:00:04Z",
        )

        self.assertEqual("PULL_BUFFER_DEFICIT", audit["state"])
        self.assertEqual(["ARTIFACT_DRIFT"], audit["invalid"][0]["reasons"])
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current"
            ).fetchone()[0],
        )
        retirement = self.store.connection.execute(
            "SELECT reasons_json FROM portfolio_pull_buffer_retirements"
        ).fetchone()[0]
        self.assertEqual('["ARTIFACT_DRIFT"]', retirement)

    def test_item_activation_retires_candidate_but_preserves_candidate_history(self) -> None:
        packet_path = self._packet(115, "BOUNDED_ENABLER")
        register_candidate(
            self.store.connection,
            self.database,
            packet_path,
            now="2026-08-24T02:00:03Z",
        )
        self.store.connection.execute(
            "UPDATE coordination_items SET status='ACTIVE', allocation_class='ACTIVE', "
            "version=version+1 WHERE repository=? AND issue_number=115",
            (REPOSITORY,),
        )
        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=False,
            now="2026-08-24T02:00:04Z",
        )
        reasons = set(audit["invalid"][0]["reasons"])
        self.assertEqual({"ITEM_VERSION_DRIFT", "NOT_ZERO_WIP_PREP"}, reasons)
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates"
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current"
            ).fetchone()[0],
        )
        self.store.connection.execute(
            "UPDATE coordination_items SET status='QUEUED', allocation_class='NONE', "
            "version=1 WHERE repository=? AND issue_number=115",
            (REPOSITORY,),
        )
        replay = register_candidate(
            self.store.connection,
            self.database,
            packet_path,
            now="2026-08-24T02:00:05Z",
        )
        self.assertEqual("PREPARED_NOT_READY", replay["state"])

    def test_duplicate_packet_key_fails_before_registration(self) -> None:
        plans = self.root / "plans"
        plans.mkdir(exist_ok=True)
        path = plans / "duplicate.json"
        path.write_text(
            '{"schema":"twinfinity-kanban-pull-buffer/v2",'
            '"schema":"twinfinity-kanban-pull-buffer/v2"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_PACKET_DUPLICATE_KEY"):
            register_candidate(
                self.store.connection,
                self.database,
                path,
                now="2026-08-24T02:00:03Z",
            )
        self.assertFalse(self.store.connection.in_transaction)

    def test_unknown_top_level_and_nested_keys_fail_closed(self) -> None:
        top_level = self._packet(
            115,
            "BOUNDED_ENABLER",
            lambda packet: packet.update({"unexpected": "not allowed"}),
        )
        with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_PACKET_INVALID"):
            register_candidate(
                self.store.connection,
                self.database,
                top_level,
                now="2026-08-24T02:00:03Z",
            )

        nested = self._packet(
            251,
            "END_TO_END",
            lambda packet: packet["capacity_policy"].update({"unexpected": 1}),
        )
        with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_PACKET_INVALID"):
            register_candidate(
                self.store.connection,
                self.database,
                nested,
                now="2026-08-24T02:00:04Z",
            )

    def test_final_descriptor_link_count_drift_rolls_back_registration(self) -> None:
        packet_path = self._packet(115, "BOUNDED_ENABLER")
        real_fstat = __import__("os").fstat
        calls = 0

        def drifting_fstat(descriptor):
            nonlocal calls
            calls += 1
            observed = real_fstat(descriptor)
            if calls < 5:
                return observed
            return SimpleNamespace(
                st_mode=observed.st_mode,
                st_uid=observed.st_uid,
                st_nlink=2,
                st_size=observed.st_size,
                st_dev=observed.st_dev,
                st_ino=observed.st_ino,
            )

        with patch("kanban_pull_buffer.os.fstat", side_effect=drifting_fstat):
            with self.assertRaisesRegex(PullBufferError, "PULL_BUFFER_ARTIFACT_DRIFT"):
                register_candidate(
                    self.store.connection,
                    self.database,
                    packet_path,
                    now="2026-08-24T02:00:03Z",
                )
        self.assertFalse(self.store.connection.in_transaction)
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates"
            ).fetchone()[0],
        )

    def test_observational_audit_and_show_are_query_only_safe(self) -> None:
        register_candidate(
            self.store.connection,
            self.database,
            self._packet(115, "BOUNDED_ENABLER"),
            now="2026-08-24T02:00:03Z",
        )
        before_changes = self.store.connection.total_changes
        self.store.connection.execute("PRAGMA query_only=ON")
        try:
            audit = audit_pull_buffer(
                self.store.connection,
                REPOSITORY,
                record=False,
                now="2026-08-24T02:00:04Z",
            )
            shown = show_pull_buffer(self.store.connection, REPOSITORY)
        finally:
            self.store.connection.execute("PRAGMA query_only=OFF")
        self.assertEqual(before_changes, self.store.connection.total_changes)
        self.assertEqual("PULL_BUFFER_DEFICIT", audit["state"])
        self.assertEqual(1, len(shown["candidates"]))

    def test_quarantine_records_and_replays_exact_empty_inventory(self) -> None:
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        inventory = ready_quarantine_inventory(
            self.store.connection, REPOSITORY
        )
        request = {
            "schema": "twinfinity-ready-quarantine-request/v1",
            "repository": REPOSITORY,
            "operation_key": "cutover-empty-ready-inventory",
            "source_harness_repository": "jayendusharma/twinfinity-harness",
            "source_harness_main_sha": "2" * 40,
            "expected_ready_inventory_sha256": inventory["inventory_sha256"],
            "cutover_authority_sha256": "3" * 64,
        }
        before = self._database_snapshot()

        first = quarantine_unattested_ready(
            self.store, request, now="2026-08-24T02:00:07Z"
        )
        replay = quarantine_unattested_ready(
            self.store, request, now="2026-08-24T02:00:08Z"
        )

        self.assertEqual(first, replay)
        self.assertEqual("twinfinity-ready-quarantine-receipt/v1", first["schema"])
        self.assertEqual(0, first["counts"]["inspected"])
        self.assertEqual(0, first["counts"]["quarantined"])
        self.assertTrue(first["empty_ready_inventory"])
        self.assertEqual(
            first["before_ready_inventory_sha256"],
            first["after_ready_inventory_sha256"],
        )
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_ready_quarantines"
            ).fetchone()[0],
        )
        after = self._database_snapshot()
        for table, rows in before.items():
            if table not in {"portfolio_ready_quarantines", "sqlite_sequence"}:
                self.assertEqual(rows, after[table], table)

    def test_quarantine_mixed_inventory_preserves_exact_ready_and_repository(self) -> None:
        self._add_prepared_graph_item(303)
        self._install_executor_registry()
        valid = self._finalize_canonical_ready(251, "quarantine-valid")
        missing = self._seed_ready_item(302, readiness_state="PENDING")
        drifted = self._finalize_canonical_ready(303, "quarantine-drift")
        self.store.connection.execute(
            "UPDATE portfolio_readiness_current SET last_error='drift' "
            "WHERE repository=? AND issue_number=303",
            (REPOSITORY,),
        )
        pointerless = self._seed_ready_item(304, with_candidate=False)
        other_repository = "example.test/isolated"
        self._seed_ready_item(305, repository=other_repository)

        before = ready_quarantine_inventory(self.store.connection, REPOSITORY)
        by_issue = {item["issue_number"]: item for item in before["items"]}
        self.assertEqual("ATTESTED", by_issue[251]["attestation"])
        self.assertNotEqual("ATTESTED", by_issue[302]["attestation"])
        self.assertNotEqual("ATTESTED", by_issue[303]["attestation"])
        self.assertNotEqual("ATTESTED", by_issue[304]["attestation"])
        valid_lineage_sha = by_issue[251]["lineage_evidence_sha256"]
        other_before = ready_quarantine_inventory(
            self.store.connection, other_repository
        )
        execution_before = {
            table: tuple(
                tuple(row)
                for row in self.store.connection.execute(
                    f'SELECT * FROM "{table}" ORDER BY rowid'
                )
            )
            for table in (
                "coordination_messages",
                "coordination_wakes",
                "coordination_terminal_watches",
                "executor_attempts",
            )
        }

        receipt = quarantine_unattested_ready(
            self.store,
            self._quarantine_request(operation_key="mixed-cutover"),
            now="2026-08-24T02:00:07Z",
        )

        self.assertEqual(
            {"inspected": 4, "preserved": 1, "quarantined": 3},
            receipt["counts"],
        )
        self.assertEqual([251], [item["issue_number"] for item in receipt["preserved"]])
        quarantined = {
            item["issue_number"]: item for item in receipt["quarantined"]
        }
        self.assertEqual({302, 303, 304}, set(quarantined))
        after = ready_quarantine_inventory(self.store.connection, REPOSITORY)
        self.assertEqual([251], [item["issue_number"] for item in after["items"]])
        self.assertEqual(
            valid_lineage_sha, after["items"][0]["lineage_evidence_sha256"]
        )
        self.assertEqual(
            other_before,
            ready_quarantine_inventory(self.store.connection, other_repository),
        )
        self.assertEqual(
            [valid["candidate_id"]],
            [
                row["candidate_id"]
                for row in self.store.connection.execute(
                    "SELECT candidate_id FROM portfolio_pull_buffer_current "
                    "WHERE repository=? ORDER BY issue_number",
                    (REPOSITORY,),
                )
            ],
        )
        for seeded in (missing, drifted, pointerless):
            issue_number = seeded["issue_number"]
            item = self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? "
                "AND issue_number=?",
                (REPOSITORY, issue_number),
            ).fetchone()
            self.assertEqual("HOLD", item["status"])
            self.assertEqual("NONE", item["allocation_class"])
            self.assertIsNone(item["accountable_session_id"])
            self.assertIsNone(item["lease_manifest_sha256"])
            self.assertEqual(
                quarantined[issue_number]["hold_item_version"], item["version"]
            )
            self.assertIsNone(
                self.store.connection.execute(
                    "SELECT 1 FROM portfolio_pull_buffer_current "
                    "WHERE repository=? AND issue_number=?",
                    (REPOSITORY, issue_number),
                ).fetchone()
            )
            if seeded["candidate_id"] is not None:
                retirement = self.store.connection.execute(
                    "SELECT * FROM portfolio_pull_buffer_retirements "
                    "WHERE candidate_id=?",
                    (seeded["candidate_id"],),
                ).fetchone()
                self.assertEqual(
                    canonical_json(["UNATTESTED_READY_QUARANTINED"]),
                    retirement["reasons_json"],
                )
        for issue_number in (302, 303):
            readiness = self.store.connection.execute(
                "SELECT * FROM portfolio_readiness_current "
                "WHERE repository=? AND issue_number=?",
                (REPOSITORY, issue_number),
            ).fetchone()
            self.assertEqual("HOLD", readiness["state"])
            self.assertEqual(
                "UNATTESTED_READY_QUARANTINED", readiness["last_error"]
            )
        self.assertEqual(
            execution_before,
            {
                table: tuple(
                    tuple(row)
                    for row in self.store.connection.execute(
                        f'SELECT * FROM "{table}" ORDER BY rowid'
                    )
                )
                for table in execution_before
            },
        )
        with registry_config_scope(self.registry_config):
            audit = audit_pull_buffer(
                self.store.connection,
                REPOSITORY,
                record=False,
                now="2026-08-24T02:00:08Z",
                database=self.database,
            )
        self.assertEqual([251], [item["issue_number"] for item in audit["selected"]])
        self.assertEqual(1, audit["executable_ready_depth"])
        self.assertEqual(1, audit["dispatchable_now_depth"])
        self.assertFalse(
            {302, 303, 304}
            & {item["issue_number"] for item in [*audit["selected"], *audit["invalid"]]}
        )

    def test_quarantine_rejects_active_resource_on_attested_ready_without_write(self) -> None:
        self._install_executor_registry()
        self._finalize_canonical_ready(251, "quarantine-active-lineage")
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": 251,
                "payload_sha256": self.sources[251],
            },
            "issue_number": 251,
            "generation": 1,
        }
        payload_json = canonical_json(payload)
        self.store.connection.execute(
            "INSERT INTO coordination_messages("
            "idempotency_key,recipient_session_id,topic,payload_sha256,"
            "payload_json,state,created_at,updated_at) VALUES (?,?,?,?,?,"
            "'PREPARED',?,?)",
            (
                "attested-ready-active-lineage",
                "role.development.v4",
                "development.admission",
                hashlib.sha256(payload_json.encode()).hexdigest(),
                payload_json,
                "2026-08-24T02:00:04Z",
                "2026-08-24T02:00:04Z",
            ),
        )
        inventory = ready_quarantine_inventory(self.store.connection, REPOSITORY)
        self.assertEqual("ATTESTED", inventory["items"][0]["attestation"])

        self._assert_quarantine_rejected_without_write(
            self._quarantine_request(operation_key="attested-active-lineage"),
            "READY_QUARANTINE_ACTIVE_LINEAGE",
        )

    def test_quarantine_reserved_pre_push_publication_is_scoped_and_zero_write(self) -> None:
        self._install_executor_registry()
        self._finalize_canonical_ready(251, "quarantine-reserved-publication")
        before = ready_quarantine_inventory(self.store.connection, REPOSITORY)

        self._seed_pre_push_publication(
            "fixtures.test/unrelated-publication", 951
        )
        self.assertEqual(
            before,
            ready_quarantine_inventory(self.store.connection, REPOSITORY),
        )

        gate_id, publication_id = self._seed_pre_push_publication(
            REPOSITORY, 251, state="HOLD"
        )
        retained = ready_quarantine_inventory(
            self.store.connection, REPOSITORY
        )
        self.store.connection.execute(
            "UPDATE coordination_pre_push_publications "
            "SET state='RESERVED',updated_at=? WHERE id=?",
            ("2026-08-24T02:00:07Z", publication_id),
        )
        after = ready_quarantine_inventory(self.store.connection, REPOSITORY)
        self.assertNotEqual(
            retained["inventory_sha256"], after["inventory_sha256"]
        )
        self.assertEqual(
            [
                {
                    "id": publication_id,
                    "generation": 1,
                    "state": "RESERVED",
                    "gate_id": gate_id,
                }
            ],
            after["items"][0]["active_resources"]["pre_push_publications"],
        )
        self._assert_quarantine_rejected_without_write(
            self._quarantine_request(
                operation_key="reserved-pre-push-publication"
            ),
            'READY_QUARANTINE_ACTIVE_LINEAGE:.*"PRE_PUSH_PUBLICATION"',
        )

    def test_quarantine_rejects_malformed_active_message_without_write(self) -> None:
        repository = "fixtures.test/quarantine-malformed-message"
        self._seed_ready_item(319, repository=repository)
        request = self._quarantine_request(
            repository, operation_key="malformed-active-message"
        )
        malformed = "{"
        self.store.connection.execute(
            "INSERT INTO coordination_messages("
            "idempotency_key,recipient_session_id,topic,payload_sha256,"
            "payload_json,state,created_at,updated_at) VALUES (?,?,?,?,?,"
            "'PREPARED',?,?)",
            (
                "malformed-active-message",
                "role.development.v6",
                "coordination.notice",
                hashlib.sha256(malformed.encode()).hexdigest(),
                malformed,
                "2026-08-24T02:00:01Z",
                "2026-08-24T02:00:01Z",
            ),
        )

        self._assert_quarantine_rejected_without_write(
            request, "READY_QUARANTINE_ACTIVE_MESSAGE_INVALID"
        )

    def test_quarantine_binds_terminal_claim_events_to_exact_item_inventory(self) -> None:
        for index, state in enumerate(("COMPLETE", "HOLD")):
            with self.subTest(state=state):
                repository = f"fixtures.test/terminal-claim-{state.lower()}"
                number = 370 + index
                seeded = self._seed_ready_item(number, repository=repository)
                payload_json = canonical_json(
                    {
                        "source": {
                            "repository": repository,
                            "object_kind": "issue",
                            "object_number": number,
                            "payload_sha256": seeded["source_payload_sha256"],
                        },
                        "issue_number": number,
                        "generation": 1,
                    }
                )
                _message_id, event_id = self._seed_terminal_claimed_message(
                    key=f"terminal-claim-{state.lower()}",
                    payload_json=payload_json,
                    state=state,
                )

                inventory = ready_quarantine_inventory(
                    self.store.connection, repository
                )
                self.assertEqual(
                    [event_id],
                    [
                        event["id"]
                        for event in inventory["items"][0]["active_resources"][
                            "claim_events"
                        ]
                    ],
                )
                request = self._quarantine_request(
                    repository,
                    operation_key=f"terminal-claim-{state.lower()}",
                )
                self._assert_quarantine_rejected_without_write(
                    request,
                    'READY_QUARANTINE_ACTIVE_LINEAGE:.*"MESSAGE_CLAIM"',
                )

    def test_quarantine_rejects_every_invalid_terminal_claim_without_write(self) -> None:
        for state_index, state in enumerate(("COMPLETE", "HOLD")):
            for case_index, case in enumerate(
                (
                    "conflicting-issue",
                    "malformed-json",
                    "duplicate-key",
                    "missing-identity",
                    "cross-repository",
                    "missing-source-fallback",
                    "non-object-source-fallback",
                    "invalid-repository",
                    "payload-digest-conflict",
                )
            ):
                with self.subTest(state=state, case=case):
                    number = 380 + state_index * 10 + case_index
                    repository = f"fixtures.test/invalid-{state.lower()}-{case}"
                    seeded = self._seed_ready_item(number, repository=repository)
                    request = self._quarantine_request(
                        repository,
                        operation_key=f"invalid-{state.lower()}-{case}",
                    )
                    source = {
                        "repository": repository,
                        "object_kind": "issue",
                        "object_number": number,
                        "payload_sha256": seeded["source_payload_sha256"],
                    }
                    if case == "conflicting-issue":
                        payload_json = canonical_json(
                            {
                                "source": source,
                                "issue_number": number + 1,
                                "generation": 1,
                            }
                        )
                    elif case == "malformed-json":
                        payload_json = "{"
                    elif case == "duplicate-key":
                        payload_json = (
                            f'{{"generation":1,"issue_number":{number},'
                            f'"issue_number":{number},"repository":'
                            f'"{repository}"}}'
                        )
                    elif case == "missing-identity":
                        payload_json = canonical_json({"generation": 1})
                    elif case == "cross-repository":
                        payload_json = canonical_json(
                            {
                                "repository": "fixtures.test/other",
                                "source": source,
                                "issue_number": number,
                                "generation": 1,
                            }
                        )
                    elif case == "missing-source-fallback":
                        payload_json = canonical_json(
                            {
                                "repository": "fixtures.test/other",
                                "issue_number": number,
                                "generation": 1,
                            }
                        )
                    elif case == "non-object-source-fallback":
                        payload_json = canonical_json(
                            {
                                "source": "not-an-object",
                                "repository": "fixtures.test/other",
                                "issue_number": number,
                                "generation": 1,
                            }
                        )
                    elif case == "invalid-repository":
                        payload_json = canonical_json(
                            {
                                "source": {
                                    **source,
                                    "repository": "not-a-repository",
                                },
                                "issue_number": number,
                                "generation": 1,
                            }
                        )
                    else:
                        payload_json = canonical_json(
                            {
                                "source": source,
                                "issue_number": number,
                                "generation": 1,
                            }
                        )
                    message_id, event_id = self._seed_terminal_claimed_message(
                        key=f"invalid-{state.lower()}-{case}",
                        payload_json=payload_json,
                        state=state,
                        topic=(
                            "development.recovery_prepare"
                            if case == "malformed-json"
                            else "development.admission"
                        ),
                        payload_sha256=(
                            "0" * 64
                            if case == "payload-digest-conflict"
                            else None
                        ),
                    )
                    try:
                        self._assert_quarantine_rejected_without_write(
                            request,
                            "READY_QUARANTINE_CLAIMED_MESSAGE_INVALID",
                        )
                    finally:
                        self.store.connection.execute(
                            "DELETE FROM coordination_events WHERE id=?",
                            (event_id,),
                        )
                        self.store.connection.execute(
                            "DELETE FROM coordination_messages WHERE id=?",
                            (message_id,),
                        )

    def test_quarantine_claim_validation_precedes_empty_inventory_receipt(self) -> None:
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        repository = "fixtures.test/empty-claimed-lineage"
        inventory = ready_quarantine_inventory(
            self.store.connection, repository
        )
        self.assertEqual([], inventory["items"])
        request = self._quarantine_request(
            repository, operation_key="empty-invalid-terminal-claim"
        )
        for entity_key in ("message:not-an-id", "message:999999"):
            with self.subTest(entity_key=entity_key):
                event_id = int(
                    self.store.connection.execute(
                        "INSERT INTO coordination_events("
                        "event_type,entity_key,payload_sha256,created_at) "
                        "VALUES ('MESSAGE_CLAIMED',?,?,?)",
                        (
                            entity_key,
                            "0" * 64,
                            "2026-08-24T02:00:01Z",
                        ),
                    ).lastrowid
                )
                try:
                    self._assert_quarantine_rejected_without_write(
                        request,
                        "READY_QUARANTINE_CLAIMED_MESSAGE_INVALID",
                    )
                finally:
                    self.store.connection.execute(
                        "DELETE FROM coordination_events WHERE id=?",
                        (event_id,),
                    )

    def test_quarantine_treats_ready_item_capacity_drift_as_unattested(self) -> None:
        self._install_executor_registry()
        finalized = self._finalize_canonical_ready(251, "quarantine-capacity-drift")
        self.store.connection.execute(
            "UPDATE coordination_items SET shared_units=shared_units+1 "
            "WHERE repository=? AND issue_number=251",
            (REPOSITORY,),
        )
        inventory = ready_quarantine_inventory(self.store.connection, REPOSITORY)
        self.assertEqual(
            "READINESS_ATTESTATION_DRIFT", inventory["items"][0]["attestation"]
        )

        receipt = quarantine_unattested_ready(
            self.store,
            self._quarantine_request(operation_key="ready-capacity-drift"),
            now="2026-08-24T02:00:07Z",
        )

        self.assertEqual(
            {"inspected": 1, "preserved": 0, "quarantined": 1},
            receipt["counts"],
        )
        self.assertEqual(
            int(finalized["finalized"]["candidate_id"]),
            int(receipt["quarantined"][0]["candidate_id"]),
        )

    def test_quarantine_requires_exact_authenticated_receipt_pickup(self) -> None:
        self._install_executor_registry()
        finalized = self._finalize_canonical_ready(251, "quarantine-pickup")
        campaign_id = int(finalized["campaign_id"])
        receipt_id = int(
            self.store.connection.execute(
                "SELECT receipt_id FROM portfolio_readiness_current "
                "WHERE repository=? AND issue_number=251",
                (REPOSITORY,),
            ).fetchone()[0]
        )
        message_id = int(finalized["message_id"])

        self.store.connection.execute(
            "UPDATE portfolio_readiness_current SET receipt_id=NULL "
            "WHERE repository=? AND issue_number=251",
            (REPOSITORY,),
        )
        self.assertEqual(
            "READINESS_ATTESTATION_INVALID",
            ready_quarantine_inventory(self.store.connection, REPOSITORY)["items"][0][
                "attestation"
            ],
        )
        self.store.connection.execute(
            "UPDATE portfolio_readiness_current SET receipt_id=? "
            "WHERE repository=? AND issue_number=251",
            (receipt_id, REPOSITORY),
        )

        self.store.connection.execute(
            "DROP TRIGGER coordination_message_envelope_immutable"
        )
        self.store.connection.execute(
            "UPDATE coordination_messages SET topic='development.admission' "
            "WHERE id=?",
            (message_id,),
        )
        self.assertEqual(
            "READINESS_ATTESTATION_DRIFT",
            ready_quarantine_inventory(self.store.connection, REPOSITORY)["items"][0][
                "attestation"
            ],
        )
        self.store.connection.execute(
            "UPDATE coordination_messages SET topic='coordination.notice' WHERE id=?",
            (message_id,),
        )

        self.store.connection.execute(
            "UPDATE portfolio_readiness_receipt_pickups SET receipt_id=NULL "
            "WHERE campaign_id=?",
            (campaign_id,),
        )
        self.assertEqual(
            "READINESS_ATTESTATION_DRIFT",
            ready_quarantine_inventory(self.store.connection, REPOSITORY)["items"][0][
                "attestation"
            ],
        )
        self.store.connection.execute(
            "UPDATE portfolio_readiness_receipt_pickups SET receipt_id=? "
            "WHERE campaign_id=?",
            (receipt_id, campaign_id),
        )
        self.store.connection.execute(
            "DROP TRIGGER portfolio_readiness_pickup_immutable_delete"
        )
        self.store.connection.execute(
            "DELETE FROM portfolio_readiness_receipt_pickups WHERE campaign_id=?",
            (campaign_id,),
        )
        inventory = ready_quarantine_inventory(self.store.connection, REPOSITORY)
        self.assertEqual(
            "READINESS_ATTESTATION_DRIFT", inventory["items"][0]["attestation"]
        )

        receipt = quarantine_unattested_ready(
            self.store,
            self._quarantine_request(operation_key="missing-receipt-pickup"),
            now="2026-08-24T02:00:07Z",
        )
        self.assertEqual(1, receipt["counts"]["quarantined"])

    def test_quarantine_rejects_every_active_or_retained_resource_without_write(self) -> None:
        for index, kind in enumerate(
            (
                "allocation",
                "accountable",
                "lease",
                "supervisor-allocation",
                "message",
                "wake",
                "watch",
                "attempt",
                "readiness-attempt",
            )
        ):
            with self.subTest(kind=kind):
                repository = f"fixtures.test/quarantine-{kind}"
                number = 320 + index
                seeded = self._seed_ready_item(
                    number,
                    repository=repository,
                    readiness_state=(
                        "PENDING" if kind == "readiness-attempt" else None
                    ),
                )
                if kind == "allocation":
                    self.store.connection.execute(
                        "UPDATE coordination_items SET allocation_class='RETAINED' "
                        "WHERE repository=? AND issue_number=?",
                        (repository, number),
                    )
                elif kind == "accountable":
                    self.store.connection.execute(
                        "UPDATE coordination_items SET accountable_session_id=? "
                        "WHERE repository=? AND issue_number=?",
                        ("role.development.v6", repository, number),
                    )
                elif kind == "lease":
                    self.store.connection.execute(
                        "UPDATE coordination_items SET lease_manifest_sha256=? "
                        "WHERE repository=? AND issue_number=?",
                        ("4" * 64, repository, number),
                    )
                elif kind == "supervisor-allocation":
                    self.store.connection.execute(
                        "INSERT INTO coordination_supervisor_items("
                        "repository,issue_number,status,allocation_class,version,"
                        "updated_at) VALUES (?,?,'ACTIVE','ACTIVE',1,?)",
                        (repository, number, "2026-08-24T02:00:01Z"),
                    )
                elif kind in {"message", "wake"}:
                    payload = {
                        "source": {
                            "repository": repository,
                            "object_kind": "issue",
                            "object_number": number,
                            "payload_sha256": seeded["source_payload_sha256"],
                        },
                        "issue_number": number,
                        "generation": 1,
                    }
                    payload_json = canonical_json(payload)
                    self.store.connection.execute(
                        "INSERT INTO coordination_messages("
                        "idempotency_key,recipient_session_id,topic,payload_sha256,"
                        "payload_json,state,created_at,updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (
                            f"unsafe-{kind}-{number}",
                            "role.development.v6",
                            "development.admission",
                            hashlib.sha256(payload_json.encode()).hexdigest(),
                            payload_json,
                            "PREPARED" if kind == "message" else "COMPLETE",
                            "2026-08-24T02:00:01Z",
                            "2026-08-24T02:00:01Z",
                        ),
                    )
                    if kind == "wake":
                        message_id = self.store.connection.execute(
                            "SELECT last_insert_rowid()"
                        ).fetchone()[0]
                        self.store.connection.execute(
                            "INSERT INTO coordination_wakes("
                            "wake_key,message_id,recipient_session_id,"
                            "message_payload_sha256,state,attempts,last_attempt_at,"
                            "updated_at) VALUES (?,?,?,?, 'INFLIGHT',1,?,?)",
                            (
                                f"unsafe-wake-{number}",
                                message_id,
                                "role.development.v6",
                                hashlib.sha256(payload_json.encode()).hexdigest(),
                                "2026-08-24T02:00:01Z",
                                "2026-08-24T02:00:01Z",
                            ),
                        )
                elif kind == "watch":
                    self.store.connection.execute(
                        "INSERT INTO coordination_terminal_watches("
                        "watch_key,repository,issue_number,generation,"
                        "accountable_session_id,lease_manifest_sha256,state,"
                        "last_heartbeat_at,next_wake_at,updated_at) "
                        "VALUES (?,?,?,?,?,?,'ACTIVE',?,?,?)",
                        (
                            f"unsafe-watch-{number}", repository, number, 0,
                            "role.development.v6", "5" * 64,
                            "2026-08-24T02:00:01Z",
                            "2026-08-24T02:00:01Z",
                            "2026-08-24T02:00:01Z",
                        ),
                    )
                else:
                    endpoint_id = f"synthetic.development.{number}"
                    attempt_id = f"00000000-0000-4000-8000-{number:012d}"
                    self.store.connection.execute(
                        "INSERT INTO executor_role_endpoints("
                        "endpoint_id,role,version,executor_profile,codex_profile,"
                        "config_sha256,config_json,command_json,created_at) "
                        "VALUES (?,'development',?,'synthetic','synthetic',"
                        "?,'{}','[]',?)",
                        (endpoint_id, 900 + index, "6" * 64, "2026-08-24T02:00:01Z"),
                    )
                    self.store.connection.execute(
                        "INSERT INTO executor_attempts("
                        "attempt_id,role,endpoint_id,instance_id,token_sha256,"
                        "target_kind,target_key,lineage_repository,"
                        "lineage_issue_number,lineage_generation,"
                        "lineage_lease_sha256,lineage_sha256,state,heartbeat_at,"
                        "version,created_at,updated_at) VALUES (?,'development',"
                        "?,?,?,'hosted_operation',?,?,?,?,?,?,'RUNNING',?,1,?,?)",
                        (
                            attempt_id,
                            endpoint_id,
                            f"unsafe-instance-{number}",
                            "7" * 64,
                            f"unsafe-target-{number}",
                            repository
                            if kind == "attempt"
                            else "fixtures.test/unrelated",
                            number if kind == "attempt" else 999,
                            0,
                            "5" * 64,
                            hashlib.sha256(
                                f"unsafe-lineage-{number}".encode()
                            ).hexdigest(),
                            "2026-08-24T02:00:01Z",
                            "2026-08-24T02:00:01Z",
                            "2026-08-24T02:00:01Z",
                        ),
                    )
                    if kind == "readiness-attempt":
                        self.store.connection.execute(
                            "UPDATE portfolio_readiness_current SET attempt_id=? "
                            "WHERE repository=? AND issue_number=?",
                            (attempt_id, repository, number),
                        )
                self._assert_quarantine_rejected_without_write(
                    self._quarantine_request(
                        repository, operation_key=f"unsafe-{kind}"
                    ),
                    rf'READY_QUARANTINE_ACTIVE_LINEAGE:.*"issue_number":{number}',
                )

    def test_quarantine_rolls_back_every_mutation_and_receipt_failpoint(self) -> None:
        self._seed_ready_item(340, readiness_state="PENDING")
        self._seed_ready_item(341, readiness_state="PENDING")
        request = self._quarantine_request(operation_key="failpoint-cutover")
        for boundary in (
            "before_quarantine:340",
            "after_pointer:340",
            "after_item:340",
            "after_readiness:340",
            "before_quarantine:341",
            "after_pointer:341",
            "after_item:341",
            "after_readiness:341",
            "before_receipt",
            "after_receipt",
            "before_commit",
        ):
            with self.subTest(boundary=boundary):
                before = self._database_snapshot()

                def failpoint(observed: str) -> None:
                    if observed == boundary:
                        raise RuntimeError(f"injected:{boundary}")

                with self.assertRaisesRegex(RuntimeError, "injected"):
                    quarantine_unattested_ready(
                        self.store,
                        request,
                        now="2026-08-24T02:00:07Z",
                        failpoint=failpoint,
                    )
                self.assertEqual(before, self._database_snapshot())

    def test_quarantine_rejects_stale_cas_and_replay_substitution(self) -> None:
        self._seed_ready_item(350)
        request = self._quarantine_request(operation_key="closed-cutover")
        stale = {**request, "expected_ready_inventory_sha256": "0" * 64}
        self._assert_quarantine_rejected_without_write(
            stale, "READY_QUARANTINE_INVENTORY_DRIFT"
        )

        before = self._database_snapshot()

        def drift_item(observed: str) -> None:
            if observed == "before_quarantine:350":
                self.store.connection.execute(
                    "UPDATE coordination_items SET version=version+1 "
                    "WHERE repository=? AND issue_number=350",
                    (REPOSITORY,),
                )

        with self.assertRaisesRegex(
            PullBufferError, "READY_QUARANTINE_ITEM_FENCE_LOST"
        ):
            quarantine_unattested_ready(
                self.store,
                request,
                now="2026-08-24T02:00:07Z",
                failpoint=drift_item,
            )
        self.assertEqual(before, self._database_snapshot())

        receipt = quarantine_unattested_ready(
            self.store, request, now="2026-08-24T02:00:07Z"
        )
        snapshot = self._database_snapshot()
        self.assertEqual(
            receipt,
            quarantine_unattested_ready(
                self.store, request, now="2026-08-24T02:00:08Z"
            ),
        )
        self.assertEqual(snapshot, self._database_snapshot())
        for field, value in (
            ("source_harness_main_sha", "4" * 40),
            ("cutover_authority_sha256", "5" * 64),
            ("repository", "example.test/substituted"),
        ):
            with self.subTest(field=field):
                self._assert_quarantine_rejected_without_write(
                    {**request, field: value},
                    "READY_QUARANTINE_OPERATION_KEY_CONFLICT",
                )
        self._assert_quarantine_rejected_without_write(
            {**request, "operation_key": "substituted-key"},
            "READY_QUARANTINE_SCOPE_CONFLICT",
        )
        self.store.connection.execute(
            "UPDATE coordination_items SET updated_at='2026-08-24T02:00:09Z' "
            "WHERE repository=? AND issue_number=350",
            (REPOSITORY,),
        )
        self._assert_quarantine_rejected_without_write(
            request, "READY_QUARANTINE_REPLAY_STATE_DRIFT"
        )
        row = self.store.connection.execute(
            "SELECT receipt_json FROM portfolio_ready_quarantines "
            "WHERE operation_key=?",
            (request["operation_key"],),
        ).fetchone()
        malformed_receipt = json.loads(row["receipt_json"])
        malformed_receipt["inspected_items"][0]["issue_number"] = {}
        malformed_json = canonical_json(malformed_receipt)
        self.store.connection.execute(
            "DROP TRIGGER portfolio_ready_quarantines_immutable_update"
        )
        self.store.connection.execute(
            "UPDATE portfolio_ready_quarantines SET receipt_json=?,"
            "receipt_sha256=? WHERE operation_key=?",
            (
                malformed_json,
                hashlib.sha256(malformed_json.encode()).hexdigest(),
                request["operation_key"],
            ),
        )
        self._assert_quarantine_rejected_without_write(
            request, "READY_QUARANTINE_RECEIPT_INVALID"
        )

    def test_quarantine_rejects_cross_repository_pointer_without_write(self) -> None:
        target = "example.test/target"
        foreign = "example.test/foreign"
        self._seed_ready_item(360, repository=target, with_candidate=False)
        foreign_seed = self._seed_ready_item(361, repository=foreign)
        self.store.connection.execute(
            "DELETE FROM portfolio_pull_buffer_current WHERE repository=? "
            "AND issue_number=361",
            (foreign,),
        )
        self.store.connection.execute(
            "INSERT INTO portfolio_pull_buffer_current("
            "repository,issue_number,candidate_id,updated_at) VALUES (?,?,?,?)",
            (
                target, 360, foreign_seed["candidate_id"],
                "2026-08-24T02:00:01Z",
            ),
        )
        self._assert_quarantine_rejected_without_write(
            self._quarantine_request(target, operation_key="cross-pointer"),
            "READY_QUARANTINE_ACTIVE_LINEAGE",
        )
        candidate = self.store.connection.execute(
            "SELECT * FROM portfolio_pull_buffer_candidates WHERE id=?",
            (foreign_seed["candidate_id"],),
        ).fetchone()
        self.assertEqual(foreign, candidate["repository"])
        self.assertIsNone(
            self.store.connection.execute(
                "SELECT 1 FROM portfolio_pull_buffer_retirements "
                "WHERE candidate_id=?",
                (foreign_seed["candidate_id"],),
            ).fetchone()
        )

    def test_quarantine_cli_uses_canonical_owner_safe_request(self) -> None:
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        request = self._quarantine_request(operation_key="cli-empty-cutover")
        request_path = self.root / "ready-quarantine-request.json"
        request_path.write_text(canonical_json(request), encoding="utf-8")
        request_path.chmod(0o600)
        output = io.StringIO()
        with (
            patch("kanban_pull_buffer.DEFAULT_DATABASE", self.database),
            patch("kanban_pull_buffer.utc_now", return_value="2026-08-24T02:00:07Z"),
            patch.object(
                sys,
                "argv",
                [
                    "kanban_pull_buffer.py",
                    "quarantine-unattested-ready",
                    "--request",
                    str(request_path),
                ],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(0, pull_buffer_main())
        result = json.loads(output.getvalue())
        self.assertEqual("COMPLETE", result["phase"])
        self.assertTrue(result["result"]["empty_ready_inventory"])

        request_path.write_text(canonical_json(request) + "\n", encoding="utf-8")
        output = io.StringIO()
        with (
            patch("kanban_pull_buffer.DEFAULT_DATABASE", self.database),
            patch.object(
                sys,
                "argv",
                [
                    "kanban_pull_buffer.py",
                    "quarantine-unattested-ready",
                    "--request",
                    str(request_path),
                ],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(1, pull_buffer_main())
        self.assertEqual(
            "READY_QUARANTINE_REQUEST_NONCANONICAL",
            json.loads(output.getvalue())["error"],
        )

    def test_quarantine_cli_rejects_fifo_request_nonblocking_before_database(self) -> None:
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        request_path = self.root / "ready-quarantine-request.fifo"
        os.mkfifo(request_path, mode=0o600)
        before = self._database_snapshot()
        real_open = os.open

        def require_nonblocking(path, flags, *args, **kwargs):
            if path == request_path.name and not flags & os.O_NONBLOCK:
                raise AssertionError("request FIFO opened without O_NONBLOCK")
            return real_open(path, flags, *args, **kwargs)

        with (
            patch(
                "kanban_pull_buffer.validate_owner_database",
                wraps=pull_buffer.validate_owner_database,
            ) as database_validator,
            patch(
                "kanban_pull_buffer.os.open", side_effect=require_nonblocking
            ),
        ):
            exit_code, result = self._run_quarantine_cli(request_path)
        self.assertEqual(1, exit_code)
        self.assertEqual("READY_QUARANTINE_REQUEST_UNSAFE", result["error"])
        self.assertEqual(0, database_validator.call_count)
        self.assertEqual(before, self._database_snapshot())

    def test_quarantine_cli_rejects_device_request_before_database(self) -> None:
        before = self._database_snapshot()
        with patch(
            "kanban_pull_buffer.validate_owner_database",
            wraps=pull_buffer.validate_owner_database,
        ) as database_validator:
            exit_code, result = self._run_quarantine_cli(
                Path("/dev/null"),
                database=Path("/dev/unused-ready-quarantine.sqlite3"),
            )
        self.assertEqual(1, exit_code)
        self.assertEqual("READY_QUARANTINE_REQUEST_UNSAFE", result["error"])
        self.assertEqual(0, database_validator.call_count)
        self.assertEqual(before, self._database_snapshot())

    def test_quarantine_cli_rejects_oversized_request_before_database(self) -> None:
        request_path = self.root / "oversized-ready-quarantine.json"
        request_path.write_bytes(
            b"x" * (pull_buffer.READY_QUARANTINE_REQUEST_MAX_BYTES + 1)
        )
        request_path.chmod(0o600)
        before = self._database_snapshot()
        with patch(
            "kanban_pull_buffer.validate_owner_database",
            wraps=pull_buffer.validate_owner_database,
        ) as database_validator:
            exit_code, result = self._run_quarantine_cli(request_path)
        self.assertEqual(1, exit_code)
        self.assertEqual("READY_QUARANTINE_REQUEST_TOO_LARGE", result["error"])
        self.assertEqual(0, database_validator.call_count)
        self.assertEqual(before, self._database_snapshot())

    def test_quarantine_cli_requires_exact_request_mode_before_database(self) -> None:
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        request = self._quarantine_request(operation_key="cli-mode-cutover")
        request_path = self.root / "world-readable-ready-quarantine.json"
        request_path.write_text(canonical_json(request), encoding="utf-8")
        request_path.chmod(0o644)
        before = self._database_snapshot()
        with patch(
            "kanban_pull_buffer.validate_owner_database",
            wraps=pull_buffer.validate_owner_database,
        ) as database_validator:
            exit_code, result = self._run_quarantine_cli(request_path)
        self.assertEqual(1, exit_code)
        self.assertEqual("READY_QUARANTINE_REQUEST_UNSAFE", result["error"])
        self.assertEqual(0, database_validator.call_count)
        self.assertEqual(before, self._database_snapshot())

    def test_quarantine_cli_revalidates_request_descriptor_before_database(self) -> None:
        ensure_pull_buffer_schema(self.store.connection)
        ensure_readiness_schema(self.store.connection)
        request = self._quarantine_request(operation_key="cli-drift-cutover")
        request_path = self.root / "drifting-ready-quarantine.json"
        request_path.write_text(canonical_json(request), encoding="utf-8")
        request_path.chmod(0o600)
        before = self._database_snapshot()
        real_open = os.open
        real_fstat = os.fstat
        request_descriptor: int | None = None
        request_fstats = 0

        def observe_open(path, flags, *args, **kwargs):
            nonlocal request_descriptor
            descriptor = real_open(path, flags, *args, **kwargs)
            if path == request_path.name:
                request_descriptor = descriptor
            return descriptor

        def drift_fstat(descriptor):
            nonlocal request_fstats
            metadata = real_fstat(descriptor)
            if descriptor != request_descriptor:
                return metadata
            request_fstats += 1
            if request_fstats == 1:
                return metadata
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_uid=metadata.st_uid,
                st_gid=metadata.st_gid,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_mtime_ns=metadata.st_mtime_ns + 1,
                st_ctime_ns=metadata.st_ctime_ns,
            )

        with (
            patch(
                "kanban_pull_buffer.validate_owner_database",
                wraps=pull_buffer.validate_owner_database,
            ) as database_validator,
            patch("kanban_pull_buffer.os.open", side_effect=observe_open),
            patch("kanban_pull_buffer.os.fstat", side_effect=drift_fstat),
        ):
            exit_code, result = self._run_quarantine_cli(request_path)
        self.assertEqual(1, exit_code)
        self.assertEqual("READY_QUARANTINE_REQUEST_UNSAFE", result["error"])
        self.assertEqual(0, database_validator.call_count)
        self.assertGreaterEqual(request_fstats, 2)
        self.assertEqual(before, self._database_snapshot())


if __name__ == "__main__":
    unittest.main()
