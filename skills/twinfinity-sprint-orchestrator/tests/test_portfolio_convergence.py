from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    digest_json,
)
from coordination_supervisor import CoordinationSupervisor  # noqa: E402
from kanban_pull_buffer import (  # noqa: E402
    PullBufferError,
    admission_binding_error,
    audit_pull_buffer,
    close_candidate_observations,
    ensure_pull_buffer_schema,
    load_candidate_packets,
    register_candidate,
)
from portfolio_convergence import (  # noqa: E402
    PortfolioConvergence,
    PortfolioConvergenceError,
)
from portfolio_graph import replace_graph  # noqa: E402
from executor_registry import (  # noqa: E402
    attempt_lineage_for_target,
    load_registry_config,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
from role_executor_transport import RoleExecutorManagerSubmission  # noqa: E402
from reconcile_routing_artifacts import (  # noqa: E402
    apply_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from tests.canonical_ready_fixture import (  # noqa: E402
    finalize_canonical_ready_candidate,
)


REPOSITORY = "twinfinityai/twinfinityapp"
MAIN = "a" * 40
DEVELOPMENT_SESSION = "role.development.v4"


class PortfolioConvergenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "coordinator"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        self.store = CoordinationStore(self.database)
        skill_root = Path(__file__).resolve().parents[1]
        config = load_registry_config(
            skill_root / "tests" / "fixtures" / "twinfinity-executor-registry-v4.toml"
        )
        aliases, alias_sha = load_legacy_alias_fixture(
            skill_root / "tests" / "fixtures" / "legacy-role-aliases.json"
        )
        plan = build_plan(
            self.store.connection,
            config,
            aliases,
            alias_fixture_sha256=alias_sha,
        )
        apply_plan(
            self.store.connection,
            plan=plan,
            operation_key="portfolio-convergence-tests",
            expected_plan_sha256=plan["plan_sha256"],
            now="2026-08-24T09:59:59Z",
        )
        self.sources = {number: self._snapshot(number) for number in (1, 2)}
        self.release_item = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=1,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256="1" * 64,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.sources[1],
            expected_version=0,
            now="2026-08-24T10:00:01Z",
        )
        self.ready_item = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=2,
            status="PREPARED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256=None,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.sources[2],
            expected_version=0,
            now="2026-08-24T10:00:01Z",
        )
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": MAIN,
                "expected_current_version": 0,
                "scope_milestones": [{"title": "Sprint", "rank": 1}],
                "excluded_issues": [],
                "nodes": [self._node(1, 1), self._node(2, 2)],
                "relations": [],
            },
            now="2026-08-24T10:00:02Z",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _snapshot(self, number: int) -> str:
        return self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=number,
            payload={
                "_projection_version": 3,
                "number": number,
                "title": f"Issue {number}",
                "state": "open",
                "updated_at": "2026-08-24T10:00:00Z",
                "milestone": {"number": 1, "title": "Sprint", "state": "open"},
            },
            source_updated_at="2026-08-24T10:00:00Z",
            fetched_at="2026-08-24T10:00:00Z",
        ).payload_sha256

    def _node(self, number: int, priority: int) -> dict:
        return {
            "node_key": f"issue:{number}",
            "issue_number": number,
            "role": "DELIVERY",
            "root_kind": "STANDALONE",
            "root_reason": "Independent test outcome",
            "lane_key": f"lane-{number}",
            "lane_order": 0,
            "dispatchable": True,
            "priority_rank": priority,
            "estimate_units": 1,
            "development_units": 1,
            "shared_units": 0,
            "sre_units": 0,
            "source_payload_sha256": self.sources[number],
            "ready_at": "2026-08-24T10:00:00Z",
        }

    def _release(self, now: str = "2026-08-24T10:00:03Z") -> dict:
        return self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=1,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256="1" * 64,
            development_units=0,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.sources[1],
            expected_version=self.release_item["version"],
            now=now,
        )

    def _convergence(self, store=None, **kwargs) -> PortfolioConvergence:
        return PortfolioConvergence(
            store or self.store,
            canonical_main_reader=lambda _repository: MAIN,
            **kwargs,
        )

    def _register_ready_candidate(self, *, existing_lease: bool = False) -> Path:
        plans = self.root / "plans"
        plans.mkdir(exist_ok=True)
        lease_path = plans / "issue-2-lease.json"
        lease_payload = {
            "repository": REPOSITORY,
            "issue_number": 2,
            "generation": 1,
            "base_sha": MAIN,
            "branch": "codex/2-ready-successor",
            "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-2",
            "no_additional_paths": True,
            "paths": [
                {
                    "path": "backend/successor.py",
                    "mode": "100644",
                    "type": "blob",
                    "sha": "b" * 40,
                }
            ],
        }
        lease_path.write_text(
            json.dumps(lease_payload, sort_keys=True) + "\n", encoding="utf-8"
        )
        lease_sha = hashlib.sha256(lease_path.read_bytes()).hexdigest()
        lease_artifacts = [
            {
                "repository": REPOSITORY,
                "issue_number": 2,
                "generation": 1,
                "path": str(lease_path),
                "retention_class": "CLOSEOUT_EVIDENCE",
            }
        ]
        if existing_lease:
            self.store.register_artifacts(
                lease_artifacts,
                now="2026-08-24T10:00:02Z",
            )
        item = {
            "repository": REPOSITORY,
            "issue_number": 2,
            "status": "ACTIVE",
            "allocation_class": "ACTIVE",
            "generation": 1,
            "accountable_session_id": DEVELOPMENT_SESSION,
            "lease_manifest_sha256": lease_sha,
            "development_units": 1,
            "shared_units": 0,
            "sre_units": 0,
            "expected_source_sha256": self.sources[2],
            "expected_version": self.ready_item["version"] + 1,
        }
        message = {
            "idempotency_key": "portfolio-convergence-issue-2",
            "recipient_session_id": DEVELOPMENT_SESSION,
            "topic": "development.admission",
            "payload": {
                "source": {
                    "repository": REPOSITORY,
                    "object_kind": "issue",
                    "object_number": 2,
                    "payload_sha256": self.sources[2],
                },
                "issue_number": 2,
                "generation": 1,
                "item_version": self.ready_item["version"] + 2,
                "base_sha": MAIN,
                "branch": "codex/2-ready-successor",
                "worktree_path": "/home/ubuntu/code/twinfinityapp-issue-2",
                "opaque_worktree_id": "twinfinityapp-issue-2",
                "accountable_session_id": DEVELOPMENT_SESSION,
                "writer": "issue-2-accountable-writer",
                "reviewer_plan": ["Different-session exact-head review."],
                "collision_proof": ["The closed lease is disjoint from active work."],
                "environment_rule": "Use only an issue-owned environment.",
                "routine_chain": [
                    "Implement and run the issue-owned gates.",
                    "Publish only through the guarded closeout chain.",
                ],
                "hard_stops": [
                    "Stop on source, graph, lease, capacity, or authority drift."
                ],
                "lease_manifest_sha256": lease_sha,
                "authority_sha256": "7" * 64,
                "capacity": {
                    "development_units": 1,
                    "shared_units": 0,
                    "sre_units": 0,
                },
                "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
            },
        }
        packet = {
            "schema": "twinfinity-kanban-pull-buffer/v2",
            "repository": REPOSITORY,
            "issue_number": 2,
            "generation": 1,
            "item_version_at_preparation": self.ready_item["version"],
            "source_payload_sha256": self.sources[2],
            "accepted_main_at_preparation": MAIN,
            "portfolio_graph_version": 1,
            "state": "PREPARED_NOT_READY",
            "verticality": "END_TO_END",
            "owner_visible_outcome": "Deliver the next safe owner-visible slice.",
            "capacity_policy": {
                "version": 1,
                "development_limit": 5,
                "shared_limit": 2,
                "sre_limit": 5,
            },
            "capacity_on_activation": {
                "development_units": 1,
                "shared_units": 0,
                "sre_units": 0,
            },
            "precomputed_collision_matrix": [
                {
                    "other_issue": 1,
                    "disposition": "DISJOINT",
                    "reason": "The predecessor lease is released.",
                }
            ],
            "preparation_complete": ["The reviewed admission packet is complete."],
            "promotion_checks_after_predecessor": ["Revalidate every local guard."],
            "hard_stops": ["Stop on any source, graph, lease, or capacity drift."],
            "promotion_trigger": "Issue 1 releases its capacity.",
        }
        result = finalize_canonical_ready_candidate(
            self.store,
            database=self.database,
            artifact_root=self.root,
            prepared_packet=packet,
            admission_transaction={
                "item": item,
                "message": message,
                **({} if existing_lease else {"artifacts": lease_artifacts}),
            },
            worker_role="development",
            worker_endpoint_id=DEVELOPMENT_SESSION,
            now="2026-08-24T10:00:02Z",
            suffix="portfolio-convergence",
        )
        self.ready_item = result["item"]
        return result["ready_path"]

    def test_default_main_reader_requires_registration_before_admission(self) -> None:
        self._register_ready_candidate()
        self._release()

        result = PortfolioConvergence(self.store).consume_one(
            "2026-08-24T10:00:04Z"
        )

        self.assertEqual("HOLD", result["state"])
        self.assertEqual("REPOSITORY_GIT_REGISTRATION_MISSING", result["error"])
        item = self.store.connection.execute(
            "SELECT status,allocation_class FROM coordination_items "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(("READY", "NONE"), tuple(item))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE topic IN ('development.admission','sre.admission')"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches WHERE issue_number=2"
            ).fetchone()[0],
        )

    def test_release_event_is_atomic_digest_bound_and_idempotent(self) -> None:
        with patch.object(
            self.store,
            "_enqueue_portfolio_dirty_event",
            side_effect=CoordinationError("INJECTED_EVENT_FAILURE"),
        ):
            with self.assertRaisesRegex(CoordinationError, "INJECTED_EVENT_FAILURE"):
                self._release()
        item = self.store.connection.execute(
            "SELECT status, allocation_class, version FROM coordination_items WHERE repository=? AND issue_number=1",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual(("ACTIVE", "ACTIVE", 1), tuple(item))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_dirty_events"
            ).fetchone()[0],
        )

        released = self._release()
        event = self.store.connection.execute(
            "SELECT * FROM portfolio_dirty_events"
        ).fetchone()
        payload = json.loads(event["payload_json"])
        self.assertEqual(released["portfolio_dirty_event_id"], event["id"])
        self.assertEqual(event["event_sha256"], digest_json(payload))
        with self.store.transaction():
            duplicate = self.store._enqueue_portfolio_dirty_event(
                repository=REPOSITORY,
                issue_number=1,
                release_item_version=released["version"],
                release_source_sha256=self.sources[1],
                prior_allocation_class="ACTIVE",
                status="DONE",
                generation=1,
                now="2026-08-24T10:00:04Z",
            )
        self.assertEqual(event["id"], duplicate)
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_dirty_events"
            ).fetchone()[0],
        )

    def test_absolute_deadline_stops_only_between_fifo_events(self) -> None:
        self._release()
        with self.store.transaction():
            self.store._enqueue_portfolio_dirty_event(
                repository=REPOSITORY,
                issue_number=2,
                release_item_version=99,
                release_source_sha256=self.sources[2],
                prior_allocation_class="ACTIVE",
                status="DONE",
                generation=1,
                now="2026-08-24T10:00:04Z",
            )
        before = [
            dict(row)
            for row in self.store.connection.execute(
                "SELECT * FROM portfolio_dirty_events ORDER BY id"
            )
        ]
        changes_before = self.store.connection.total_changes

        none = self._convergence().consume_due(
            limit=2,
            now="2026-08-24T10:00:05Z",
            deadline=5.0,
            monotonic=lambda: 5.0,
        )

        self.assertEqual([], none)
        self.assertEqual(changes_before, self.store.connection.total_changes)
        self.assertEqual(
            before,
            [
                dict(row)
                for row in self.store.connection.execute(
                    "SELECT * FROM portfolio_dirty_events ORDER BY id"
                )
            ],
        )
        ticks = iter((4.0, 5.0))
        one = self._convergence().consume_due(
            limit=2,
            now="2026-08-24T10:00:05Z",
            deadline=5.0,
            monotonic=lambda: next(ticks),
        )
        untouched_next = dict(
            self.store.connection.execute(
                "SELECT * FROM portfolio_dirty_events ORDER BY id LIMIT 1 OFFSET 1"
            ).fetchone()
        )

        self.assertEqual(1, len(one))
        self.assertEqual(before[1], untouched_next)

    def test_retained_to_none_release_enqueues_one_dirty_event(self) -> None:
        source = self._snapshot(3)
        retained = self.store.set_issue_status(
            repository=REPOSITORY,
            issue_number=3,
            status="HOLD",
            allocation_class="RETAINED",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256="3" * 64,
            development_units=1,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source,
            expected_version=0,
            now="2026-08-24T10:00:03Z",
        )
        released = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=3,
            status="DONE",
            allocation_class="NONE",
            generation=2,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256="3" * 64,
            development_units=0,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=source,
            expected_version=retained["version"],
            now="2026-08-24T10:00:04Z",
        )
        rows = self.store.connection.execute(
            "SELECT payload_json FROM portfolio_dirty_events WHERE issue_number=3"
        ).fetchall()

        self.assertEqual(1, len(rows))
        self.assertEqual(
            "RETAINED",
            json.loads(rows[0]["payload_json"])["prior_allocation_class"],
        )
        event_id = self.store.connection.execute(
            "SELECT id FROM portfolio_dirty_events WHERE issue_number=3"
        ).fetchone()[0]
        self.assertEqual(released["portfolio_dirty_event_id"], event_id)

    def test_monotonic_done_none_version_keeps_release_wake_admissible(self) -> None:
        released = self._release()
        advanced = self.store._set_issue_status_for_test_fixture(
            repository=REPOSITORY,
            issue_number=1,
            status="DONE",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=DEVELOPMENT_SESSION,
            lease_manifest_sha256="1" * 64,
            development_units=0,
            shared_units=0,
            sre_units=0,
            expected_source_sha256=self.sources[1],
            expected_version=released["version"],
            now="2026-08-24T10:00:04Z",
        )
        self.assertGreater(advanced["version"], released["version"])
        self._register_ready_candidate()

        result = self._convergence().consume_one("2026-08-24T10:00:05Z")

        self.assertEqual("ADMITTED", result["outcome"])
        self.assertEqual(2, result["admitted_issue_number"])

    def test_canonical_main_is_read_twice_before_write_lock(self) -> None:
        self._release()
        observations: list[bool] = []

        def reader(_repository: str) -> str:
            observations.append(self.store.connection.in_transaction)
            return MAIN

        result = PortfolioConvergence(
            self.store,
            canonical_main_reader=reader,
        ).consume_one("2026-08-24T10:00:04Z")

        self.assertEqual([False, False], observations)
        self.assertEqual("RETRY", result["state"])

    def test_local_main_cannot_overwrite_provider_cursor(self) -> None:
        self._register_ready_candidate()
        self._release()
        advanced = "c" * 40
        result = PortfolioConvergence(
            self.store,
            canonical_main_reader=lambda _repository: advanced,
        ).consume_one("2026-08-24T10:00:04Z")

        candidate = self.store.connection.execute(
            "SELECT status, allocation_class FROM coordination_items "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        triggers = [
            json.loads(row[0])["trigger_kind"]
            for row in self.store.connection.execute(
                "SELECT payload_json FROM portfolio_dirty_events ORDER BY id"
            )
        ]
        self.assertEqual("RETRY", result["state"])
        self.assertEqual("CANONICAL_MAIN_PROVIDER_CURSOR_DRIFT", result["error"])
        self.assertEqual(("READY", "NONE"), tuple(candidate))
        self.assertNotIn("MAIN_CURSOR_ADVANCED", triggers)

    def test_dispatchable_depth_requires_complete_admission_binding(self) -> None:
        self._register_ready_candidate()
        observations = load_candidate_packets(
            self.store.connection,
            REPOSITORY,
            database=self.database,
            keep_descriptors=True,
        )
        try:
            observation = next(iter(observations.values()))
            observation["packet"]["admission_transaction"]["message"]["payload"][
                "base_sha"
            ] = "d" * 40
            audit = audit_pull_buffer(
                self.store.connection,
                REPOSITORY,
                record=False,
                now="2026-08-24T10:00:03Z",
                database=self.database,
                artifact_observations=observations,
            )
        finally:
            close_candidate_observations(observations)

        self.assertEqual(0, audit["executable_ready_depth"])
        self.assertEqual(0, audit["dispatchable_now_depth"])
        self.assertIn(
            "ADMISSION_PACKET_BINDING_DRIFT",
            {
                reason
                for candidate in audit["invalid"]
                for reason in candidate["reasons"]
            },
        )

    def test_all_canonical_development_dispatch_bindings_are_required(self) -> None:
        self._register_ready_candidate()
        observations = load_candidate_packets(
            self.store.connection,
            REPOSITORY,
            database=self.database,
            keep_descriptors=True,
        )
        try:
            observation = next(iter(observations.values()))
            admission = observation["packet"]["admission_transaction"]
            candidate = dict(
                self.store.connection.execute(
                    "SELECT candidate.* FROM portfolio_pull_buffer_current pointer "
                    "JOIN portfolio_pull_buffer_candidates candidate "
                    "ON candidate.id=pointer.candidate_id WHERE pointer.issue_number=2"
                ).fetchone()
            )
            changes_before = self.store.connection.total_changes
            for field in (
                "writer",
                "reviewer_plan",
                "collision_proof",
                "environment_rule",
                "routine_chain",
                "hard_stops",
            ):
                with self.subTest(field=field):
                    incomplete = deepcopy(admission)
                    incomplete["message"]["payload"].pop(field)
                    self.assertEqual(
                        "ADMISSION_DISPATCH_BINDING_INCOMPLETE",
                        admission_binding_error(
                            incomplete,
                            candidate=candidate,
                            observed_main_sha=MAIN,
                            observation=observation,
                            connection=self.store.connection,
                        ),
                    )
            self.assertEqual(changes_before, self.store.connection.total_changes)
        finally:
            close_candidate_observations(observations)

    def test_shared_dispatch_validator_rejects_wrong_types_and_empty_values(
        self,
    ) -> None:
        self._register_ready_candidate()
        observations = load_candidate_packets(
            self.store.connection,
            REPOSITORY,
            database=self.database,
            keep_descriptors=True,
        )
        try:
            observation = next(iter(observations.values()))
            admission = observation["packet"]["admission_transaction"]
            candidate = dict(
                self.store.connection.execute(
                    "SELECT candidate.* FROM portfolio_pull_buffer_current pointer "
                    "JOIN portfolio_pull_buffer_candidates candidate "
                    "ON candidate.id=pointer.candidate_id WHERE pointer.issue_number=2"
                ).fetchone()
            )
            wrong_types = {
                "writer": ["writer"],
                "reviewer_plan": ("review",),
                "collision_proof": {"proof": "clear"},
                "environment_rule": ["isolated"],
                "routine_chain": "deliver",
                "hard_stops": {"stop": "drift"},
            }
            semantic_empties = {
                "writer": "   ",
                "reviewer_plan": ["   "],
                "collision_proof": ["\t"],
                "environment_rule": "\n",
                "routine_chain": [""],
                "hard_stops": ["   "],
            }
            changes_before = self.store.connection.total_changes
            for category, invalid_values in (
                ("wrong_type", wrong_types),
                ("semantic_empty", semantic_empties),
            ):
                for field, value in invalid_values.items():
                    with self.subTest(category=category, field=field):
                        invalid = deepcopy(admission)
                        invalid["message"]["payload"][field] = value
                        self.assertEqual(
                            "ADMISSION_DISPATCH_BINDING_INVALID",
                            admission_binding_error(
                                invalid,
                                candidate=candidate,
                                observed_main_sha=MAIN,
                                observation=observation,
                                connection=self.store.connection,
                            ),
                        )
            self.assertEqual(changes_before, self.store.connection.total_changes)
        finally:
            close_candidate_observations(observations)

    def test_incomplete_dispatch_binding_never_partially_activates_sqlite(self) -> None:
        self._register_ready_candidate()
        self._release()
        convergence = self._convergence()
        original_reader = convergence._read_external_context

        def incomplete_reader(event: dict) -> dict:
            context = original_reader(event)
            observation = next(iter(context["candidate_observations"].values()))
            observation["packet"]["admission_transaction"]["message"]["payload"].pop(
                "reviewer_plan"
            )
            return context

        convergence.external_reader = incomplete_reader
        result = convergence.consume_one("2026-08-24T10:00:04Z")

        item = self.store.connection.execute(
            "SELECT status, allocation_class, version FROM coordination_items "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("RETRY", result["state"])
        self.assertIn(
            "ADMISSION_DISPATCH_BINDING_INCOMPLETE:issue:2", result["blockers"]
        )
        self.assertEqual(("READY", "NONE", self.ready_item["version"]), tuple(item))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE topic IN ('development.admission','sre.admission')"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches WHERE issue_number=2"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current WHERE issue_number=2"
            ).fetchone()[0],
        )

    def test_substituted_lease_registry_lineage_never_partially_activates_sqlite(self) -> None:
        self._register_ready_candidate(existing_lease=True)
        self._release()
        convergence = self._convergence()
        original_reader = convergence._read_external_context

        def substituted_registry_reader(event: dict) -> dict:
            context = original_reader(event)
            observation = next(iter(context["candidate_observations"].values()))
            registered = observation["admission_artifacts"][0]["entry"][
                "registered_artifact"
            ]
            registered["repository"] = "attacker/substituted-lineage"
            return context

        convergence.external_reader = substituted_registry_reader
        result = convergence.consume_one("2026-08-24T10:00:04Z")

        item = self.store.connection.execute(
            "SELECT status, allocation_class, version FROM coordination_items "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("RETRY", result["state"])
        self.assertIn("ADMISSION_LEASE_ARTIFACT_DRIFT:issue:2", result["blockers"])
        self.assertEqual(("READY", "NONE", self.ready_item["version"]), tuple(item))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE topic IN ('development.admission','sre.admission')"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches WHERE issue_number=2"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_current WHERE issue_number=2"
            ).fetchone()[0],
        )

    def test_every_immutable_lease_registry_identity_field_is_revalidated(self) -> None:
        self._register_ready_candidate(existing_lease=True)
        observations = load_candidate_packets(
            self.store.connection,
            REPOSITORY,
            database=self.database,
            keep_descriptors=True,
        )
        try:
            observation = next(iter(observations.values()))
            admission = observation["packet"]["admission_transaction"]
            candidate = dict(
                self.store.connection.execute(
                    "SELECT candidate.* FROM portfolio_pull_buffer_current pointer "
                    "JOIN portfolio_pull_buffer_candidates candidate "
                    "ON candidate.id=pointer.candidate_id WHERE pointer.issue_number=2"
                ).fetchone()
            )
            registered = observation["admission_artifacts"][0]["entry"][
                "registered_artifact"
            ]
            substitutions = {
                "artifact_key": "f" * 64,
                "repository": "attacker/substituted-lineage",
                "issue_number": 999,
                "generation": 999,
                "relative_path": "plans/substituted-lease.json",
                "content_sha256": "f" * 64,
                "size_bytes": int(registered["size_bytes"]) + 1,
                "device_id": int(registered["device_id"]) + 1,
                "inode": int(registered["inode"]) + 1,
                "retention_class": "RETAINED",
                "registered_at": "2026-08-24T10:00:02.000001Z",
            }
            changes_before = self.store.connection.total_changes
            for field, substituted in substitutions.items():
                with self.subTest(field=field):
                    drifted = deepcopy(observation)
                    drifted["admission_artifacts"][0]["entry"][
                        "registered_artifact"
                    ][field] = substituted
                    self.assertEqual(
                        "ADMISSION_LEASE_ARTIFACT_DRIFT",
                        admission_binding_error(
                            admission,
                            candidate=candidate,
                            observed_main_sha=MAIN,
                            observation=drifted,
                            connection=self.store.connection,
                        ),
                    )
            self.assertEqual(changes_before, self.store.connection.total_changes)
        finally:
            close_candidate_observations(observations)

    def test_injected_readers_initialize_pull_buffer_schema_on_fresh_store(self) -> None:
        fresh_database = self.root / "fresh.sqlite3"
        fresh_store = CoordinationStore(fresh_database)
        try:
            PortfolioConvergence(
                fresh_store,
                external_reader=lambda _event: {"candidate_observations": {}},
                canonical_main_reader=lambda _repository: MAIN,
            )
            installed = {
                row[0]
                for row in fresh_store.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name LIKE 'portfolio_pull_buffer_%'"
                )
            }
            self.assertEqual(
                {
                    "portfolio_pull_buffer_candidates",
                    "portfolio_pull_buffer_current",
                    "portfolio_pull_buffer_audits",
                    "portfolio_pull_buffer_retirements",
                },
                installed,
            )
        finally:
            fresh_store.close()

    def test_convergence_prereads_lease_bytes_and_fails_on_descriptor_drift(self) -> None:
        packet_path = self._register_ready_candidate()
        self._release()
        original_reader = PortfolioConvergence(self.store)._read_external_context

        def drifting_reader(event: dict) -> dict:
            self.assertFalse(self.store.connection.in_transaction)
            context = original_reader(event)
            packet = next(iter(context["candidate_observations"].values()))["packet"]
            lease_path = Path(
                packet["admission_transaction"]["artifacts"][0]["path"]
            )
            lease_path.write_bytes(lease_path.read_bytes() + b" ")
            return context

        result = self._convergence(external_reader=drifting_reader).consume_one(
            "2026-08-24T10:00:04Z"
        )

        self.assertEqual("RETRY", result["state"])
        self.assertIn("ADMISSION_LEASE_ARTIFACT_DRIFT:issue:2", result["blockers"])
        self.assertTrue(packet_path.exists())

    def test_late_rollback_preserves_release_and_recovers_once(self) -> None:
        self._register_ready_candidate()
        self._release()

        def failpoint(name: str) -> None:
            if name == "before_event_complete":
                raise PortfolioConvergenceError("INJECTED_LATE_ROLLBACK")

        failed = self._convergence(failpoint=failpoint).consume_one(
            "2026-08-24T10:00:04Z"
        )
        released = self.store.connection.execute(
            "SELECT status, allocation_class FROM coordination_items WHERE repository=? AND issue_number=1",
            (REPOSITORY,),
        ).fetchone()
        candidate = self.store.connection.execute(
            "SELECT status, allocation_class FROM coordination_items WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("RETRY", failed["state"])
        self.assertEqual(("DONE", "NONE"), tuple(released))
        self.assertEqual(("READY", "NONE"), tuple(candidate))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE topic IN ('development.admission','sre.admission')"
            ).fetchone()[0],
        )

        recovered = self._convergence().consume_one(
            "2026-08-24T10:00:10Z"
        )
        second = self._convergence().consume_one(
            "2026-08-24T10:00:11Z"
        )
        self.assertEqual("ADMITTED", recovered["outcome"])
        self.assertEqual("RETRY", second["state"])
        self.assertEqual("NO_ADMISSION", second["outcome"])
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE topic IN ('development.admission','sre.admission')"
            ).fetchone()[0],
        )

    def test_final_main_fence_rolls_back_activated_admission(self) -> None:
        self._register_ready_candidate()
        self._release()
        main = [MAIN]

        def drift_before_event_complete(name: str) -> None:
            if name == "before_event_complete":
                main[0] = "d" * 40

        result = PortfolioConvergence(
            self.store,
            canonical_main_reader=lambda _repository: main[0],
            failpoint=drift_before_event_complete,
        ).consume_one("2026-08-24T10:00:04Z")

        candidate = self.store.connection.execute(
            "SELECT status, allocation_class FROM coordination_items "
            "WHERE repository=? AND issue_number=2",
            (REPOSITORY,),
        ).fetchone()
        self.assertEqual("RETRY", result["state"])
        self.assertEqual(
            "CANONICAL_MAIN_CHANGED_BEFORE_ADMISSION_COMMIT", result["error"]
        )
        self.assertEqual(("READY", "NONE"), tuple(candidate))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE topic IN ('development.admission','sre.admission')"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_terminal_watches WHERE issue_number=2"
            ).fetchone()[0],
        )
        event = self.store.connection.execute(
            "SELECT state, attempts, last_error FROM portfolio_dirty_events ORDER BY id LIMIT 1"
        ).fetchone()
        self.assertEqual(
            ("RETRY", 1, "CANONICAL_MAIN_CHANGED_BEFORE_ADMISSION_COMMIT"),
            tuple(event),
        )

    def test_two_consumers_are_fenced_after_external_reads(self) -> None:
        self._register_ready_candidate()
        self._release()
        second_store = CoordinationStore(self.database)
        winner_results: list[dict] = []
        loser = self._convergence(second_store)

        def interleaved_reader(event: dict) -> dict:
            self.assertFalse(second_store.connection.in_transaction)
            context = loser._read_external_context(event)
            winner_results.append(
                self._convergence().consume_one(
                    "2026-08-24T10:00:04Z"
                )
            )
            return context

        loser.external_reader = interleaved_reader
        try:
            fenced = loser.consume_one("2026-08-24T10:00:04Z")
        finally:
            second_store.close()

        self.assertEqual("ADMITTED", winner_results[0]["outcome"])
        self.assertEqual("FENCED", fenced["state"])
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_messages "
                "WHERE topic IN ('development.admission','sre.admission')"
            ).fetchone()[0],
        )

    def test_bounded_retry_holds_after_five_external_failures(self) -> None:
        self._release()

        def unavailable(_event: dict) -> dict:
            raise PortfolioConvergenceError("EXTERNAL_READ_FAILED")

        convergence = self._convergence(external_reader=unavailable)
        results = [
            convergence.consume_one(timestamp)
            for timestamp in (
                "2026-08-24T10:00:04Z",
                "2026-08-24T10:00:10Z",
                "2026-08-24T10:00:21Z",
                "2026-08-24T10:00:42Z",
                "2026-08-24T10:01:23Z",
            )
        ]
        self.assertEqual(["RETRY"] * 4 + ["HOLD"], [item["state"] for item in results])
        event = self.store.connection.execute(
            "SELECT state, attempts, last_error FROM portfolio_dirty_events"
        ).fetchone()
        self.assertEqual(("HOLD", 5, "EXTERNAL_READ_FAILED"), tuple(event))

    def test_ready_registration_rearms_after_prior_release_event_holds(self) -> None:
        self._release()
        convergence = self._convergence()
        for timestamp in (
            "2026-08-24T10:00:04Z",
            "2026-08-24T10:00:10Z",
            "2026-08-24T10:00:21Z",
            "2026-08-24T10:00:42Z",
            "2026-08-24T10:01:23Z",
        ):
            held = convergence.consume_one(timestamp)
        self.assertEqual("HOLD", held["state"])

        self._register_ready_candidate()
        admitted = convergence.consume_one("2026-08-24T10:01:24Z")

        self.assertEqual("ADMITTED", admitted["outcome"])
        self.assertEqual(2, admitted["admitted_issue_number"])

    def test_public_ready_registration_cannot_mutate_identical_database_copy(self) -> None:
        packet_path = self._register_ready_candidate()
        copied_path = self.root / "unissued-copy.sqlite3"
        copied = CoordinationStore(copied_path)
        try:
            self.store.connection.backup(copied.connection)
            before = copied.connection.total_changes
            before_rows = tuple(
                copied.connection.execute(
                    "SELECT "
                    "(SELECT COUNT(*) FROM portfolio_pull_buffer_candidates),"
                    "(SELECT COUNT(*) FROM portfolio_ready_finalizations),"
                    "(SELECT COUNT(*) FROM portfolio_dirty_events),"
                    "(SELECT COUNT(*) FROM coordination_events)"
                ).fetchone()
            )
            with self.assertRaisesRegex(
                PullBufferError, "PULL_BUFFER_READY_FINALIZER_REQUIRED"
            ):
                register_candidate(
                    copied.connection,
                    copied_path,
                    packet_path,
                    now="2026-08-24T10:00:03Z",
                )
            self.assertEqual(before, copied.connection.total_changes)
            self.assertEqual(
                before_rows,
                tuple(
                    copied.connection.execute(
                        "SELECT "
                        "(SELECT COUNT(*) FROM portfolio_pull_buffer_candidates),"
                        "(SELECT COUNT(*) FROM portfolio_ready_finalizations),"
                        "(SELECT COUNT(*) FROM portfolio_dirty_events),"
                        "(SELECT COUNT(*) FROM coordination_events)"
                    ).fetchone()
                ),
            )
        finally:
            copied.close()

    def test_ready_successor_registration_marks_promotion_from_prepared_pointer(self) -> None:
        ensure_pull_buffer_schema(self.store.connection)
        audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=False,
            now="2026-08-24T10:00:01Z",
            database=self.database,
        )
        self.store.connection.execute(
            """
            INSERT INTO portfolio_pull_buffer_candidates(
                repository, issue_number, generation, item_version,
                source_payload_sha256, accepted_main_sha, graph_version,
                capacity_policy_version, lane_key, state, verticality,
                development_units, shared_units, sre_units, promotion_trigger,
                artifact_relative_path, artifact_content_sha256,
                candidate_sha256, registered_at
            ) VALUES (?, 2, 1, ?, ?, ?, 1, 1, 'lane-2',
                      'PREPARED_NOT_READY', 'END_TO_END', 1, 0, 0,
                      'terminal release', 'plans/historical.json', ?, ?, ?)
            """,
            (
                REPOSITORY,
                self.ready_item["version"],
                self.sources[2],
                MAIN,
                "e" * 64,
                "f" * 64,
                "2026-08-24T10:00:01Z",
            ),
        )
        candidate_id = self.store.connection.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]
        self.store.connection.execute(
            "INSERT INTO portfolio_pull_buffer_current(repository, issue_number, candidate_id, updated_at) "
            "VALUES (?, 2, ?, '2026-08-24T10:00:01Z')",
            (REPOSITORY, candidate_id),
        )

        self._register_ready_candidate()

        newest = self.store.connection.execute(
            "SELECT payload_json FROM portfolio_dirty_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(
            "CANDIDATE_PROMOTED",
            json.loads(newest["payload_json"])["trigger_kind"],
        )

    def test_no_ready_candidate_commits_explicit_zero_wip_deficit(self) -> None:
        self._release()
        result = self._convergence().consume_one(
            "2026-08-24T10:00:04Z"
        )
        occupancy = self.store.connection.execute(
            """
            SELECT COALESCE(SUM(development_units), 0)
            FROM coordination_items
            WHERE allocation_class IN ('ACTIVE','RETAINED')
            """
        ).fetchone()[0]
        event = self.store.connection.execute(
            "SELECT state, result_json FROM portfolio_dirty_events"
        ).fetchone()
        receipt = json.loads(event["result_json"])

        self.assertEqual("RETRY", result["state"])
        self.assertIn("READY_DEPTH_ZERO", result["blockers"])
        self.assertEqual(0, occupancy)
        self.assertEqual("RETRY", event["state"])
        self.assertEqual({"development": 0, "shared": 0, "sre": 0}, receipt["wip_delta"])

    def test_successful_ready_admission_launches_only_after_commit(self) -> None:
        self._register_ready_candidate()
        self._release()
        launch_observations: list[tuple[str, str, str]] = []

        def launcher(
            session_id: str, message_id: int
        ) -> RoleExecutorManagerSubmission:
            event = self.store.connection.execute(
                "SELECT state FROM portfolio_dirty_events"
            ).fetchone()
            item = self.store.connection.execute(
                "SELECT status, allocation_class FROM coordination_items WHERE repository=? AND issue_number=2",
                (REPOSITORY,),
            ).fetchone()
            launch_observations.append((event["state"], item["status"], item["allocation_class"]))
            intent = self.store.connection.execute(
                "SELECT created_at FROM coordination_events "
                "WHERE event_type='SESSION_WAKE_MANAGER_SUBMISSION_INTENT' "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(intent)
            intent_at = str(intent["created_at"])

            target_key = str(message_id)
            invocation_id = hashlib.sha256(
                f"{session_id}:message:{target_key}".encode("utf-8")
            ).hexdigest()[:32]
            reserved, token = reserve_attempt(
                self.store.connection,
                role="development",
                endpoint_id=session_id,
                target_kind="message",
                target_key=target_key,
                now=intent_at,
                precondition=lambda connection: attempt_lineage_for_target(
                    connection, "message", target_key
                ),
            )
            unit = stable_systemd_unit("development", "message", target_key)
            launching = transition_attempt(
                self.store.connection,
                attempt_id=reserved["attempt_id"],
                token=token,
                expected_version=reserved["version"],
                new_state="LAUNCHING",
                systemd_unit=unit,
                systemd_invocation_id=invocation_id,
                systemd_control_group=f"/user.slice/{unit}",
                now=intent_at,
            )
            transition_attempt(
                self.store.connection,
                attempt_id=reserved["attempt_id"],
                token=token,
                expected_version=launching["version"],
                new_state="RUNNING",
                process_id=9000 + message_id,
                now=intent_at,
            )
            return RoleExecutorManagerSubmission(
                systemd_unit=unit,
                systemd_invocation_id=invocation_id,
            )

        supervisor = CoordinationSupervisor(
            self.store,
            convergence=self._convergence(),
            launcher=launcher,
            terminal_watch_launcher=lambda *_args: self.fail(
                "terminal watcher must not launch"
            ),
            process_checker=lambda _session, _target_kind, _target_key: False,
        )
        result = supervisor.run_once("2026-08-24T10:00:04Z")
        audit = audit_pull_buffer(
            self.store.connection,
            REPOSITORY,
            record=False,
            now="2026-08-24T10:00:05Z",
        )

        self.assertEqual("ADMITTED", result["portfolio_convergence"][0]["outcome"])
        self.assertEqual([("COMPLETE", "ACTIVE", "ACTIVE")], launch_observations)
        self.assertEqual(1, len(result["launched"]))
        self.assertEqual(0, audit["executable_ready_depth"])


if __name__ == "__main__":
    unittest.main()
