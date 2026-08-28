from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import coordination_store as coordination_store_module  # noqa: E402
import kanban_pull_buffer as pull_buffer_module  # noqa: E402
from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    terminal_published_body,
    terminal_publication_body,
)
from executor_registry import (  # noqa: E402
    attempt_lineage_for_target,
    current_endpoint,
    reserve_attempt,
    stable_systemd_unit,
    transition_attempt,
)
from hosted_operation_control import HostedOperationControl  # noqa: E402
from kanban_pull_buffer import (  # noqa: E402
    PullBufferError,
    ZERO_WIP_PREPARATION_SCHEMA,
    close_candidate_observations,
    load_candidate_packets,
    prepare_zero_wip_candidate,
    register_candidate,
)
from repository_delivery_policy import (  # noqa: E402
    HARNESS_REPOSITORY,
    canonical_harness_standing_controls,
)
from portfolio_graph import (  # noqa: E402
    PortfolioGraphError,
    _schedule_decision,
    evaluate_graph,
    replace_graph,
    sync_head,
)
from portfolio_convergence import PortfolioConvergence  # noqa: E402
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)
from tests.canonical_ready_fixture import (  # noqa: E402
    finalize_canonical_ready_item,
)


MAIN = "a" * 40
NOW = "2026-08-27T06:00:00Z"


class HarnessZeroWipPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "coordination"
        self.root.mkdir(mode=0o700)
        self.database = self.root / "state.sqlite3"
        goal_raw = b"Harness source lane test planner goal.\n"
        (self.root / "product-planner-goal.md").write_bytes(goal_raw)
        self.goal_sha256 = hashlib.sha256(goal_raw).hexdigest()
        self.store = CoordinationStore(self.database)
        apply_reviewed_current_endpoint_catalog(
            self.store.connection,
            ROOT,
            operation_key="harness-source-lane-tests",
        )
        bootstrap_manifest = {"kind": "harness-source-lane-test-bootstrap"}
        with self.store.transaction():
            self.store.record_bootstrap_provenance(
                bootstrap_id="harness-source-lane-tests",
                manifest_sha256=hashlib.sha256(
                    json.dumps(
                        bootstrap_manifest, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest(),
                manifest=bootstrap_manifest,
                source_harness_repository=HARNESS_REPOSITORY,
                source_harness_main_sha=MAIN,
                source_registry_sha256="1" * 64,
                approved_goal_sha256=self.goal_sha256,
                application_repository="twinfinityai/twinfinityapp",
                application_main_sha="2" * 40,
                archived_database_sha256="3" * 64,
                now=NOW,
            )
        self.sources: dict[int, str] = {}
        for issue in (35, 36):
            snapshot = self.store.ingest_snapshot(
                repository=HARNESS_REPOSITORY,
                object_kind="issue",
                object_number=issue,
                payload={
                    "number": issue,
                    "title": f"Harness issue {issue}",
                    "state": "open",
                    "updated_at": NOW,
                    "milestone": None,
                },
                source_updated_at=NOW,
                fetched_at=NOW,
            )
            self.sources[issue] = snapshot.payload_sha256
        self.store.bootstrap_capacity_policy(
            repository=HARNESS_REPOSITORY,
            development_limit=5,
            shared_limit=2,
            sre_limit=5,
            authority_sha256="7" * 64,
            now=NOW,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def request(self) -> dict:
        return {
            "schema": ZERO_WIP_PREPARATION_SCHEMA,
            "repository": HARNESS_REPOSITORY,
            "observed_main_sha": MAIN,
            "expected_graph_version": 0,
            "expected_item_version": 0,
            "expected_capacity_policy": {
                "version": 1,
                "development_limit": 5,
                "shared_limit": 2,
                "sre_limit": 5,
                "authority_sha256": "7" * 64,
            },
            "issue_sources": [
                {"issue_number": issue, "payload_sha256": self.sources[issue]}
                for issue in (35, 36)
            ],
            "scope": {"kind": "ISSUE_SET", "issue_numbers": [35, 36]},
            "graph": {
                "nodes": [
                    {
                        "node_key": "issue:35",
                        "issue_number": 35,
                        "role": "DELIVERY",
                        "root_kind": "NORMAL",
                        "root_reason": None,
                        "lane_key": "harness-source",
                        "lane_order": 1,
                        "dispatchable": True,
                        "priority_rank": 2,
                        "estimate_units": 1,
                        "development_units": 0,
                        "shared_units": 1,
                        "sre_units": 0,
                    },
                    {
                        "node_key": "issue:36",
                        "issue_number": 36,
                        "role": "CONTROL",
                        "root_kind": "INTENTIONAL",
                        "root_reason": "Bootstrap the bounded harness source lane.",
                        "lane_key": "harness-source",
                        "lane_order": 0,
                        "dispatchable": True,
                        "priority_rank": 1,
                        "estimate_units": 1,
                        "development_units": 0,
                        "shared_units": 1,
                        "sre_units": 0,
                    },
                ],
                "relations": [
                    {
                        "left_node_key": "issue:36",
                        "right_node_key": "issue:35",
                        "relation_kind": "HARD_BLOCK",
                        "reason": "The bootstrap transport precedes its first consumer.",
                        "source_issue_number": 36,
                    },
                    {
                        "left_node_key": "issue:35",
                        "right_node_key": "issue:36",
                        "relation_kind": "COLLISION",
                        "reason": "Only one harness source writer may be active.",
                        "source_issue_number": 36,
                    },
                ],
                "excluded_issues": [],
            },
            "candidate": {
                "issue_number": 36,
                "generation": 1,
                "verticality": "BOUNDED_ENABLER",
                "immediate_product_consumer": "#35",
                "owner_visible_outcome": "Bootstrap one real harness source lane.",
                "preparation_complete": ["Exact graph and source bindings are frozen."],
                "promotion_checks_after_predecessor": [
                    "Revalidate main, sources, graph, collisions, and capacity."
                ],
                "hard_stops": canonical_harness_standing_controls()["hard_stops"],
                "promotion_trigger": "All readiness gates pass.",
            },
        }

    def prepare(
        self,
        request: dict | None = None,
        *,
        failpoint=None,
        canonical_main_reader=None,
    ) -> dict:
        return prepare_zero_wip_candidate(
            self.store,
            self.request() if request is None else request,
            now=NOW,
            canonical_main_reader=(
                (lambda _repository: MAIN)
                if canonical_main_reader is None
                else canonical_main_reader
            ),
            failpoint=failpoint,
        )

    def _register_hidden_git_dir(self) -> Path:
        git_dir = self.root / ".harness-common-git"
        git_dir.mkdir()
        (git_dir / "config").write_text(
            "[core]\n\tbare = true\n"
            '[remote "origin"]\n'
            f"\turl = https://github.com/{HARNESS_REPOSITORY}.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            encoding="utf-8",
        )
        ref = git_dir / "refs" / "remotes" / "origin" / "main"
        ref.parent.mkdir(parents=True)
        ref.write_text(MAIN + "\n", encoding="ascii")
        bootstrap = self.store.connection.execute(
            "SELECT bootstrap_id,manifest_sha256 FROM coordination_bootstrap_provenance"
        ).fetchone()
        with self.store.transaction():
            self.store.record_repository_git_registration(
                repository=HARNESS_REPOSITORY,
                git_dir=git_dir,
                source_main_sha=MAIN,
                bootstrap_id=bootstrap["bootstrap_id"],
                bootstrap_manifest_sha256=bootstrap["manifest_sha256"],
                now=NOW,
            )
        return git_dir

    def test_default_main_reader_uses_registered_hidden_git_dir(self) -> None:
        git_dir = self._register_hidden_git_dir()
        self.assertFalse((self.root / "twinfinity-harness").exists())

        prepared = prepare_zero_wip_candidate(self.store, self.request(), now=NOW)

        self.assertEqual("PREPARED_NOT_READY", prepared["state"])
        self.assertEqual(
            MAIN,
            self.store.read_registered_repository_main(HARNESS_REPOSITORY),
        )
        self.assertTrue(git_dir.is_dir())

    def test_missing_registration_fails_before_zero_wip_state(self) -> None:
        with self.assertRaisesRegex(
            PullBufferError, "ZERO_WIP_MAIN_EVIDENCE_INVALID"
        ):
            prepare_zero_wip_candidate(self.store, self.request(), now=NOW)

        for table in (
            "portfolio_graph_revisions",
            "portfolio_pull_buffer_candidates",
            "coordination_items",
            "coordination_messages",
            "coordination_terminal_watches",
        ):
            exists = self.store.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            self.assertEqual(
                0,
                0
                if exists is None
                else self.store.connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0],
                table,
            )

    def test_absent_state_prepares_one_zero_wip_candidate_and_replays_exactly(self) -> None:
        first = self.prepare()
        counts = {
            table: int(self.store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "portfolio_graph_revisions",
                "portfolio_graph_nodes",
                "portfolio_graph_relations",
                "portfolio_pull_buffer_candidates",
                "portfolio_pull_buffer_current",
                "coordination_items",
                "coordination_artifacts",
                "coordination_messages",
                "coordination_terminal_watches",
                "executor_attempts",
                "coordination_pre_push_gates",
                "coordination_pre_push_publications",
                "portfolio_dirty_events",
            )
        }
        second = self.prepare()
        replay_counts = {
            table: int(self.store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in counts
        }

        self.assertFalse(first["replay"])
        self.assertTrue(second["replay"])
        self.assertEqual(first["candidate_sha256"], second["candidate_sha256"])
        self.assertEqual(counts, replay_counts)
        self.assertEqual(1, counts["portfolio_graph_revisions"])
        self.assertEqual(2, counts["portfolio_graph_nodes"])
        self.assertEqual(2, counts["portfolio_graph_relations"])
        self.assertEqual(1, counts["portfolio_pull_buffer_candidates"])
        self.assertEqual(1, counts["portfolio_pull_buffer_current"])
        self.assertEqual(1, counts["coordination_items"])
        for table in (
            "coordination_messages",
            "coordination_terminal_watches",
            "executor_attempts",
            "coordination_pre_push_gates",
            "coordination_pre_push_publications",
            "portfolio_dirty_events",
        ):
            self.assertEqual(0, counts[table], table)
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=36",
            (HARNESS_REPOSITORY,),
        ).fetchone()
        self.assertEqual("PREPARED", item["status"])
        self.assertEqual("NONE", item["allocation_class"])
        self.assertEqual((0, 1, 0), tuple(item[key] for key in (
            "development_units", "shared_units", "sre_units"
        )))

    def test_failure_rolls_back_every_database_write(self) -> None:
        for phase in ("after_graph", "after_item", "after_artifact", "after_candidate"):
            with self.subTest(phase=phase):
                self.tearDown()
                self.setUp()

                def failpoint(observed: str) -> None:
                    if observed == phase:
                        raise RuntimeError(phase)

                with self.assertRaisesRegex(RuntimeError, phase):
                    self.prepare(failpoint=failpoint)
                for table in (
                    "portfolio_graph_revisions",
                    "portfolio_graph_nodes",
                    "portfolio_graph_relations",
                    "portfolio_pull_buffer_candidates",
                    "portfolio_pull_buffer_current",
                    "coordination_items",
                    "coordination_artifacts",
                ):
                    self.assertEqual(
                        0,
                        self.store.connection.execute(
                            f"SELECT COUNT(*) FROM {table}"
                        ).fetchone()[0],
                        (phase, table),
                    )
                preparations = self.root / "preparations"
                self.assertEqual(
                    [], list(preparations.iterdir()) if preparations.exists() else []
                )

    def test_artifact_write_fsync_and_unlink_failures_are_recoverable(self) -> None:
        preparations = self.root / "preparations"
        preparations.mkdir(mode=0o700)

        class FailingStream:
            def __init__(self, descriptor: int):
                self.descriptor = descriptor

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def write(self, _raw: bytes) -> None:
                raise OSError("injected write failure")

            def flush(self) -> None:
                return None

            def fileno(self) -> int:
                return self.descriptor

        with patch.object(
            pull_buffer_module.os,
            "fdopen",
            side_effect=lambda descriptor, *_args, **_kwargs: FailingStream(
                descriptor
            ),
        ):
            with self.assertRaisesRegex(OSError, "injected write failure"):
                self.prepare()
        self.assertEqual([], list(preparations.iterdir()))

        real_fsync = os.fsync
        fsync_calls = 0

        def fail_first_fsync(descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 1:
                raise OSError("injected fsync failure")
            real_fsync(descriptor)

        with patch.object(
            pull_buffer_module.os, "fsync", side_effect=fail_first_fsync
        ):
            with self.assertRaisesRegex(OSError, "injected fsync failure"):
                self.prepare()
        self.assertEqual([], list(preparations.iterdir()))

        real_unlink = os.unlink
        unlink_calls = 0

        def fail_first_unlink(path) -> None:
            nonlocal unlink_calls
            unlink_calls += 1
            if unlink_calls == 1:
                raise OSError("injected unlink failure")
            real_unlink(path)

        with patch.object(
            pull_buffer_module.os, "unlink", side_effect=fail_first_unlink
        ):
            with self.assertRaisesRegex(OSError, "injected unlink failure"):
                self.prepare()
        self.assertEqual([], list(preparations.iterdir()))

    def test_linked_process_remnant_is_exactly_recovered(self) -> None:
        preparations = self.root / "preparations"
        preparations.mkdir(mode=0o700)
        packet = preparations / "harness-issue-36-recovery.json"
        raw = b'{"packet":"exact"}\n'
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{packet.name}.", dir=preparations
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, raw)
            os.fsync(descriptor)
            os.link(temporary, packet, follow_symlinks=False)
        finally:
            os.close(descriptor)

        self.assertTrue(
            pull_buffer_module._materialize_zero_wip_packet(packet, raw)
        )
        self.assertEqual(raw, packet.read_bytes())
        self.assertEqual(1, packet.stat().st_nlink)
        self.assertEqual([packet], list(preparations.iterdir()))

    def test_partial_unlinked_process_remnant_is_safely_retired(self) -> None:
        preparations = self.root / "preparations"
        preparations.mkdir(mode=0o700)
        packet = preparations / "harness-issue-36-recovery.json"
        raw = b'{"packet":"exact"}\n'
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{packet.name}.", dir=preparations
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, raw[:5])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        self.assertTrue(
            pull_buffer_module._materialize_zero_wip_packet(packet, raw)
        )
        self.assertFalse(temporary.exists())
        self.assertEqual(raw, packet.read_bytes())
        self.assertEqual([packet], list(preparations.iterdir()))

    def test_base_exception_rolls_back_and_cleans_materialized_packet(self) -> None:
        original_materialize = pull_buffer_module._materialize_zero_wip_packet

        def materialize_then_interrupt(path: Path, raw: bytes) -> bool:
            original_materialize(path, raw)
            raise KeyboardInterrupt("injected process interruption")

        with patch.object(
            pull_buffer_module,
            "_materialize_zero_wip_packet",
            side_effect=materialize_then_interrupt,
        ), self.assertRaisesRegex(
            KeyboardInterrupt, "injected process interruption"
        ):
            self.prepare()
        self.assertFalse(self.store.connection.in_transaction)
        preparations = self.root / "preparations"
        self.assertEqual([], list(preparations.iterdir()))
        self.assertFalse(self.prepare()["replay"])

    def test_interruption_after_successful_commit_preserves_registered_packet(self) -> None:
        def commit_then_interrupt(connection) -> None:
            connection.execute("COMMIT")
            raise KeyboardInterrupt("injected post-commit interruption")

        with patch.object(
            pull_buffer_module,
            "_commit_zero_wip",
            side_effect=commit_then_interrupt,
        ), self.assertRaisesRegex(
            KeyboardInterrupt, "injected post-commit interruption"
        ):
            self.prepare()
        self.assertFalse(self.store.connection.in_transaction)
        packet_paths = list((self.root / "preparations").glob("*.json"))
        self.assertEqual(1, len(packet_paths))
        artifact = self.store.connection.execute(
            "SELECT relative_path FROM coordination_artifacts"
        ).fetchone()
        self.assertEqual(
            packet_paths[0].relative_to(self.root).as_posix(),
            artifact["relative_path"],
        )
        self.assertTrue(self.prepare()["replay"])

    def test_changed_request_retires_old_unregistered_final_and_partial_temp(self) -> None:
        preparations = self.root / "preparations"
        preparations.mkdir(mode=0o700)
        old_final = preparations / f"harness-issue-36-{'1' * 64}.json"
        old_temp = preparations / f".harness-issue-36-{'2' * 64}.json.partial"
        old_final.write_bytes(b"old complete crash remnant\n")
        old_temp.write_bytes(b"partial")
        old_final.chmod(0o600)
        old_temp.chmod(0o600)

        result = self.prepare()
        self.assertFalse(result["replay"])
        self.assertFalse(old_final.exists())
        self.assertFalse(old_temp.exists())
        self.assertEqual(
            [self.root / result["artifact_relative_path"]],
            list(preparations.iterdir()),
        )

    def test_changed_candidate_retires_final_temp_and_linked_crash_remnants(self) -> None:
        preparations = self.root / "preparations"
        preparations.mkdir(mode=0o700)
        old_final = preparations / f"harness-issue-35-{'1' * 64}.json"
        old_temp = preparations / f".harness-issue-34-{'2' * 64}.json.partial"
        linked_final = preparations / f"harness-issue-33-{'3' * 64}.json"
        linked_temp = preparations / f".{linked_final.name}.linked"
        old_final.write_bytes(b"old candidate final\n")
        old_temp.write_bytes(b"old candidate partial")
        linked_final.write_bytes(b"old linked candidate\n")
        os.link(linked_final, linked_temp)
        for path in (old_final, old_temp, linked_final, linked_temp):
            path.chmod(0o600)

        result = self.prepare()
        self.assertFalse(result["replay"])
        for path in (old_final, old_temp, linked_final, linked_temp):
            self.assertFalse(path.exists())
        self.assertEqual(
            [self.root / result["artifact_relative_path"]],
            list(preparations.iterdir()),
        )

    def test_post_commit_orphan_cleanup_rejects_substituted_preparation_directory(self) -> None:
        original_retire = pull_buffer_module._retire_zero_wip_orphans_after_commit
        substituted_victim: Path | None = None

        def substitute_then_retire(store, keep_path, expected_directory_identity):
            nonlocal substituted_victim
            preparations = keep_path.parent
            saved = self.root / "preparations-original"
            preparations.rename(saved)
            preparations.mkdir(mode=0o700)
            substituted_victim = (
                preparations / f"harness-issue-35-{'9' * 64}.json"
            )
            substituted_victim.write_bytes(b"unrelated substituted namespace\n")
            substituted_victim.chmod(0o600)
            return original_retire(store, keep_path, expected_directory_identity)

        with patch.object(
            pull_buffer_module,
            "_retire_zero_wip_orphans_after_commit",
            side_effect=substitute_then_retire,
        ):
            result = self.prepare()

        self.assertEqual("HOLD", result["orphan_retirement"])
        self.assertIsNotNone(substituted_victim)
        self.assertTrue(substituted_victim.exists())
        self.assertEqual(b"unrelated substituted namespace\n", substituted_victim.read_bytes())

    def test_two_connections_same_request_serialize_to_one_create_and_one_replay(self) -> None:
        request = self.request()

        def run_prepare() -> dict:
            store = CoordinationStore(self.database)
            try:
                return prepare_zero_wip_candidate(
                    store,
                    copy.deepcopy(request),
                    now=NOW,
                    canonical_main_reader=lambda _repository: MAIN,
                )
            finally:
                store.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: run_prepare(), range(2)))
        self.assertEqual([False, True], sorted(result["replay"] for result in results))
        self.assertEqual(
            1,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_pull_buffer_candidates"
            ).fetchone()[0],
        )
        self.assertEqual(1, len(list((self.root / "preparations").iterdir())))

    def test_process_interruption_before_link_cleans_temporary(self) -> None:
        with patch.object(
            pull_buffer_module.os,
            "link",
            side_effect=KeyboardInterrupt("injected pre-link interruption"),
        ), self.assertRaisesRegex(
            KeyboardInterrupt, "injected pre-link interruption"
        ):
            self.prepare()
        preparations = self.root / "preparations"
        self.assertEqual([], list(preparations.iterdir()))
        self.assertFalse(self.prepare()["replay"])
        self.assertEqual(1, len(list(preparations.glob("*.json"))))
        self.assertEqual([], list(preparations.glob(".*")))

    def test_replay_rejects_registry_identity_and_active_allocation_drift(self) -> None:
        first = self.prepare()
        packet = self.root / first["artifact_relative_path"]
        held_descriptor = os.open(packet, os.O_RDONLY)
        try:
            packet.unlink()
            with self.assertRaisesRegex(
                PullBufferError, "ZERO_WIP_REPLAY_ARTIFACT_DRIFT"
            ):
                self.prepare()
        finally:
            os.close(held_descriptor)
        self.assertFalse(packet.exists())

        competing = self.store.ingest_snapshot(
            repository=HARNESS_REPOSITORY,
            object_kind="issue",
            object_number=37,
            payload={
                "number": 37,
                "title": "Competing source lane",
                "state": "open",
                "updated_at": NOW,
                "milestone": None,
            },
            source_updated_at=NOW,
            fetched_at=NOW,
        )
        self.store._set_issue_status_for_test_fixture(
            repository=HARNESS_REPOSITORY,
            issue_number=37,
            status="ACTIVE",
            allocation_class="ACTIVE",
            generation=1,
            accountable_session_id="role.development.v4",
            lease_manifest_sha256="4" * 64,
            development_units=0,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=competing.payload_sha256,
            expected_version=0,
            now=NOW,
        )
        with self.assertRaisesRegex(
            PullBufferError, "ZERO_WIP_ALLOCATION_PRESENT"
        ):
            self.prepare()

    def test_prepared_hosted_sre_operation_blocks_zero_wip_preparation(self) -> None:
        sre = current_endpoint(self.store.connection, "sre")
        self.assertIsNotNone(sre)
        authority_body = "Bounded hosted-operation test authority"
        authority = {
            "id": 1234,
            "issue_url": (
                f"https://api.github.com/repos/{HARNESS_REPOSITORY}/issues/36"
            ),
            "body": authority_body,
        }
        control = HostedOperationControl(self.database)
        try:
            transaction = {
                "idempotency_key": "harness-zero-wip-hosted-sre",
                "repository": HARNESS_REPOSITORY,
                "issue_number": 36,
                "source_payload_sha256": self.sources[36],
                "provider": "github",
                "target_kind": "github_ruleset",
                "target_key": "1",
                "operation_kind": "UPDATE_SETTINGS",
                "authority_comment_id": 1234,
                "authority_body_sha256": hashlib.sha256(
                    authority_body.encode("utf-8")
                ).hexdigest(),
                "recipient_session_id": str(sre["endpoint_id"]),
                "sre_units": 1,
                "blocked_by_issue_number": None,
                "scope": {
                    "target": {
                        "repository": HARNESS_REPOSITORY,
                        "ruleset_id": 1,
                    },
                    "expected_state": {
                        "enforcement": "evaluate",
                        "include": [],
                        "required_status_check": None,
                    },
                    "desired_state": {
                        "enforcement": "active",
                        "include": ["refs/heads/main"],
                        "required_status_check": "ci-gate",
                        "required_approving_review_count": 1,
                    },
                    "exclusions": ["No repository content change"],
                    "stop_conditions": ["Source or target drift"],
                },
            }
            with patch.object(
                HostedOperationControl,
                "_validate_approval_guard",
                return_value=None,
            ), patch.object(
                HostedOperationControl,
                "_fetch_authority_comment",
                return_value=authority,
            ):
                prepared = control.prepare(transaction, NOW)
            self.assertEqual("PREPARED", prepared["state"])
        finally:
            control.close()

        with self.assertRaisesRegex(
            PullBufferError, "ZERO_WIP_HOSTED_SRE_PRESENT"
        ):
            self.prepare()
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_graph_revisions"
            ).fetchone()[0],
        )

    def test_public_none_allocation_cannot_manufacture_harness_lease(self) -> None:
        with self.assertRaisesRegex(
            CoordinationError, "HARNESS_ZERO_WIP_LINEAGE_INVALID"
        ):
            self.store.set_issue_status(
                repository=HARNESS_REPOSITORY,
                issue_number=36,
                status="PREPARED",
                allocation_class="NONE",
                generation=1,
                accountable_session_id="role.development.v4",
                lease_manifest_sha256="4" * 64,
                development_units=0,
                shared_units=1,
                sre_units=0,
                expected_source_sha256=self.sources[36],
                expected_version=0,
                now=NOW,
            )
        self.assertIsNone(
            self.store.connection.execute(
                "SELECT 1 FROM coordination_items WHERE repository=? AND issue_number=36",
                (HARNESS_REPOSITORY,),
            ).fetchone()
        )

        self.prepare()
        item = self.store.connection.execute(
            "SELECT accountable_session_id, lease_manifest_sha256 "
            "FROM coordination_items WHERE repository=? AND issue_number=36",
            (HARNESS_REPOSITORY,),
        ).fetchone()
        self.assertEqual((None, None), tuple(item))

    def test_composable_graph_and_candidate_writes_require_outer_transaction(self) -> None:
        for ensure_schema in (False, True):
            with self.subTest(operation="graph", ensure_schema=ensure_schema), self.assertRaisesRegex(
                PortfolioGraphError, "GRAPH_TRANSACTION_REQUIRED"
            ):
                replace_graph(
                    self.store.connection,
                    {},
                    now=NOW,
                    _transaction=False,
                    _ensure_schema=ensure_schema,
                )
            with self.subTest(operation="candidate", ensure_schema=ensure_schema), self.assertRaisesRegex(
                PullBufferError, "PULL_BUFFER_TRANSACTION_REQUIRED"
            ):
                register_candidate(
                    self.store.connection,
                    self.database,
                    self.root / "missing.json",
                    now=NOW,
                    _transaction=False,
                    _ensure_schema=ensure_schema,
                )
        with self.store.transaction(), self.assertRaisesRegex(
            PullBufferError, "ZERO_WIP_TRANSACTION_CONFLICT"
        ):
            self.prepare()

    def test_final_main_fence_rolls_back_post_write_drift(self) -> None:
        observed = iter((MAIN, MAIN, "b" * 40))
        with self.assertRaisesRegex(PullBufferError, "ZERO_WIP_MAIN_DRIFT"):
            self.prepare(canonical_main_reader=lambda _repository: next(observed))
        for table in (
            "portfolio_graph_revisions",
            "portfolio_pull_buffer_candidates",
            "coordination_items",
            "coordination_artifacts",
        ):
            self.assertEqual(
                0,
                self.store.connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0],
                table,
            )
        self.assertEqual([], list((self.root / "preparations").iterdir()))

    def test_issue_set_graph_becomes_stale_when_main_moves(self) -> None:
        self.prepare()
        advanced = "b" * 40

        result = sync_head(
            self.store.connection,
            HARNESS_REPOSITORY,
            advanced,
            expected_version=1,
            expected_observed_main_sha=MAIN,
            now="2026-08-27T06:01:00Z",
        )
        evaluation = evaluate_graph(
            self.store.connection,
            HARNESS_REPOSITORY,
            current_main=advanced,
        )
        current = self.store.connection.execute(
            "SELECT health, observed_main_sha, last_error "
            "FROM portfolio_graph_current WHERE repository=?",
            (HARNESS_REPOSITORY,),
        ).fetchone()

        self.assertEqual("STALE", result["health"])
        self.assertEqual("STALE", evaluation["health"])
        self.assertIn("GRAPH_MAIN_DRIFT", evaluation["stale_reasons"])
        self.assertEqual(("STALE", advanced, "GRAPH_MAIN_DRIFT"), tuple(current))

    def test_hard_blocked_successor_cannot_enter_zero_wip_buffer(self) -> None:
        request = self.request()
        request["candidate"].update(
            {
                "issue_number": 35,
                "verticality": "END_TO_END",
                "owner_visible_outcome": "Attempt to skip the source predecessor.",
            }
        )
        request["candidate"].pop("immediate_product_consumer")

        with self.assertRaisesRegex(
            PullBufferError, "ZERO_WIP_CANDIDATE_HARD_BLOCKED"
        ):
            self.prepare(request)
        for table in (
            "portfolio_graph_revisions",
            "portfolio_pull_buffer_candidates",
            "coordination_items",
            "coordination_artifacts",
        ):
            self.assertEqual(
                0,
                self.store.connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0],
                table,
            )

    def test_issue_set_exclusion_is_digest_bound_and_node_overlap_is_rejected(self) -> None:
        snapshot = self.store.ingest_snapshot(
            repository=HARNESS_REPOSITORY,
            object_kind="issue",
            object_number=34,
            payload={
                "number": 34,
                "title": "Excluded harness issue",
                "state": "open",
                "updated_at": NOW,
                "milestone": None,
            },
            source_updated_at=NOW,
            fetched_at=NOW,
        )
        self.sources[34] = snapshot.payload_sha256
        request = self.request()
        request["scope"]["issue_numbers"] = [34, 35, 36]
        request["issue_sources"] = [
            {"issue_number": issue, "payload_sha256": self.sources[issue]}
            for issue in (34, 35, 36)
        ]
        request["graph"]["excluded_issues"] = [
            {"issue_number": 34, "reason": "Not part of the bootstrap slice."}
        ]
        self.prepare(request)
        self.assertEqual(
            "CURRENT",
            evaluate_graph(
                self.store.connection,
                HARNESS_REPOSITORY,
                current_main=MAIN,
            )["health"],
        )
        self.store.connection.execute(
            "DELETE FROM github_current WHERE repository=? "
            "AND object_kind='issue' AND object_number=34",
            (HARNESS_REPOSITORY,),
        )
        stale = evaluate_graph(
            self.store.connection,
            HARNESS_REPOSITORY,
            current_main=MAIN,
        )
        self.assertEqual("STALE", stale["health"])
        self.assertTrue(
            any("GRAPH_SOURCE_MISSING:issue:34" in reason for reason in stale["stale_reasons"]),
            stale,
        )

        self.tearDown()
        self.setUp()
        overlap = self.request()
        overlap["graph"]["excluded_issues"] = [
            {"issue_number": 36, "reason": "Contradictory exclusion."}
        ]
        with self.assertRaisesRegex(PullBufferError, "GRAPH_SCOPE_CONFLICT"):
            # The public graph validator is reached before any artifact or DB write.
            self.prepare(overlap)

    def test_issue_set_rejects_duplicate_issue_nodes_and_milestoned_sources(self) -> None:
        duplicate = self.request()
        duplicate["graph"]["nodes"][1]["issue_number"] = 35
        for relation in duplicate["graph"]["relations"]:
            relation["source_issue_number"] = 35
        with self.assertRaisesRegex(PullBufferError, "GRAPH_NODE_ISSUE_DUPLICATE"):
            self.prepare(duplicate)

        updated = self.store.ingest_snapshot(
            repository=HARNESS_REPOSITORY,
            object_kind="issue",
            object_number=35,
            payload={
                "number": 35,
                "title": "Harness issue 35",
                "state": "open",
                "updated_at": "2026-08-27T06:00:01Z",
                "milestone": {"number": 1, "title": "Fabricated", "state": "open"},
            },
            source_updated_at="2026-08-27T06:00:01Z",
            fetched_at="2026-08-27T06:00:01Z",
        )
        self.sources[35] = updated.payload_sha256
        with self.assertRaisesRegex(
            PullBufferError, "GRAPH_ISSUE_SET_MILESTONE_CONFLICT"
        ):
            self.prepare()

    def test_issue_set_graph_digest_binds_accepted_main(self) -> None:
        first = self.prepare()
        self.tearDown()
        self.setUp()
        request = self.request()
        request["observed_main_sha"] = "b" * 40
        second = self.prepare(
            request, canonical_main_reader=lambda _repository: "b" * 40
        )
        self.assertNotEqual(first["graph_sha256"], second["graph_sha256"])

    def test_bracketed_main_evidence_fails_before_database_or_writer_state(self) -> None:
        observed = iter((MAIN, "b" * 40))
        with self.assertRaisesRegex(PullBufferError, "ZERO_WIP_MAIN_DRIFT"):
            self.prepare(canonical_main_reader=lambda _repository: next(observed))
        for table in (
            "portfolio_graph_revisions",
            "portfolio_pull_buffer_candidates",
            "coordination_items",
            "coordination_messages",
            "coordination_terminal_watches",
        ):
            self.assertEqual(
                0,
                self.store.connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0],
                table,
            )

    def test_zero_wip_rejects_residual_watch_without_mutating_it(self) -> None:
        with self.store.transaction():
            self.store.connection.execute(
                """
                INSERT INTO coordination_terminal_watches(
                    watch_key, repository, issue_number, generation,
                    accountable_session_id, lease_manifest_sha256, state,
                    admission_message_id, admission_payload_sha256,
                    claim_attempt_id, attempts, process_id,
                    target_progress_sha256, last_heartbeat_at, next_wake_at,
                    updated_at, last_error
                ) VALUES (?, ?, 36, 0, 'role.development.v4', ?, 'ACTIVE',
                          NULL, NULL, NULL, 0, NULL, NULL, ?, ?, ?, NULL)
                """,
                ("residual-watch", HARNESS_REPOSITORY, "9" * 64, NOW, NOW, NOW),
            )
        with self.assertRaisesRegex(
            PullBufferError,
            "ZERO_WIP_RESIDUAL_STATE:coordination_terminal_watches",
        ):
            self.prepare()
        row = self.store.connection.execute(
            "SELECT state, attempts, updated_at FROM coordination_terminal_watches "
            "WHERE watch_key='residual-watch'"
        ).fetchone()
        self.assertEqual(("ACTIVE", 0, NOW), tuple(row))
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_graph_revisions"
            ).fetchone()[0],
        )

    def test_zero_wip_allows_immutable_completed_history(self) -> None:
        payload = {"source": {"repository": HARNESS_REPOSITORY}}
        payload_raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self.store.transaction():
            self.store.connection.execute(
                """
                INSERT INTO coordination_messages(
                    idempotency_key, recipient_session_id, topic, payload_sha256,
                    payload_json, state, claimed_by, created_at, updated_at, last_error
                ) VALUES ('completed-history', 'role.development.v4',
                          'development.admission', ?, ?, 'COMPLETE',
                          'role.development.v4', ?, ?, NULL)
                """,
                (
                    hashlib.sha256(payload_raw.encode("utf-8")).hexdigest(),
                    payload_raw,
                    NOW,
                    NOW,
                ),
            )
            self.store.connection.execute(
                """
                INSERT INTO coordination_messages(
                    idempotency_key, recipient_session_id, topic, payload_sha256,
                    payload_json, state, claimed_by, created_at, updated_at, last_error
                ) VALUES ('held-history', 'role.development.v4',
                          'development.admission', ?, ?, 'HOLD',
                          NULL, ?, ?, 'historical terminal hold')
                """,
                (
                    hashlib.sha256(payload_raw.encode("utf-8")).hexdigest(),
                    payload_raw,
                    NOW,
                    NOW,
                ),
            )
            self.store.connection.execute(
                """
                INSERT INTO coordination_terminal_watches(
                    watch_key, repository, issue_number, generation,
                    accountable_session_id, lease_manifest_sha256, state,
                    admission_message_id, admission_payload_sha256,
                    claim_attempt_id, attempts, process_id,
                    target_progress_sha256, last_heartbeat_at, next_wake_at,
                    updated_at, last_error
                ) VALUES ('completed-watch', ?, 36, 0, 'role.development.v4', ?,
                          'COMPLETE', NULL, NULL, NULL, 0, NULL, NULL, ?, ?, ?, NULL)
                """,
                (HARNESS_REPOSITORY, "9" * 64, NOW, NOW, NOW),
            )
            self.store.connection.execute(
                """
                INSERT INTO coordination_terminal_watches(
                    watch_key, repository, issue_number, generation,
                    accountable_session_id, lease_manifest_sha256, state,
                    admission_message_id, admission_payload_sha256,
                    claim_attempt_id, attempts, process_id,
                    target_progress_sha256, last_heartbeat_at, next_wake_at,
                    updated_at, last_error
                ) VALUES ('held-watch', ?, 35, 0, 'role.development.v4', ?,
                          'HOLD', NULL, NULL, NULL, 5, NULL, NULL, ?, ?, ?,
                          'historical terminal hold')
                """,
                (HARNESS_REPOSITORY, "8" * 64, NOW, NOW, NOW),
            )
        self.assertFalse(self.prepare()["replay"])

    def test_unreviewed_or_drifting_capacity_policy_never_prepares_wip(self) -> None:
        self.store.connection.execute(
            "DROP TRIGGER coordination_capacity_policy_immutable_update"
        )
        self.store.connection.execute(
            "UPDATE coordination_capacity_policies SET authority_sha256=NULL "
            "WHERE repository=? AND version=1",
            (HARNESS_REPOSITORY,),
        )
        with self.assertRaisesRegex(
            PullBufferError, "ZERO_WIP_CAPACITY_POLICY_MISSING"
        ):
            self.prepare()
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM portfolio_graph_revisions"
            ).fetchone()[0],
        )

        self.tearDown()
        self.setUp()
        stale_request = self.request()
        self.store._set_capacity_policy_for_test_fixture(
            repository=HARNESS_REPOSITORY,
            development_limit=5,
            shared_limit=3,
            sre_limit=5,
            authority_sha256="8" * 64,
            expected_version=1,
            now="2026-08-27T06:00:01Z",
        )
        with self.assertRaisesRegex(PullBufferError, "ZERO_WIP_CAPACITY_POLICY_DRIFT"):
            self.prepare(stale_request)
        for table in (
            "portfolio_graph_revisions",
            "portfolio_pull_buffer_candidates",
            "coordination_items",
            "coordination_artifacts",
            "coordination_messages",
            "coordination_terminal_watches",
        ):
            self.assertEqual(
                0,
                self.store.connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0],
                table,
            )
        self.assertEqual([], list(self.root.rglob("*.json")))

    def test_repository_writer_mutex_selects_and_activates_only_one_lane(self) -> None:
        request = self.request()
        request["graph"]["relations"] = [
            relation
            for relation in request["graph"]["relations"]
            if relation["relation_kind"] == "COLLISION"
        ]
        request["graph"]["nodes"][0].update(
            {
                "root_kind": "INTENTIONAL",
                "root_reason": "Independent source work used to prove the mutex.",
            }
        )
        self.prepare(request)
        development = current_endpoint(self.store.connection, "development")
        self.assertIsNotNone(development)
        self.store._set_issue_status_for_test_fixture(
            repository=HARNESS_REPOSITORY,
            issue_number=35,
            status="PREPARED",
            allocation_class="NONE",
            generation=1,
            accountable_session_id=None,
            lease_manifest_sha256=None,
            development_units=0,
            shared_units=1,
            sre_units=0,
            expected_source_sha256=self.sources[35],
            expected_version=0,
            now=NOW,
        )
        finalize_canonical_ready_item(
            self.store,
            database=self.database,
            artifact_root=self.root,
            repository=HARNESS_REPOSITORY,
            issue_number=36,
            source_payload_sha256=self.sources[36],
            accepted_main_sha=MAIN,
            worker_role="development",
            worker_endpoint_id=str(development["endpoint_id"]),
            now=NOW,
            suffix="mutex-first",
        )
        with patch.object(
            pull_buffer_module,
            "_schedule_decision",
            return_value={"selected": ["issue:35"]},
        ):
            finalize_canonical_ready_item(
                self.store,
                database=self.database,
                artifact_root=self.root,
                repository=HARNESS_REPOSITORY,
                issue_number=35,
                source_payload_sha256=self.sources[35],
                accepted_main_sha=MAIN,
                worker_role="development",
                worker_endpoint_id=str(development["endpoint_id"]),
                now=NOW,
                suffix="mutex-second",
            )
        decision = _schedule_decision(
            self.store.connection,
            HARNESS_REPOSITORY,
            current_main=MAIN,
            record=False,
            now=NOW,
        )
        self.assertEqual(["issue:36"], decision["selected"])
        self.assertIn(
            {"node_key": "issue:35", "reason": "REPOSITORY_WRITER_MUTEX"},
            decision["skipped"],
        )

        observations = load_candidate_packets(
            self.store.connection,
            HARNESS_REPOSITORY,
            database=self.database,
            keep_descriptors=True,
        )
        try:
            candidates = {
                int(row["issue_number"]): row
                for row in self.store.connection.execute(
                    "SELECT candidate.* FROM portfolio_pull_buffer_current pointer "
                    "JOIN portfolio_pull_buffer_candidates candidate "
                    "ON candidate.id=pointer.candidate_id "
                    "WHERE pointer.repository=?",
                    (HARNESS_REPOSITORY,),
                )
            }

            def admission(issue_number: int):
                candidate = candidates[issue_number]
                observation = observations[int(candidate["id"])]
                return observation["packet"]["admission_transaction"], observation

            first, first_observation = admission(36)
            self.store.activate_admission(
                item=first["item"],
                message=first["message"],
                artifacts=first.get("artifacts"),
                artifact_observations=first_observation["admission_artifacts"],
                now="2026-08-27T06:00:01Z",
            )
            second, second_observation = admission(35)
            before_second = dict(
                self.store.connection.execute(
                    "SELECT * FROM coordination_items WHERE repository=? "
                    "AND issue_number=35",
                    (HARNESS_REPOSITORY,),
                ).fetchone()
            )
            with self.assertRaisesRegex(
                CoordinationError, "ADMISSION_REPOSITORY_WRITER_MUTEX"
            ):
                self.store.activate_admission(
                    item=second["item"],
                    message=second["message"],
                    artifacts=second.get("artifacts"),
                    artifact_observations=second_observation[
                        "admission_artifacts"
                    ],
                    now="2026-08-27T06:00:02Z",
                )
            after_second = dict(
                self.store.connection.execute(
                    "SELECT * FROM coordination_items WHERE repository=? "
                    "AND issue_number=35",
                    (HARNESS_REPOSITORY,),
                ).fetchone()
            )
            self.assertEqual(before_second, after_second)
            self.assertEqual(
                1,
                self.store.connection.execute(
                    "SELECT COUNT(*) FROM coordination_messages "
                    "WHERE topic='development.admission'"
                ).fetchone()[0],
            )
            occupied = self.store.connection.execute(
                "SELECT COALESCE(SUM(shared_units),0) FROM coordination_items "
                "WHERE repository=? AND allocation_class IN ('ACTIVE','RETAINED')",
                (HARNESS_REPOSITORY,),
            ).fetchone()[0]
            self.assertEqual(1, occupied)
        finally:
            close_candidate_observations(observations)

    def test_standing_authority_goal_drift_never_activates_or_consumes_capacity(self) -> None:
        self.prepare()
        development = current_endpoint(self.store.connection, "development")
        self.assertIsNotNone(development)
        finalize_canonical_ready_item(
            self.store,
            database=self.database,
            artifact_root=self.root,
            repository=HARNESS_REPOSITORY,
            issue_number=36,
            source_payload_sha256=self.sources[36],
            accepted_main_sha=MAIN,
            worker_role="development",
            worker_endpoint_id=str(development["endpoint_id"]),
            now=NOW,
            suffix="authority-goal-drift",
        )
        before_item = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? "
                "AND issue_number=36",
                (HARNESS_REPOSITORY,),
            ).fetchone()
        )
        lifecycle_tables = (
            "coordination_messages",
            "coordination_terminal_watches",
            "coordination_pre_push_gates",
            "coordination_pre_push_publications",
        )
        before_counts = {
            table: self.store.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in lifecycle_tables
        }
        self.store.connection.execute(
            "DROP TRIGGER coordination_bootstrap_provenance_immutable_update"
        )
        self.store.connection.execute(
            "UPDATE coordination_bootstrap_provenance "
            "SET approved_goal_sha256=?",
            ("8" * 64,),
        )
        result = PortfolioConvergence(
            self.store, canonical_main_reader=lambda _repository: MAIN
        ).consume_one(
            now="2026-08-27T06:01:00Z", repository=HARNESS_REPOSITORY
        )
        self.assertEqual("NO_ADMISSION", result["outcome"], result)
        self.assertTrue(
            any(
                blocker.startswith(
                    "HARNESS_STANDING_AUTHORITY_PROVENANCE_DRIFT:issue:36"
                )
                for blocker in result["blockers"]
            ),
            result,
        )
        after_item = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? "
                "AND issue_number=36",
                (HARNESS_REPOSITORY,),
            ).fetchone()
        )
        self.assertEqual(before_item, after_item)
        for table in lifecycle_tables:
            self.assertEqual(
                before_counts[table],
                self.store.connection.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0],
                table,
            )
        occupied = self.store.connection.execute(
            "SELECT COUNT(*) FROM coordination_items WHERE repository=? "
            "AND allocation_class IN ('ACTIVE','RETAINED')",
            (HARNESS_REPOSITORY,),
        ).fetchone()[0]
        self.assertEqual(0, occupied)

    def test_public_status_api_cannot_create_or_rewrite_harness_reservations(self) -> None:
        self.prepare()
        development = current_endpoint(self.store.connection, "development")
        self.assertIsNotNone(development)
        finalize_canonical_ready_item(
            self.store,
            database=self.database,
            artifact_root=self.root,
            repository=HARNESS_REPOSITORY,
            issue_number=36,
            source_payload_sha256=self.sources[36],
            accepted_main_sha=MAIN,
            worker_role="development",
            worker_endpoint_id=str(development["endpoint_id"]),
            now=NOW,
            suffix="reservation-gateway",
        )
        result = PortfolioConvergence(
            self.store, canonical_main_reader=lambda _repository: MAIN
        ).consume_one("2026-08-27T06:01:00Z", repository=HARNESS_REPOSITORY)
        self.assertEqual("ADMITTED", result["outcome"], result)
        active = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=36",
                (HARNESS_REPOSITORY,),
            ).fetchone()
        )
        common = {
            "repository": HARNESS_REPOSITORY,
            "issue_number": 36,
            "status": "ACTIVE",
            "allocation_class": "ACTIVE",
            "generation": int(active["generation"]),
            "accountable_session_id": active["accountable_session_id"],
            "lease_manifest_sha256": active["lease_manifest_sha256"],
            "development_units": 0,
            "shared_units": 1,
            "sre_units": 0,
            "expected_source_sha256": self.sources[36],
            "expected_version": int(active["version"]),
            "now": "2026-08-27T06:01:01Z",
        }
        wrong_capacity = dict(common, development_units=1, shared_units=0)
        with self.assertRaisesRegex(
            CoordinationError, "HARNESS_SOURCE_CAPACITY_INVALID"
        ):
            self.store.set_issue_status(**wrong_capacity)
        with self.assertRaisesRegex(
            CoordinationError, "HARNESS_RESERVATION_GATEWAY_REQUIRED"
        ):
            self.store.set_issue_status(**common)
        after = dict(
            self.store.connection.execute(
                "SELECT * FROM coordination_items WHERE repository=? AND issue_number=36",
                (HARNESS_REPOSITORY,),
            ).fetchone()
        )
        self.assertEqual(active, after)

    def test_store_contract_rejects_non_development_or_wrong_shared_class(self) -> None:
        self.prepare()
        development = current_endpoint(self.store.connection, "development")
        sre = current_endpoint(self.store.connection, "sre")
        self.assertIsNotNone(development)
        self.assertIsNotNone(sre)
        ready = finalize_canonical_ready_item(
            self.store,
            database=self.database,
            artifact_root=self.root,
            repository=HARNESS_REPOSITORY,
            issue_number=36,
            source_payload_sha256=self.sources[36],
            accepted_main_sha=MAIN,
            worker_role="development",
            worker_endpoint_id=str(development["endpoint_id"]),
            now=NOW,
            suffix="store-class-fence",
        )
        packet = json.loads(ready["ready_path"].read_text(encoding="utf-8"))
        admission = packet["admission_transaction"]

        wrong_shared = copy.deepcopy(admission["message"]["payload"])
        wrong_shared["capacity"]["shared_units"] = 2
        with self.assertRaisesRegex(
            CoordinationError, "MESSAGE_HARNESS_SOURCE_CLASS_MISMATCH"
        ):
            self.store._validate_message_contract(
                topic="development.admission",
                recipient_session_id=str(development["endpoint_id"]),
                payload=wrong_shared,
                projected_item=admission["item"],
            )

        wrong_role = copy.deepcopy(admission["message"]["payload"])
        wrong_role["accountable_session_id"] = str(sre["endpoint_id"])
        with self.assertRaisesRegex(
            CoordinationError, "MESSAGE_HARNESS_SOURCE_CLASS_MISMATCH"
        ):
            self.store._validate_message_contract(
                topic="sre.admission",
                recipient_session_id=str(sre["endpoint_id"]),
                payload=wrong_role,
                projected_item=admission["item"],
            )

    def test_source_capacity_and_scope_drift_fail_before_wip(self) -> None:
        variants: list[tuple[str, dict, str]] = []
        source = copy.deepcopy(self.request())
        source["issue_sources"][1]["payload_sha256"] = "f" * 64
        variants.append(("source", source, "ZERO_WIP_SOURCE_DRIFT"))
        capacity = copy.deepcopy(self.request())
        capacity["graph"]["nodes"][1]["development_units"] = 1
        variants.append(("capacity", capacity, "ZERO_WIP_HARNESS_CAPACITY_INVALID"))
        predecessor_capacity = copy.deepcopy(self.request())
        predecessor_capacity["graph"]["nodes"][0]["shared_units"] = 2
        variants.append(
            (
                "predecessor_capacity",
                predecessor_capacity,
                "ZERO_WIP_HARNESS_CAPACITY_INVALID",
            )
        )
        scope = copy.deepcopy(self.request())
        scope["scope"]["issue_numbers"] = [36]
        variants.append(("scope", scope, "ZERO_WIP_SOURCE_INVENTORY_INVALID"))

        for name, request, error in variants:
            with self.subTest(name=name), self.assertRaisesRegex(PullBufferError, error):
                self.prepare(request)
        self.assertEqual(
            0,
            self.store.connection.execute(
                "SELECT COUNT(*) FROM coordination_items"
            ).fetchone()[0],
        )

    def test_ready_activation_claim_and_terminal_closeout_release_shared_atomically(self) -> None:
        self.prepare()
        development = current_endpoint(self.store.connection, "development")
        self.assertIsNotNone(development)
        ready = finalize_canonical_ready_item(
            self.store,
            database=self.database,
            artifact_root=self.root,
            repository=HARNESS_REPOSITORY,
            issue_number=36,
            source_payload_sha256=self.sources[36],
            accepted_main_sha=MAIN,
            worker_role="development",
            worker_endpoint_id=str(development["endpoint_id"]),
            now=NOW,
            suffix="complete-harness-source-lane",
        )
        self.assertEqual("READY", ready["item"]["status"])

        convergence = PortfolioConvergence(
            self.store, canonical_main_reader=lambda _repository: MAIN
        )
        results = convergence.consume_due(
            limit=10, now="2026-08-27T06:01:00Z", repository=HARNESS_REPOSITORY
        )
        admitted = [result for result in results if result.get("outcome") == "ADMITTED"]
        self.assertEqual(1, len(admitted), results)
        message_id = int(admitted[0]["message_id"])
        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=36",
            (HARNESS_REPOSITORY,),
        ).fetchone()
        watch = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE repository=? AND issue_number=36",
            (HARNESS_REPOSITORY,),
        ).fetchone()
        self.assertEqual(("ACTIVE", "ACTIVE", 0, 1, 0), (
            item["status"], item["allocation_class"], item["development_units"],
            item["shared_units"], item["sre_units"],
        ))
        self.assertEqual("PENDING_CLAIM", watch["state"])

        reserved, token = reserve_attempt(
            self.store.connection,
            role="development",
            endpoint_id=str(development["endpoint_id"]),
            target_kind="message",
            target_key=str(message_id),
            now="2026-08-27T06:01:01Z",
            precondition=lambda connection: attempt_lineage_for_target(
                connection, "message", str(message_id)
            ),
        )
        unit = stable_systemd_unit("development", "message", str(message_id))
        launching = transition_attempt(
            self.store.connection,
            attempt_id=str(reserved["attempt_id"]),
            token=token,
            expected_version=int(reserved["version"]),
            new_state="LAUNCHING",
            systemd_unit=unit,
            systemd_invocation_id=hashlib.md5(unit.encode()).hexdigest(),
            systemd_control_group=f"/user.slice/{unit}",
            now="2026-08-27T06:01:02Z",
        )
        running = transition_attempt(
            self.store.connection,
            attempt_id=str(reserved["attempt_id"]),
            token=token,
            expected_version=int(launching["version"]),
            new_state="RUNNING",
            process_id=3600,
            now="2026-08-27T06:01:03Z",
        )
        self.store.claim_message(
            message_id,
            str(development["endpoint_id"]),
            "2026-08-27T06:01:04Z",
            attempt_id=str(running["attempt_id"]),
            executor_token=token,
        )
        watch = self.store.connection.execute(
            "SELECT * FROM coordination_terminal_watches WHERE repository=? AND issue_number=36",
            (HARNESS_REPOSITORY,),
        ).fetchone()
        self.assertEqual("ACTIVE", watch["state"])

        item = self.store.connection.execute(
            "SELECT * FROM coordination_items WHERE repository=? AND issue_number=36",
            (HARNESS_REPOSITORY,),
        ).fetchone()
        lease = str(item["lease_manifest_sha256"])
        closeout_key = (
            f"terminal-closeout:{HARNESS_REPOSITORY}:issue:36:generation:1"
        )
        receipt = {
            "schema": "twinfinity-terminal-receipt/v1",
            "repository": HARNESS_REPOSITORY,
            "issue_number": 36,
            "generation": 1,
            "source_payload_sha256": self.sources[36],
            "lease_manifest_sha256": lease,
            "outcome": "ACCEPTED",
            "accepted_head_sha": MAIN,
            "operational_state_sha256": None,
            "acceptance_evidence_sha256": "d" * 64,
            "residual_risks": ["Source completion does not install or activate bytes."],
        }
        cleanup = {
            "schema": "twinfinity-terminal-cleanup/v1",
            "repository": HARNESS_REPOSITORY,
            "issue_number": 36,
            "generation": 1,
            "lease_manifest_sha256": lease,
            "owned_resources_absent": True,
            "temporary_resources_absent": True,
            "worktree_disposition": "ABSENT",
            "local_branch_disposition": "ABSENT",
            "remote_branch_disposition": "ABSENT",
            "residuals": [],
        }
        prepared = self.store.prepare_terminal_closeout(
            packet={
                "schema": "twinfinity-terminal-closeout-packet/v1",
                "repository": HARNESS_REPOSITORY,
                "issue_number": 36,
                "generation": 1,
                "expected_item_version": int(item["version"]),
                "source_payload_sha256": self.sources[36],
                "lease_manifest_sha256": lease,
                "terminal_watch_key": (
                    f"terminal:{HARNESS_REPOSITORY}:issue:36:generation:1"
                ),
                "activation_message_id": message_id,
                "terminal_receipt": receipt,
                "cleanup_evidence": cleanup,
                "outbox": {
                    "idempotency_key": closeout_key,
                    "body": terminal_publication_body(
                        closeout_key=closeout_key,
                        terminal_receipt=receipt,
                        cleanup_evidence=cleanup,
                    ),
                },
            },
            attempt_id=str(running["attempt_id"]),
            executor_token=token,
            now="2026-08-27T06:02:00Z",
        )
        pending = self.store.connection.execute(
            "SELECT status,allocation_class,shared_units FROM coordination_items "
            "WHERE repository=? AND issue_number=36",
            (HARNESS_REPOSITORY,),
        ).fetchone()
        self.assertEqual(("PUBLICATION_PENDING", "ACTIVE", 1), tuple(pending))
        self.store.bind_terminal_outbox_publisher(
            outbox_id=int(prepared["outbox_id"]),
            publisher_login="twinfinity-bot",
            now="2026-08-27T06:02:01Z",
        )
        self.store.reserve_outbox(
            int(prepared["outbox_id"]), "2026-08-27T06:02:02Z"
        )
        outbox = self.store.connection.execute(
            "SELECT idempotency_key,payload_json FROM github_outbox WHERE id=?",
            (prepared["outbox_id"],),
        ).fetchone()
        body = json.loads(outbox["payload_json"])["body"]
        published_body = terminal_published_body(body, outbox["idempotency_key"])
        comment = {
            "id": 3600,
            "event": "commented",
            "body": published_body,
            "created_at": "2026-08-27T06:02:03Z",
            "updated_at": "2026-08-27T06:02:03Z",
            "issue_url": (
                f"https://api.github.com/repos/{HARNESS_REPOSITORY}/issues/36"
            ),
            "user": {"login": "twinfinity-bot"},
        }
        self.store.complete_terminal_outbox_from_readback(
            outbox_id=int(prepared["outbox_id"]),
            remote_receipt="comment:3600",
            published_body=published_body,
            publisher_login="twinfinity-bot",
            now="2026-08-27T06:02:03Z",
        )
        issue_payload = self.store.current_snapshot(
            HARNESS_REPOSITORY, "issue", 36
        ).payload
        with patch.object(
            coordination_store_module,
            "_fetch_terminal_live_observation",
            return_value=(
                issue_payload,
                {"ref": "refs/heads/main", "object": {"sha": MAIN}},
                comment,
                [comment],
            ),
        ):
            committed = self.store.commit_terminal_closeout(
                closeout_key=closeout_key,
                attempt_id=str(running["attempt_id"]),
                executor_token=token,
            )
        self.assertEqual("COMPLETE", committed["state"])
        transition_attempt(
            self.store.connection,
            attempt_id=str(running["attempt_id"]),
            token=token,
            expected_version=int(running["version"]),
            new_state="COMPLETE",
            exit_code=0,
            now="2026-08-27T06:02:04Z",
        )
        item = self.store.connection.execute(
            "SELECT status,allocation_class,shared_units "
            "FROM coordination_items WHERE repository=? AND issue_number=36",
            (HARNESS_REPOSITORY,),
        ).fetchone()
        attempt = self.store.connection.execute(
            "SELECT state FROM executor_attempts WHERE attempt_id=?",
            (str(running["attempt_id"]),),
        ).fetchone()
        self.assertEqual("DONE", item["status"])
        self.assertEqual("NONE", item["allocation_class"])
        self.assertEqual(0, item["shared_units"])
        self.assertEqual("COMPLETE", attempt["state"])
        message = self.store.connection.execute(
            "SELECT state FROM coordination_messages WHERE id=?", (message_id,)
        ).fetchone()
        watch = self.store.connection.execute(
            "SELECT state FROM coordination_terminal_watches WHERE repository=? AND issue_number=36",
            (HARNESS_REPOSITORY,),
        ).fetchone()
        self.assertEqual("COMPLETE", message["state"])
        self.assertEqual("COMPLETE", watch["state"])


if __name__ == "__main__":
    unittest.main()
