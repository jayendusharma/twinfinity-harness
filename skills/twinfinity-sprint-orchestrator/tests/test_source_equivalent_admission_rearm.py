from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from admission_source_equivalence import admission_lineage_source_is_current  # noqa: E402
from coordination_store import CoordinationError, CoordinationStore, canonical_json, digest_json  # noqa: E402
from executor_registry import attempt_lineage_for_target, load_registry_config, reserve_attempt, stable_systemd_unit, transition_attempt  # noqa: E402
from portfolio_graph import graph_allows_admission_source_pair, replace_graph  # noqa: E402
from reconcile_routing_artifacts import apply_plan, build_plan, load_legacy_alias_fixture  # noqa: E402
from coordination_supervisor import CoordinationSupervisor  # noqa: E402
from tests.canonical_ready_fixture import finalize_canonical_ready_item  # noqa: E402


REPOSITORY = "twinfinityai/twinfinityapp"
ISSUE = 272
GENERATION = 0
LEASE = "6" * 64
ENDPOINT = "role.development.v6"
OWNER = "jayendusharma"


class SourceEquivalentAdmissionRearmTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        coordination = root / "coordination"; coordination.mkdir(mode=0o700)
        self.store = CoordinationStore(coordination / "state.sqlite3")
        installed = root / "installed"; installed.mkdir()
        references = ROOT / "references"
        for profile in references.glob("*-v*.config.toml"):
            shutil.copy2(profile, installed / profile.name)
        config = load_registry_config(
            references / "twinfinity-executor-registry.toml",
            codex_home=installed, profile_template_root=references,
        )
        aliases, alias_sha = load_legacy_alias_fixture(references / "twinfinity-legacy-role-aliases.json")
        plan = build_plan(self.store.connection, config, aliases, alias_fixture_sha256=alias_sha)
        apply_plan(self.store.connection, plan=plan, operation_key="issue-34-v6", expected_plan_sha256=plan["plan_sha256"], now="2026-08-26T20:00:00Z")

        self.bound_payload = {
            "number": ISSUE, "title": "Bound scope", "body": "Exact body",
            "state": "OPEN", "labels": ["bug"], "milestone": None,
            "assignees": [], "updated_at": "2026-08-26T20:00:01Z",
            "_projection_version": 1,
        }
        bound = self.store.ingest_snapshot(
            repository=REPOSITORY, object_kind="issue", object_number=ISSUE,
            payload=self.bound_payload, source_updated_at=self.bound_payload["updated_at"],
            fetched_at="2026-08-26T20:00:02Z",
        )
        self.bound_sha = bound.payload_sha256
        self.store.set_issue_status(
            repository=REPOSITORY, issue_number=ISSUE, status="PREPARED", allocation_class="NONE",
            generation=GENERATION, accountable_session_id=None, lease_manifest_sha256=None,
            development_units=1, shared_units=1, sre_units=0, expected_source_sha256=self.bound_sha,
            expected_version=0, now="2026-08-26T20:00:03Z",
        )
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": "b" * 40,
                "expected_current_version": 0,
                "scope_milestones": [{"title": "Fixture", "rank": 1}],
                "excluded_issues": [],
                "nodes": [{
                    "node_key": f"issue:{ISSUE}", "issue_number": ISSUE,
                    "role": "DELIVERY", "root_kind": "STANDALONE",
                    "root_reason": "Bounded source-equivalence fixture",
                    "lane_key": "development", "lane_order": 0,
                    "dispatchable": True, "priority_rank": 1, "estimate_units": 1,
                    "development_units": 1, "shared_units": 1, "sre_units": 0,
                    "source_payload_sha256": self.bound_sha,
                    "ready_at": "2026-08-26T20:00:03Z",
                }],
                "relations": [],
            },
            now="2026-08-26T20:00:03Z",
        )
        ready = finalize_canonical_ready_item(
            self.store,
            database=self.store.path,
            artifact_root=self.store.path.parent,
            repository=REPOSITORY,
            issue_number=ISSUE,
            source_payload_sha256=self.bound_sha,
            accepted_main_sha="b" * 40,
            worker_role="development",
            worker_endpoint_id=ENDPOINT,
            now="2026-08-26T20:00:04Z",
            suffix="bounded",
        )
        transaction = ready["admission_transaction"]
        self.payload = transaction["message"]["payload"]
        _active, self.message_id = self.store.activate_admission(
            item=transaction["item"], message=transaction["message"],
            artifacts=transaction.get("artifacts"), now="2026-08-26T20:00:05Z",
        )
        self.watch_key = f"terminal:{REPOSITORY}:issue:{ISSUE}:generation:{GENERATION}"
        attempt, token = reserve_attempt(
            self.store.connection, role="development", endpoint_id=ENDPOINT,
            target_kind="message", target_key=str(self.message_id), now="2026-08-26T20:00:05Z",
            precondition=lambda connection: attempt_lineage_for_target(connection, "message", str(self.message_id)),
        )
        unit = stable_systemd_unit("development", "message", str(self.message_id))
        launching = transition_attempt(self.store.connection, attempt_id=attempt["attempt_id"], token=token, expected_version=attempt["version"], new_state="LAUNCHING", systemd_unit=unit, systemd_invocation_id="c"*32, systemd_control_group=f"/user.slice/{unit}", now="2026-08-26T20:00:05Z")
        running = transition_attempt(self.store.connection, attempt_id=attempt["attempt_id"], token=token, expected_version=launching["version"], new_state="RUNNING", process_id=272, now="2026-08-26T20:00:06Z")
        self.store.claim_message(self.message_id, ENDPOINT, "2026-08-26T20:00:07Z", attempt_id=attempt["attempt_id"], executor_token=token)
        transition_attempt(self.store.connection, attempt_id=attempt["attempt_id"], token=token, expected_version=running["version"], new_state="COMPLETE", exit_code=0, now="2026-08-26T20:00:08Z")
        self.attempt_id = attempt["attempt_id"]
        self.store.connection.commit()

        body = {"kind": "OWNER_CONTROL_COMMENT", "body": "receipt"}
        cursor = self.store.connection.execute(
            "INSERT INTO github_outbox(idempotency_key,repository,object_kind,object_number,operation,expected_source_sha256,payload_sha256,payload_json,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("issue-272-owner-comment", REPOSITORY, "issue", ISSUE, "comment", self.bound_sha, digest_json(body), canonical_json(body), "PREPARED", "2026-08-26T20:00:09Z", "2026-08-26T20:00:09Z"),
        )
        self.outbox_id = int(cursor.lastrowid)
        self.store.connection.commit()
        self.store.reserve_outbox(self.outbox_id, "2026-08-26T20:00:10Z")
        self.store.complete_outbox(self.outbox_id, "comment:5430908495", "2026-08-26T20:00:11Z")
        self.current_at = "2026-08-26T20:00:12Z"
        current_payload = {**self.bound_payload, "updated_at": self.current_at, "_projection_version": 2, "_projection_dashboard": "changed"}
        current = self.store.ingest_snapshot(repository=REPOSITORY, object_kind="issue", object_number=ISSUE, payload=current_payload, source_updated_at=self.current_at, fetched_at="2026-08-26T20:00:13Z")
        self.current_sha = current.payload_sha256
        self.message_hold_at = "2026-08-26T20:00:14Z"; self.watch_hold_at = "2026-08-26T20:00:15Z"
        self.store.connection.execute("UPDATE coordination_messages SET state='HOLD',updated_at=?,last_error='SOURCE_SNAPSHOT_DRIFT' WHERE id=?", (self.message_hold_at, self.message_id))
        self.store.connection.execute("UPDATE coordination_terminal_watches SET state='HOLD',process_id=NULL,updated_at=?,last_error='TERMINAL_WATCH_ADMISSION_BINDING_DRIFT' WHERE watch_key=?", (self.watch_hold_at, self.watch_key))
        self.store.connection.commit()
        self.timeline = [{"event": "commented", "id": 5430908495, "created_at": self.current_at, "actor": {"login": OWNER}}]
        self.request = {
            "repository": REPOSITORY, "issue_number": ISSUE, "message_id": self.message_id,
            "expected_message_updated_at": self.message_hold_at, "watch_key": self.watch_key,
            "expected_watch_updated_at": self.watch_hold_at, "outbox_id": self.outbox_id,
            "timeline": self.timeline, "expected_owner_login": OWNER,
        }

    def _add_graph_issue(self, issue_number: int, *, retained: bool = False) -> str:
        payload = {
            "number": issue_number,
            "title": f"Graph fixture {issue_number}",
            "body": "Exact auxiliary graph fixture",
            "state": "OPEN",
            "labels": ["bug"],
            "milestone": None,
            "assignees": [],
            "updated_at": "2026-08-26T20:00:14Z",
            "_projection_version": 1,
        }
        snapshot = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=issue_number,
            payload=payload,
            source_updated_at=payload["updated_at"],
            fetched_at="2026-08-26T20:00:14Z",
        )
        if retained:
            self.store._set_issue_status_for_test_fixture(
                repository=REPOSITORY,
                issue_number=issue_number,
                status="HOLD",
                allocation_class="RETAINED",
                generation=0,
                accountable_session_id=ENDPOINT,
                lease_manifest_sha256="7" * 64,
                development_units=0,
                shared_units=1,
                sre_units=0,
                expected_source_sha256=snapshot.payload_sha256,
                expected_version=0,
                now="2026-08-26T20:00:14Z",
            )
        return snapshot.payload_sha256

    def _reconcile_graph_to_current_source(
        self,
        *,
        accepted_main_sha: str = "b" * 40,
        dispatchable: bool = True,
        relation_kind: str | None = None,
    ) -> None:
        nodes = [{
            "node_key": f"issue:{ISSUE}", "issue_number": ISSUE,
            "role": "DELIVERY", "root_kind": (
                "NORMAL" if relation_kind == "HARD_BLOCK" else "STANDALONE"
            ),
            "root_reason": (
                None
                if relation_kind == "HARD_BLOCK"
                else "Bounded source-equivalence fixture"
            ),
            "lane_key": "development", "lane_order": 0,
            "dispatchable": dispatchable, "priority_rank": 1,
            "estimate_units": 1, "development_units": 1,
            "shared_units": 1, "sre_units": 0,
            "source_payload_sha256": self.current_sha,
            "ready_at": "2026-08-26T20:00:03Z",
        }]
        relations = []
        if relation_kind is not None:
            other_issue = ISSUE - 1 if relation_kind == "HARD_BLOCK" else ISSUE + 1
            other_source = self._add_graph_issue(
                other_issue, retained=relation_kind == "COLLISION"
            )
            nodes.append({
                "node_key": f"issue:{other_issue}",
                "issue_number": other_issue,
                "role": "DELIVERY",
                "root_kind": (
                    "INTENTIONAL" if relation_kind == "HARD_BLOCK" else "STANDALONE"
                ),
                "root_reason": (
                    "Required predecessor fixture"
                    if relation_kind == "HARD_BLOCK"
                    else "Active collision fixture"
                ),
                "lane_key": "other",
                "lane_order": 0,
                "dispatchable": True,
                "priority_rank": 2,
                "estimate_units": 1,
                "development_units": 0,
                "shared_units": 1,
                "sre_units": 0,
                "source_payload_sha256": other_source,
                "ready_at": "2026-08-26T20:00:03Z",
            })
            relations.append({
                "left_node_key": (
                    f"issue:{other_issue}"
                    if relation_kind == "HARD_BLOCK"
                    else f"issue:{ISSUE}"
                ),
                "right_node_key": (
                    f"issue:{ISSUE}"
                    if relation_kind == "HARD_BLOCK"
                    else f"issue:{other_issue}"
                ),
                "relation_kind": relation_kind,
                "reason": f"Material {relation_kind.lower()} replacement",
                "source_payload_sha256": other_source,
            })
        replace_graph(
            self.store.connection,
            {
                "repository": REPOSITORY,
                "accepted_main_sha": accepted_main_sha,
                "expected_current_version": 1,
                "scope_milestones": [{"title": "Fixture", "rank": 1}],
                "excluded_issues": [],
                "nodes": nodes,
                "relations": relations,
            },
            now="2026-08-26T20:00:15Z",
        )

    def _assert_graph_drift_is_zero_write(self) -> None:
        before = list(self.store.connection.iterdump())
        with self.assertRaisesRegex(
            CoordinationError, "SOURCE_EQUIVALENCE_GRAPH_DRIFT"
        ):
            self.store.preview_source_equivalent_admission_rearm(**self.request)
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def tearDown(self) -> None:
        self.store.close(); self.temp.cleanup()

    def test_atomic_rearm_replay_and_exact_lineage_acceptance(self) -> None:
        item_before = dict(self.store.connection.execute("SELECT * FROM coordination_items").fetchone())
        preview = self.store.preview_source_equivalent_admission_rearm(**self.request)
        receipt = self.store.apply_source_equivalent_admission_rearm(**self.request, expected_preview_sha256=preview["preview_sha256"], now="2026-08-26T20:00:16Z")
        replay = self.store.apply_source_equivalent_admission_rearm(**self.request, expected_preview_sha256=preview["preview_sha256"], now="2026-08-26T20:00:17Z")
        self.assertEqual(receipt, replay)
        self.assertEqual(("CLAIMED", None), tuple(self.store.connection.execute("SELECT state,last_error FROM coordination_messages WHERE id=?", (self.message_id,)).fetchone()))
        self.assertEqual(("ACTIVE", None), tuple(self.store.connection.execute("SELECT state,last_error FROM coordination_terminal_watches WHERE watch_key=?", (self.watch_key,)).fetchone()))
        self.assertEqual(item_before, dict(self.store.connection.execute("SELECT * FROM coordination_items").fetchone()))
        item = self.store.connection.execute("SELECT * FROM coordination_items").fetchone()
        message = self.store.connection.execute("SELECT * FROM coordination_messages WHERE id=?", (self.message_id,)).fetchone()
        watch = self.store.connection.execute("SELECT * FROM coordination_terminal_watches WHERE watch_key=?", (self.watch_key,)).fetchone()
        self.assertTrue(admission_lineage_source_is_current(self.store.connection, item=item, message=message, watch=watch, current_source_sha256=self.current_sha))
        self.assertEqual(1, self.store.connection.execute("SELECT COUNT(*) FROM coordination_admission_source_equivalence").fetchone()[0])
        supervisor = CoordinationSupervisor(self.store, process_checker=lambda *_: False)
        self.assertEqual(1, len(supervisor._eligible_due_terminal_watch_lineages("2026-08-26T20:00:16Z")))

    def test_current_graph_reconciled_to_current_source_rearms_exact_pair(self) -> None:
        self._reconcile_graph_to_current_source()
        item_before = dict(self.store.connection.execute("SELECT * FROM coordination_items").fetchone())

        self.assertTrue(graph_allows_admission_source_pair(
            self.store.connection,
            repository=REPOSITORY,
            issue_number=ISSUE,
            bound_source_sha256=self.bound_sha,
            current_source_sha256=self.current_sha,
        ))

        preview = self.store.preview_source_equivalent_admission_rearm(**self.request)
        receipt = self.store.apply_source_equivalent_admission_rearm(
            **self.request,
            expected_preview_sha256=preview["preview_sha256"],
            now="2026-08-26T20:00:16Z",
        )
        replay = self.store.apply_source_equivalent_admission_rearm(
            **self.request,
            expected_preview_sha256=preview["preview_sha256"],
            now="2026-08-26T20:00:17Z",
        )

        self.assertEqual(receipt, replay)
        self.assertEqual(
            ("CLAIMED", None),
            tuple(self.store.connection.execute(
                "SELECT state,last_error FROM coordination_messages WHERE id=?",
                (self.message_id,),
            ).fetchone()),
        )
        self.assertEqual(
            ("ACTIVE", None),
            tuple(self.store.connection.execute(
                "SELECT state,last_error FROM coordination_terminal_watches WHERE watch_key=?",
                (self.watch_key,),
            ).fetchone()),
        )
        self.assertEqual(
            item_before,
            dict(self.store.connection.execute("SELECT * FROM coordination_items").fetchone()),
        )

    def test_current_graph_rejects_a_mixed_node_and_later_live_source(self) -> None:
        self._reconcile_graph_to_current_source()
        self._change_current(_projection_version=3, _projection_dashboard="later")
        before = list(self.store.connection.iterdump())

        with self.assertRaisesRegex(CoordinationError, "SOURCE_EQUIVALENCE_GRAPH_DRIFT"):
            self.store.preview_source_equivalent_admission_rearm(**self.request)

        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_current_graph_requires_the_exact_accepted_main(self) -> None:
        self._reconcile_graph_to_current_source()
        self.store.connection.execute(
            "UPDATE portfolio_graph_current SET observed_main_sha=? WHERE repository=?",
            ("a" * 40, REPOSITORY),
        )
        self.store.connection.commit()
        before = list(self.store.connection.iterdump())

        with self.assertRaisesRegex(CoordinationError, "SOURCE_EQUIVALENCE_GRAPH_DRIFT"):
            self.store.preview_source_equivalent_admission_rearm(**self.request)

        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_current_graph_cannot_manufacture_equivalence_provenance(self) -> None:
        self._reconcile_graph_to_current_source()
        self.request["expected_owner_login"] = "other"
        before = list(self.store.connection.iterdump())

        with self.assertRaisesRegex(CoordinationError, "SOURCE_EQUIVALENCE_PROVENANCE_INVALID"):
            self.store.preview_source_equivalent_admission_rearm(**self.request)

        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_current_graph_cannot_advance_the_admission_base(self) -> None:
        self._reconcile_graph_to_current_source(accepted_main_sha="c" * 40)
        self._assert_graph_drift_is_zero_write()

    def test_current_graph_cannot_add_an_unfinished_hard_predecessor(self) -> None:
        self._reconcile_graph_to_current_source(relation_kind="HARD_BLOCK")
        self._assert_graph_drift_is_zero_write()

    def test_current_graph_cannot_add_an_active_collision(self) -> None:
        self._reconcile_graph_to_current_source(relation_kind="COLLISION")
        self._assert_graph_drift_is_zero_write()

    def test_current_graph_cannot_disable_dispatchability(self) -> None:
        self._reconcile_graph_to_current_source(dispatchable=False)
        self._assert_graph_drift_is_zero_write()

    def test_later_projection_drift_invalidates_receipt_currentness(self) -> None:
        preview = self.store.preview_source_equivalent_admission_rearm(**self.request)
        self.store.apply_source_equivalent_admission_rearm(**self.request, expected_preview_sha256=preview["preview_sha256"], now="2026-08-26T20:00:16Z")
        payload = {**self.bound_payload, "updated_at": "2026-08-26T20:00:21Z", "_projection_version": 3}
        later = self.store.ingest_snapshot(repository=REPOSITORY, object_kind="issue", object_number=ISSUE, payload=payload, source_updated_at=payload["updated_at"], fetched_at="2026-08-26T20:00:22Z")
        item = self.store.connection.execute("SELECT * FROM coordination_items").fetchone()
        message = self.store.connection.execute("SELECT * FROM coordination_messages WHERE id=?", (self.message_id,)).fetchone()
        watch = self.store.connection.execute("SELECT * FROM coordination_terminal_watches WHERE watch_key=?", (self.watch_key,)).fetchone()
        self.assertFalse(admission_lineage_source_is_current(self.store.connection, item=item, message=message, watch=watch, current_source_sha256=later.payload_sha256))

    def test_material_drift_is_zero_write(self) -> None:
        self._change_current(body="material")
        before = list(self.store.connection.iterdump())
        with self.assertRaisesRegex(CoordinationError, "SOURCE_EQUIVALENCE_MATERIAL_DRIFT"):
            self.store.preview_source_equivalent_admission_rearm(**self.request)
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_wrong_owner_provenance_is_zero_write(self) -> None:
        self.request["expected_owner_login"] = "other"
        before = list(self.store.connection.iterdump())
        with self.assertRaisesRegex(CoordinationError, "SOURCE_EQUIVALENCE_PROVENANCE_INVALID"):
            self.store.preview_source_equivalent_admission_rearm(**self.request)
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def test_ambiguous_timeline_is_zero_write(self) -> None:
        self.request["timeline"].append(dict(self.timeline[0]))
        before = list(self.store.connection.iterdump())
        with self.assertRaisesRegex(CoordinationError, "SOURCE_EQUIVALENCE_INPUT_INVALID"):
            self.store.preview_source_equivalent_admission_rearm(**self.request)
        self.assertEqual(before, list(self.store.connection.iterdump()))

    def _change_current(self, **changes: object) -> None:
        payload = {**self.bound_payload, "updated_at": "2026-08-26T20:00:18Z", **changes}
        self.store.ingest_snapshot(repository=REPOSITORY, object_kind="issue", object_number=ISSUE, payload=payload, source_updated_at=payload["updated_at"], fetched_at="2026-08-26T20:00:19Z")

    def test_preview_cas_drift_rolls_back(self) -> None:
        preview = self.store.preview_source_equivalent_admission_rearm(**self.request)
        self.store.connection.execute("UPDATE coordination_terminal_watches SET updated_at='changed' WHERE watch_key=?", (self.watch_key,)); self.store.connection.commit()
        before = self.store.connection.execute("SELECT COUNT(*) FROM coordination_admission_source_equivalence").fetchone()[0]
        with self.assertRaisesRegex(CoordinationError, "SOURCE_EQUIVALENCE_STATE_MISMATCH"):
            self.store.apply_source_equivalent_admission_rearm(**self.request, expected_preview_sha256=preview["preview_sha256"], now="2026-08-26T20:00:20Z")
        self.assertEqual(before, self.store.connection.execute("SELECT COUNT(*) FROM coordination_admission_source_equivalence").fetchone()[0])

    def test_unrelated_graph_drift_holds_apply_with_zero_writes(self) -> None:
        preview = self.store.preview_source_equivalent_admission_rearm(**self.request)
        self.store.connection.execute(
            "UPDATE portfolio_graph_current SET last_error='GRAPH_SCOPE_INVENTORY_DRIFT' WHERE repository=?",
            (REPOSITORY,),
        )
        self.store.connection.commit()
        before = list(self.store.connection.iterdump())
        with self.assertRaisesRegex(CoordinationError, "SOURCE_EQUIVALENCE_GRAPH_DRIFT"):
            self.store.apply_source_equivalent_admission_rearm(
                **self.request, expected_preview_sha256=preview["preview_sha256"],
                now="2026-08-26T20:00:20Z",
            )
        self.assertEqual(before, list(self.store.connection.iterdump()))


if __name__ == "__main__":
    unittest.main()
