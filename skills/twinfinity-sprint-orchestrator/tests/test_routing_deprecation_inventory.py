from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from archive_readiness_audit import archive_readiness  # noqa: E402
from coordination_store import (  # noqa: E402
    CoordinationError,
    CoordinationStore,
    descriptor_file_sha256,
)
from executor_registry import (  # noqa: E402
    ensure_executor_registry_schema,
    load_registry_config,
)
from reconcile_routing_artifacts import (  # noqa: E402
    _verify_or_insert_endpoint,
    apply_plan,
    audit_plan,
    build_plan,
    load_legacy_alias_fixture,
)
from routing_deprecation_inventory import (  # noqa: E402
    InventoryError,
    build_inventory_candidate,
    classify_occurrence,
    load_alias_artifact,
    prepare_inventory,
    published_receipt_body,
    scan_repository,
    stable_scan_repository,
)


REPOSITORY = "twinfinityai/twinfinityapp"
CONFIG = ROOT / "references" / "twinfinity-executor-registry.toml"
ALIASES = ROOT / "tests" / "fixtures" / "legacy-role-aliases.json"
UPDATED = "2026-08-24T09:00:00Z"


def node(kind: str, number: int, body: str = "") -> dict:
    return {
        "__typename": "Issue" if kind == "issue" else "PullRequest",
        "id": f"{kind}:{number}",
        "number": number,
        "body": body,
        "updatedAt": UPDATED,
    }


def page(total: int, nodes: list[dict], has_next: bool, cursor=None) -> dict:
    return {
        "totalCount": total,
        "nodes": nodes,
        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
    }


class StaticReader:
    def __init__(self, issues: list[dict], pulls: list[dict] | None = None):
        self.values = {"issue": issues, "pull_request": pulls or []}

    def __call__(self, kind: str, cursor: str | None) -> dict:
        self.assert_cursor(cursor)
        values = self.values[kind]
        return page(len(values), copy.deepcopy(values), False)

    @staticmethod
    def assert_cursor(cursor: str | None) -> None:
        if cursor is not None:
            raise AssertionError(f"unexpected cursor {cursor}")


class RoutingInventoryScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.aliases = load_alias_artifact(ALIASES).aliases
        self.alias = sorted(self.aliases)[0]

    def test_paginates_over_100_and_exact_multiple(self) -> None:
        for total in (101, 200):
            values = [node("issue", number) for number in range(1, total + 1)]

            def reader(kind, cursor, values=values):
                if kind == "pull_request":
                    return page(0, [], False)
                offset = 0 if cursor is None else int(cursor)
                batch = values[offset : offset + 100]
                next_offset = offset + len(batch)
                return page(
                    total,
                    copy.deepcopy(batch),
                    next_offset < total,
                    str(next_offset) if next_offset < total else None,
                )

            result = scan_repository(REPOSITORY, self.aliases, reader)
            self.assertEqual(total, len(result["object_manifest"]))

    def test_rejects_repeated_cursor_count_mismatch_and_duplicate(self) -> None:
        cases = []

        def repeated(kind, cursor):
            if kind == "pull_request":
                return page(0, [], False)
            number = 1 if cursor is None else 2
            return page(3, [node("issue", number)], True, "same")

        cases.append((repeated, "CURSOR_INVALID"))

        def count_mismatch(kind, cursor):
            if kind == "pull_request":
                return page(0, [], False)
            return page(2, [node("issue", 1)], False)

        cases.append((count_mismatch, "COUNT_MISMATCH"))

        duplicate_nodes = [node("issue", 1), node("issue", 1)]
        cases.append(
            (
                lambda kind, cursor: page(
                    2 if kind == "issue" else 0,
                    copy.deepcopy(duplicate_nodes) if kind == "issue" else [],
                    False,
                ),
                "DUPLICATE_OBJECT",
            )
        )
        for reader, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(
                InventoryError, error
            ):
                scan_repository(REPOSITORY, self.aliases, reader)

    def test_rejects_total_count_drift_across_pages(self) -> None:
        def reader(kind, cursor):
            if kind == "pull_request":
                return page(0, [], False)
            if cursor is None:
                return page(2, [node("issue", 1)], True, "next")
            return page(3, [node("issue", 2)], False)

        with self.assertRaisesRegex(InventoryError, "COUNT_DRIFT"):
            scan_repository(REPOSITORY, self.aliases, reader)

    def test_two_complete_scans_must_be_identical(self) -> None:
        issue_calls = 0

        def reader(kind, cursor):
            nonlocal issue_calls
            if kind == "pull_request":
                return page(0, [], False)
            issue_calls += 1
            body = "first" if issue_calls == 1 else "second"
            return page(1, [node("issue", 179, body)], False)

        with self.assertRaisesRegex(InventoryError, "SCAN_DRIFT"):
            stable_scan_repository(REPOSITORY, self.aliases, reader)

    def test_unicode_byte_offsets_classes_and_independent_tags(self) -> None:
        aliases = sorted(self.aliases)
        body = "\n\n".join(
            (
                f"é Scope HOLD approval dependency acceptance route {aliases[0]}",
                f"Current endpoint receiver is {aliases[1]}",
                f"Historical provenance; never route work to {aliases[2]}",
                f"Unrelated token {aliases[0]}",
            )
        )
        result = scan_repository(
            REPOSITORY,
            self.aliases,
            StaticReader([node("issue", 179, body)]),
        )
        occurrences = result["occurrences"]
        self.assertEqual(
            [
                "EXECUTABLE_ROUTE",
                "AMBIGUOUS_REFERENCE",
                "HISTORICAL_PROVENANCE",
                "AMBIGUOUS_REFERENCE",
            ],
            [item["classification"] for item in occurrences],
        )
        self.assertEqual(
            ["ACCEPTANCE", "APPROVAL", "DEPENDENCY", "HOLD", "SCOPE"],
            occurrences[0]["semantic_tags"],
        )
        expected_char = body.index(aliases[0])
        self.assertEqual(len(body[:expected_char].encode("utf-8")), occurrences[0]["byte_start"])
        self.assertEqual(
            len(body[: body.index(aliases[0])].split("\n")[-1].encode("utf-8")) + 1,
            occurrences[0]["byte_column"],
        )

    def test_multi_sentence_mixed_polarity_in_first_paragraph_is_ambiguous(self) -> None:
        body = (
            f"Never route work to {self.alias}. "
            f"Resume the active delivery through {self.alias}."
        )
        starts = [match.start() for match in re.finditer(re.escape(self.alias), body)]
        self.assertEqual(
            ["AMBIGUOUS_REFERENCE", "AMBIGUOUS_REFERENCE"],
            [classify_occurrence(body, start) for start in starts],
        )

    def test_mixed_polarity_with_multiple_aliases_is_ambiguous_for_each(self) -> None:
        aliases = sorted(self.aliases)[:3]
        body = (
            f"Do not dispatch to {aliases[0]} or {aliases[1]}. "
            f"Instead send the bounded attempt to {aliases[2]}."
        )
        result = scan_repository(
            REPOSITORY,
            self.aliases,
            StaticReader([node("issue", 179, body)]),
        )
        self.assertEqual(
            ["AMBIGUOUS_REFERENCE"] * 3,
            [item["classification"] for item in result["occurrences"]],
        )

    def test_clear_negative_only_provenance_remains_historical(self) -> None:
        bodies = (
            f"Historical provenance only; never route work to {self.alias}.",
            f"Immutable provenance: work must never be assigned to {self.alias}.",
        )
        for body in bodies:
            with self.subTest(body=body):
                self.assertEqual(
                    "HISTORICAL_PROVENANCE",
                    classify_occurrence(body, body.index(self.alias)),
                )

    def test_unlisted_continuation_language_fails_closed(self) -> None:
        bodies = (
            f"The next bounded delivery belongs with {self.alias}.",
            f"Worker ownership ought to move toward {self.alias}.",
            f"Keep {self.alias} in charge of the pending job.",
            f"The active lease points at {self.alias}.",
        )
        for body in bodies:
            with self.subTest(body=body):
                self.assertEqual(
                    "AMBIGUOUS_REFERENCE",
                    classify_occurrence(body, body.index(self.alias)),
                )

    def test_historical_words_do_not_sanitize_actionable_or_unclear_text(self) -> None:
        bodies = (
            f"Historical record: the next attempt belongs with {self.alias}.",
            f"Legacy provenance mentions {self.alias}; it should own pending work.",
            f"Archived note for {self.alias}, with delivery status still pending.",
        )
        for body in bodies:
            with self.subTest(body=body):
                self.assertEqual(
                    "AMBIGUOUS_REFERENCE",
                    classify_occurrence(body, body.index(self.alias)),
                )

    def test_explicit_inert_routing_literal_is_reference(self) -> None:
        body = f"The recorded recipient identifier string value is {self.alias}."
        self.assertEqual(
            "ROUTING_REFERENCE",
            classify_occurrence(body, body.index(self.alias)),
        )

    def test_digest_is_deterministic_for_equivalent_object_order(self) -> None:
        values = [node("issue", 179, f"Historical {self.alias}"), node("issue", 2)]
        first = scan_repository(REPOSITORY, self.aliases, StaticReader(values))
        second = scan_repository(REPOSITORY, self.aliases, StaticReader(list(reversed(values))))
        self.assertEqual(first, second)


class RoutingInventoryStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        fixture_root = Path(self.temp.name) / "canonical-operational-inputs"
        fixture_root.mkdir()
        planner_goal = fixture_root / "product-planner-goal.md"
        planner_goal.write_text(
            "Use only current role endpoints.\n",
            encoding="utf-8",
        )
        agents = fixture_root / "AGENTS.md"
        agents.write_text(
            "Current role endpoints are the only executable routing inputs.\n",
            encoding="utf-8",
        )
        self.enterContext(
            patch(
                "archive_readiness_audit.CANONICAL_PLANNER_GOAL",
                planner_goal,
            )
        )
        self.enterContext(
            patch("archive_readiness_audit.CANONICAL_AGENTS", agents)
        )
        directory = Path(self.temp.name) / "coordination"
        directory.mkdir(mode=0o700)
        self.store = CoordinationStore(directory / "state.sqlite3")
        config = load_registry_config(CONFIG)
        aliases, alias_sha = load_legacy_alias_fixture(ALIASES)
        ensure_executor_registry_schema(self.store.connection)
        for role, endpoint in config.roles.items():
            _verify_or_insert_endpoint(
                self.store.connection, endpoint.payload, UPDATED
            )
            self.store.connection.execute(
                """
                INSERT INTO executor_role_endpoint_current(
                    role, endpoint_id, pointer_version, updated_at
                ) VALUES (?, ?, 1, ?)
                """,
                (role, endpoint.endpoint_id, UPDATED),
            )
        plan_value = build_plan(
            self.store.connection, config, aliases, alias_fixture_sha256=alias_sha
        )
        apply_plan(
            self.store.connection,
            plan=plan_value,
            operation_key="routing-inventory-test-migration",
            expected_plan_sha256=plan_value["plan_sha256"],
            now="2026-08-24T09:00:00Z",
        )
        self.alias = sorted(load_alias_artifact(ALIASES).aliases)[0]
        self.body = f"Historical provenance only; never route work to {self.alias}"
        self.source = self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=179,
            payload={"number": 179, "body": self.body, "updated_at": UPDATED},
            source_updated_at=UPDATED,
            fetched_at="2026-08-24T09:00:01Z",
        )
        self.reader = StaticReader([node("issue", 179, self.body)])

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def candidate(self):
        return build_inventory_candidate(
            self.store.connection,
            repository=REPOSITORY,
            alias_artifact=load_alias_artifact(ALIASES),
            page_reader=self.reader,
        )

    def prepare(self):
        inventory, _ = self.candidate()
        prepared, outbox_id = prepare_inventory(
            self.store,
            repository=REPOSITORY,
            alias_path=ALIASES,
            page_reader=self.reader,
            expected_inventory_sha256=inventory["inventory_sha256"],
            expected_endpoint_state_sha256=inventory["endpoint_state_sha256"],
            expected_issue_179_source_sha256=inventory["issue_179_source_sha256"],
            now="2026-08-24T09:00:02Z",
        )
        return prepared, outbox_id

    def complete_outbox(self, outbox_id: int) -> None:
        self.store.reserve_outbox(outbox_id, "2026-08-24T09:00:03Z")
        self.store.complete_outbox(outbox_id, "comment:555", "2026-08-24T09:00:04Z")

    def comment(self, inventory: dict, *, issue: int = 179, body: str | None = None):
        return {
            "id": 555,
            "body": published_receipt_body(inventory) if body is None else body,
            "issue_url": f"https://api.github.com/repos/{REPOSITORY}/issues/{issue}",
        }

    def readiness(self, inventory: dict, reader=None, comment=None, alias_path=ALIASES):
        return archive_readiness(
            self.store.connection,
            legacy_alias_path=alias_path,
            routing_page_reader=reader or self.reader,
            routing_comment_reader=comment or (
                lambda repository, issue, comment_id: self.comment(inventory)
            ),
        )

    def test_prepare_is_atomic_replayable_conflict_fenced_and_immutable(self) -> None:
        inventory, outbox_id = self.prepare()
        replay, replay_outbox = self.prepare()
        self.assertEqual(inventory["inventory_sha256"], replay["inventory_sha256"])
        self.assertEqual(outbox_id, replay_outbox)
        self.assertEqual(
            (1, 1),
            (
                self.store.connection.execute(
                    "SELECT COUNT(*) FROM routing_deprecation_inventories"
                ).fetchone()[0],
                self.store.connection.execute(
                    "SELECT COUNT(*) FROM github_outbox"
                ).fetchone()[0],
            ),
        )
        candidate, occurrences = self.candidate()
        with self.assertRaisesRegex(CoordinationError, "INVENTORY_CONFLICT"):
            self.store.prepare_routing_deprecation_inventory(
                inventory=candidate,
                occurrences=occurrences,
                alias_source_path=ALIASES,
                outbox_idempotency_key="changed-key",
                receipt_body="changed",
                now="2026-08-24T09:00:05Z",
            )
        for statement in (
            "UPDATE routing_deprecation_inventories SET object_count=9",
            "DELETE FROM routing_deprecation_inventories",
            "UPDATE routing_deprecation_occurrences SET line_number=9",
            "DELETE FROM routing_deprecation_occurrences",
        ):
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                self.store.connection.execute(statement)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
                """
                INSERT INTO routing_deprecation_occurrences(
                    inventory_sha256,ordinal,object_kind,object_number,node_id,
                    object_updated_at,body_sha256,alias,byte_start,byte_end,
                    line_number,byte_column,classification,semantic_tags_json
                )
                SELECT inventory_sha256,99,object_kind,object_number,node_id,
                       object_updated_at,body_sha256,alias,9999,10000,
                       line_number,byte_column,classification,semantic_tags_json
                FROM routing_deprecation_occurrences LIMIT 1
                """
            )

    def test_internal_failure_rolls_back_outbox_inventory_and_occurrences(self) -> None:
        inventory, occurrences = self.candidate()
        with patch.object(self.store, "_event", side_effect=RuntimeError("fault")):
            with self.assertRaisesRegex(RuntimeError, "fault"):
                self.store.prepare_routing_deprecation_inventory(
                    inventory=inventory,
                    occurrences=occurrences,
                    alias_source_path=ALIASES,
                    outbox_idempotency_key="atomic-fault",
                    receipt_body="receipt",
                    now="2026-08-24T09:00:02Z",
                )
        for table in (
            "github_outbox",
            "routing_deprecation_inventories",
            "routing_deprecation_occurrences",
        ):
            self.assertEqual(
                0,
                self.store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
            )

    def test_scan_to_prepare_snapshot_drift_fails_atomically(self) -> None:
        inventory, _ = self.candidate()
        original = self.store.prepare_routing_deprecation_inventory

        def drift_then_prepare(**kwargs):
            self.store.ingest_snapshot(
                repository=REPOSITORY,
                object_kind="issue",
                object_number=179,
                payload={"number": 179, "body": "changed", "updated_at": UPDATED},
                source_updated_at="2026-08-24T09:01:00Z",
                fetched_at="2026-08-24T09:01:01Z",
            )
            return original(**kwargs)

        with patch.object(
            self.store,
            "prepare_routing_deprecation_inventory",
            side_effect=drift_then_prepare,
        ):
            with self.assertRaisesRegex(CoordinationError, "PREPARE_DRIFT"):
                prepare_inventory(
                    self.store,
                    repository=REPOSITORY,
                    alias_path=ALIASES,
                    page_reader=self.reader,
                    expected_inventory_sha256=inventory["inventory_sha256"],
                    expected_endpoint_state_sha256=inventory["endpoint_state_sha256"],
                    expected_issue_179_source_sha256=inventory[
                        "issue_179_source_sha256"
                    ],
                    now="2026-08-24T09:00:02Z",
                )
        self.assertEqual(
            (0, 0),
            (
                self.store.connection.execute(
                    "SELECT COUNT(*) FROM routing_deprecation_inventories"
                ).fetchone()[0],
                self.store.connection.execute(
                    "SELECT COUNT(*) FROM github_outbox"
                ).fetchone()[0],
            ),
        )

    def test_descriptor_hash_rejects_in_place_metadata_drift(self) -> None:
        before = ALIASES.stat()
        after = types.SimpleNamespace(
            st_dev=before.st_dev,
            st_ino=before.st_ino,
            st_size=before.st_size + 1,
            st_mtime_ns=before.st_mtime_ns + 1,
            st_ctime_ns=before.st_ctime_ns + 1,
        )
        with patch("coordination_store.os.fstat", side_effect=[before, after]):
            with self.assertRaisesRegex(CoordinationError, "ARTIFACT_DRIFT"):
                descriptor_file_sha256(ALIASES)

    def test_archive_requires_exact_receipt_and_stable_unchanged_occurrences(self) -> None:
        inventory, outbox_id = self.prepare()
        self.complete_outbox(outbox_id)
        self.assertEqual("PASS", self.readiness(inventory)["phase"])

        missing = self.readiness(
            inventory,
            comment=lambda repository, issue, comment_id: (_ for _ in ()).throw(
                InventoryError("missing")
            ),
        )
        self.assertEqual("HOLD", missing["phase"])
        edited = self.readiness(
            inventory,
            comment=lambda repository, issue, comment_id: self.comment(
                inventory, body="edited"
            ),
        )
        self.assertEqual("HOLD", edited["phase"])
        wrong_issue = self.readiness(
            inventory,
            comment=lambda repository, issue, comment_id: self.comment(
                inventory, issue=178
            ),
        )
        self.assertEqual("HOLD", wrong_issue["phase"])

        changed_body = self.body + f"\nHistorical provenance {self.alias}"
        drifted = self.readiness(
            inventory,
            reader=StaticReader([node("issue", 179, changed_body)]),
        )
        self.assertEqual("HOLD", drifted["phase"])
        self.assertTrue(
            any(
                item.get("error") == "ROUTING_DEPRECATION_OCCURRENCE_DRIFT"
                for item in drifted["gates"]["routing_deprecation_inventory"]
            )
        )

    def test_receipt_comment_timestamp_change_does_not_invalidate_overlay(self) -> None:
        inventory, outbox_id = self.prepare()
        self.complete_outbox(outbox_id)
        later = node("issue", 179, self.body)
        later["updatedAt"] = "2026-08-24T09:02:00Z"

        readiness = self.readiness(inventory, reader=StaticReader([later]))

        self.assertEqual("PASS", readiness["phase"])

    def test_exact_overlay_retires_ambiguous_and_executable_occurrences(self) -> None:
        self.body = (
            f"Never route work to {self.alias}. Resume work through {self.alias}."
            f"\n\nRoute work to {self.alias}."
        )
        mixed_updated = "2026-08-24T09:01:00Z"
        self.store.ingest_snapshot(
            repository=REPOSITORY,
            object_kind="issue",
            object_number=179,
            payload={"number": 179, "body": self.body, "updated_at": mixed_updated},
            source_updated_at=mixed_updated,
            fetched_at="2026-08-24T09:01:01Z",
        )
        mixed_node = node("issue", 179, self.body)
        mixed_node["updatedAt"] = mixed_updated
        self.reader = StaticReader([mixed_node])
        inventory, outbox_id = self.prepare()
        self.assertEqual(2, inventory["classification_counts"]["AMBIGUOUS_REFERENCE"])
        self.assertEqual(1, inventory["classification_counts"]["EXECUTABLE_ROUTE"])
        self.complete_outbox(outbox_id)

        readiness = self.readiness(inventory)

        self.assertEqual("PASS", readiness["phase"])

    def test_archive_fails_on_endpoint_and_alias_drift(self) -> None:
        inventory, outbox_id = self.prepare()
        self.complete_outbox(outbox_id)
        self.store.connection.execute(
            "UPDATE executor_role_endpoint_current "
            "SET pointer_version=pointer_version+1 WHERE role='development'"
        )
        endpoint = self.readiness(inventory)
        self.assertEqual("HOLD", endpoint["phase"])

        self.store.connection.execute(
            "UPDATE executor_role_endpoint_current "
            "SET pointer_version=pointer_version-1 WHERE role='development'"
        )
        changed_alias = Path(self.temp.name) / "aliases.json"
        payload = json.loads(ALIASES.read_text(encoding="utf-8"))
        payload["aliases"][0]["alias"] = "11111111-1111-4111-8111-111111111111"
        changed_alias.write_text(json.dumps(payload), encoding="utf-8")
        alias = self.readiness(inventory, alias_path=changed_alias)
        self.assertEqual("HOLD", alias["phase"])

    def test_reconciliation_emits_only_digest_hints_and_no_mutation(self) -> None:
        config = load_registry_config(CONFIG)
        aliases, alias_sha = load_legacy_alias_fixture(ALIASES)
        plan_value = build_plan(
            self.store.connection, config, aliases, alias_fixture_sha256=alias_sha
        )
        serialized = json.dumps(plan_value, sort_keys=True)
        self.assertIn("github_routing_inventory_hints", plan_value)
        self.assertNotIn("desired_body", serialized)
        self.assertNotIn("transport_requirement", serialized)
        self.assertFalse(plan_value["github_mutation_performed"])
        self.assertIn(
            "ROUTING_DEPRECATION_INVENTORY_REQUIRED", audit_plan(plan_value)["blockers"]
        )


if __name__ == "__main__":
    unittest.main()
