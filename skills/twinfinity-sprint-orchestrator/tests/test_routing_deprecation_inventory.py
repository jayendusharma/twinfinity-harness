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
    ROUTING_INVENTORIES_TABLE_SQL,
    ROUTING_OCCURRENCES_TABLE_SQL,
    _normalized_schema_sql,
    canonical_json,
    descriptor_file_sha256,
    digest_json,
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
    github_comment_reader,
    github_page_reader,
    load_alias_artifact,
    prepare_inventory,
    preview_inventory,
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
    def test_github_reader_rejects_graphql_errors_even_with_data(self) -> None:
        response = {"errors": [{"message": "partial"}], "data": {"repository": {"issues": page(0, [], False)}}}
        completed = types.SimpleNamespace(returncode=0, stdout=json.dumps(response))
        with patch("routing_deprecation_inventory.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(InventoryError, "GITHUB_INVENTORY_RESPONSE_INVALID"):
                github_page_reader(REPOSITORY)("issue", None)

    def test_github_comment_reader_requires_exact_issue_binding(self) -> None:
        completed = types.SimpleNamespace(returncode=0, stdout=json.dumps({
            "id": 555, "body": "receipt",
            "issue_url": f"https://api.github.com/repos/{REPOSITORY}/issues/180",
        }))
        with patch("routing_deprecation_inventory.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(InventoryError, "GITHUB_COMMENT_RESPONSE_INVALID"):
                github_comment_reader(REPOSITORY, 179, 555)

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
        preview = preview_inventory(
            self.store, repository=REPOSITORY, alias_path=ALIASES,
            page_reader=self.reader,
        )
        prepared, outbox_id = prepare_inventory(
            self.store,
            repository=REPOSITORY,
            alias_path=ALIASES,
            page_reader=self.reader,
            expected_inventory_sha256=inventory["inventory_sha256"],
            expected_endpoint_state_sha256=inventory["endpoint_state_sha256"],
            expected_issue_179_source_sha256=inventory["issue_179_source_sha256"],
            expected_preview_sha256=preview["preview_sha256"],
            expected_prior_generation=None if preview["generation"] == 1 else preview["generation"] - 1,
            now="2026-08-24T09:00:02Z",
        )
        return prepared, outbox_id

    def complete_outbox(self, outbox_id: int) -> None:
        self.store.reserve_outbox(outbox_id, "2026-08-24T09:00:03Z")
        self.store.complete_outbox(outbox_id, "comment:555", "2026-08-24T09:00:04Z")
        row = self.store.connection.execute("SELECT * FROM routing_deprecation_inventories WHERE outbox_id=?", (outbox_id,)).fetchone()
        current = self.store.connection.execute("SELECT 1 FROM routing_deprecation_current").fetchone()
        if row is not None and int(row["generation"]) == 1 and current is None:
            inventory = self.candidate()[0]
            self.promote_current(
                repository=REPOSITORY, generation=1, inventory_sha256=row["inventory_sha256"],
                expected_prior_generation=None, expected_preview_sha256=row["preview_sha256"],
                remote_receipt_body=published_receipt_body(inventory), now="2026-08-24T09:00:04Z",
            )

    def promote_current(self, **kwargs):
        inventory, occurrences = self.candidate()
        return self.store.promote_routing_deprecation_inventory(
            current_inventory=inventory, current_occurrences=occurrences,
            alias_source_path=ALIASES, **kwargs,
        )

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

    def promoted_second_generation(self):
        _, first_outbox = self.prepare()
        self.complete_outbox(first_outbox)
        changed_body = f"Immutable provenance: never dispatch to {self.alias}."
        self.store.ingest_snapshot(repository=REPOSITORY, object_kind="issue", object_number=179,
            payload={"number": 179, "body": changed_body, "updated_at": UPDATED},
            source_updated_at="2026-08-24T10:00:00Z", fetched_at="2026-08-24T10:00:01Z")
        self.reader = StaticReader([node("issue", 179, changed_body)])
        preview = preview_inventory(self.store, repository=REPOSITORY, alias_path=ALIASES, page_reader=self.reader)
        second = self.candidate()[0]
        second, outbox_id = prepare_inventory(self.store, repository=REPOSITORY, alias_path=ALIASES, page_reader=self.reader,
            expected_inventory_sha256=second["inventory_sha256"], expected_endpoint_state_sha256=second["endpoint_state_sha256"],
            expected_issue_179_source_sha256=second["issue_179_source_sha256"], expected_preview_sha256=preview["preview_sha256"],
            expected_prior_generation=1, now="2026-08-24T10:00:02Z")
        self.complete_outbox(outbox_id)
        self.promote_current(repository=REPOSITORY, generation=2,
            inventory_sha256=second["inventory_sha256"], expected_prior_generation=1,
            expected_preview_sha256=preview["preview_sha256"], remote_receipt_body=published_receipt_body(second),
            now="2026-08-24T10:00:05Z")
        return second

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
                expected_preview_sha256=self.store.connection.execute(
                    "SELECT preview_sha256 FROM routing_deprecation_inventories"
                ).fetchone()[0],
                expected_prior_generation=None,
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

    def test_prepare_rejects_dynamic_numeric_types_ranges_and_bool_zero_write(self) -> None:
        cases = (("object_number", "abc"), ("object_number", True), ("object_number", 1.5),
                 ("byte_start", -1), ("byte_end", 0), ("line_number", 0), ("byte_column", False))
        for field, value in cases:
            inventory, occurrences = self.candidate(); inventory = copy.deepcopy(inventory); occurrences = copy.deepcopy(occurrences)
            occurrences[0][field] = value
            inventory["occurrence_manifest_sha256"] = digest_json(occurrences)
            inventory["inventory_sha256"] = digest_json({key: item for key, item in inventory.items() if key != "inventory_sha256"})
            before = tuple(self.store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("routing_deprecation_inventories","routing_deprecation_occurrences","github_outbox"))
            with self.subTest(field=field, value=value), self.assertRaisesRegex(CoordinationError, "INVENTORY_INVALID"):
                self.store.prepare_routing_deprecation_inventory(inventory=inventory, occurrences=occurrences,
                    alias_source_path=ALIASES, outbox_idempotency_key=f"invalid-{field}-{value}", receipt_body="invalid",
                    expected_preview_sha256="0" * 64, expected_prior_generation=None,
                    now="2026-08-24T09:00:02Z")
            after = tuple(self.store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("routing_deprecation_inventories","routing_deprecation_occurrences","github_outbox"))
            self.assertEqual(before, after)

    def test_first_generation_prepare_is_non_authorizing_until_real_receipt_promotion(self) -> None:
        inventory, outbox_id = self.prepare()
        self.assertIsNone(self.store.connection.execute("SELECT * FROM routing_deprecation_current").fetchone())
        self.assertEqual("HOLD", self.readiness(inventory)["phase"])
        with self.assertRaisesRegex(CoordinationError, "RECEIPT_INCOMPLETE"):
            row = self.store.connection.execute("SELECT * FROM routing_deprecation_inventories").fetchone()
            self.promote_current(repository=REPOSITORY, generation=1,
                inventory_sha256=inventory["inventory_sha256"], expected_prior_generation=None,
                expected_preview_sha256=row["preview_sha256"], remote_receipt_body=published_receipt_body(inventory),
                now="2026-08-24T09:00:03Z")
        self.complete_outbox(outbox_id)
        self.assertEqual(1, self.store.connection.execute("SELECT generation FROM routing_deprecation_current").fetchone()[0])
        self.assertEqual("comment:555", self.store.connection.execute("SELECT remote_receipt FROM routing_deprecation_promotions").fetchone()[0])

    def test_promotion_holds_after_non_179_full_scan_drift(self) -> None:
        other = f"Historical mention of {self.alias}."
        self.reader = StaticReader([node("issue", 179, self.body), node("issue", 180, other)])
        inventory, outbox_id = self.prepare()
        self.store.reserve_outbox(outbox_id, "2026-08-24T09:00:03Z")
        self.store.complete_outbox(outbox_id, "comment:555", "2026-08-24T09:00:04Z")
        self.reader = StaticReader([node("issue", 179, self.body), node("issue", 180, other + " changed")])
        row = self.store.connection.execute("SELECT * FROM routing_deprecation_inventories").fetchone()
        with self.assertRaisesRegex(CoordinationError, "PROMOTION_SOURCE_DRIFT"):
            self.promote_current(repository=REPOSITORY, generation=1,
                inventory_sha256=inventory["inventory_sha256"], expected_prior_generation=None,
                expected_preview_sha256=row["preview_sha256"], remote_receipt_body=published_receipt_body(inventory),
                now="2026-08-24T09:00:05Z")
        self.assertIsNone(self.store.connection.execute("SELECT * FROM routing_deprecation_current").fetchone())

    def test_promotion_holds_after_issue_179_drift_but_preserves_complete_receipt(self) -> None:
        inventory, outbox_id = self.prepare()
        self.store.reserve_outbox(outbox_id, "2026-08-24T09:00:03Z")
        self.store.complete_outbox(outbox_id, "comment:555", "2026-08-24T09:00:04Z")
        changed = self.body + " changed"
        self.store.ingest_snapshot(repository=REPOSITORY, object_kind="issue", object_number=179,
            payload={"number": 179, "body": changed, "updated_at": UPDATED},
            source_updated_at="2026-08-24T09:01:00Z", fetched_at="2026-08-24T09:01:01Z")
        self.reader = StaticReader([node("issue", 179, changed)])
        row = self.store.connection.execute("SELECT * FROM routing_deprecation_inventories").fetchone()
        for _ in range(2):
            with self.assertRaisesRegex(CoordinationError, "PROMOTION_SOURCE_DRIFT"):
                self.promote_current(repository=REPOSITORY, generation=1,
                    inventory_sha256=inventory["inventory_sha256"], expected_prior_generation=None,
                    expected_preview_sha256=row["preview_sha256"], remote_receipt_body=published_receipt_body(inventory),
                    now="2026-08-24T09:01:02Z")
        self.assertEqual("COMPLETE", self.store.connection.execute("SELECT state FROM github_outbox WHERE id=?", (outbox_id,)).fetchone()[0])
        self.assertIsNone(self.store.connection.execute("SELECT * FROM routing_deprecation_current").fetchone())

    def test_exact_promotion_replay_revalidates_corrupt_outbox_state_and_receipt(self) -> None:
        for column, value in (("state", "'PREPARED'"), ("remote_receipt", "'comment:999'")):
            case = RoutingInventoryStoreTests(); case.setUp()
            try:
                inventory, outbox_id = case.prepare(); case.complete_outbox(outbox_id)
                row = case.store.connection.execute("SELECT * FROM routing_deprecation_inventories").fetchone()
                before = ([tuple(item) for item in case.store.connection.execute("SELECT * FROM routing_deprecation_current")], [tuple(item) for item in case.store.connection.execute("SELECT * FROM routing_deprecation_promotions")])
                case.store.connection.execute(f"UPDATE github_outbox SET {column}={value} WHERE id=?", (outbox_id,)); case.store.connection.commit()
                with self.subTest(column=column), self.assertRaisesRegex(CoordinationError, "RECEIPT_INCOMPLETE|PROMOTION_CONFLICT"):
                    case.promote_current(repository=REPOSITORY, generation=1,
                        inventory_sha256=inventory["inventory_sha256"], expected_prior_generation=None,
                        expected_preview_sha256=row["preview_sha256"], remote_receipt_body=published_receipt_body(inventory),
                        now="2026-08-24T09:00:05Z")
                after = ([tuple(item) for item in case.store.connection.execute("SELECT * FROM routing_deprecation_current")], [tuple(item) for item in case.store.connection.execute("SELECT * FROM routing_deprecation_promotions")])
                self.assertEqual(before, after)
            finally:
                case.tearDown()

    def test_older_promotion_replay_revalidates_entire_current_chain(self) -> None:
        cases = {
            "current_generation": ("DROP TRIGGER routing_deprecation_current_monotonic", "UPDATE routing_deprecation_current SET generation=3"),
            "current_inventory": ("DROP TRIGGER routing_deprecation_current_monotonic", "UPDATE routing_deprecation_current SET inventory_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"),
            "gen2_prior": ("DROP TRIGGER routing_deprecation_promotion_immutable_update", "UPDATE routing_deprecation_promotions SET prior_generation=99 WHERE generation=2"),
            "gen2_inventory": ("DROP TRIGGER routing_deprecation_promotion_immutable_update", "UPDATE routing_deprecation_promotions SET inventory_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE generation=2"),
            "gen2_counts": ("DROP TRIGGER routing_deprecation_inventory_immutable_update", "UPDATE routing_deprecation_inventories SET classification_counts_json='{}' WHERE generation=2"),
        }
        for name, (setup_sql, mutation_sql) in cases.items():
            case = RoutingInventoryStoreTests(); case.setUp()
            try:
                case.promoted_second_generation()
                first = case.store.connection.execute("SELECT * FROM routing_deprecation_inventories WHERE generation=1").fetchone()
                outbox = case.store.connection.execute("SELECT * FROM github_outbox WHERE id=?", (first["outbox_id"],)).fetchone()
                payload_body = json.loads(outbox["payload_json"])["body"]
                marker = __import__("hashlib").sha256(outbox["idempotency_key"].encode()).hexdigest()
                readback = f"{payload_body}\n\n<!-- twinfinity-outbox:{marker} -->"
                case.store.connection.commit(); case.store.connection.execute("PRAGMA foreign_keys=OFF")
                case.store.connection.execute(setup_sql); case.store.connection.execute(mutation_sql); case.store.connection.commit()
                before = ([tuple(row) for row in case.store.connection.execute("SELECT * FROM routing_deprecation_current")], [tuple(row) for row in case.store.connection.execute("SELECT * FROM routing_deprecation_promotions ORDER BY generation")])
                with self.subTest(name=name), self.assertRaisesRegex(CoordinationError, "PROMOTION_CHAIN_INVALID|PROMOTION_CONFLICT"):
                    case.promote_current(repository=REPOSITORY, generation=1,
                        inventory_sha256=first["inventory_sha256"], expected_prior_generation=None,
                        expected_preview_sha256=first["preview_sha256"], remote_receipt_body=readback,
                        now="2026-08-24T10:10:00Z")
                after = ([tuple(row) for row in case.store.connection.execute("SELECT * FROM routing_deprecation_current")], [tuple(row) for row in case.store.connection.execute("SELECT * FROM routing_deprecation_promotions ORDER BY generation")])
                self.assertEqual(before, after)
            finally:
                case.tearDown()

    def test_current_version_zero_or_999_holds_archive_and_replay(self) -> None:
        for version in (0, 999):
            case = RoutingInventoryStoreTests(); case.setUp()
            try:
                second = case.promoted_second_generation()
                first = case.store.connection.execute("SELECT * FROM routing_deprecation_inventories WHERE generation=1").fetchone()
                outbox = case.store.connection.execute("SELECT * FROM github_outbox WHERE id=?", (first["outbox_id"],)).fetchone()
                marker = __import__("hashlib").sha256(outbox["idempotency_key"].encode()).hexdigest()
                readback = f"{json.loads(outbox['payload_json'])['body']}\n\n<!-- twinfinity-outbox:{marker} -->"
                case.store.connection.execute("PRAGMA ignore_check_constraints=ON")
                case.store.connection.execute("DROP TRIGGER routing_deprecation_current_monotonic")
                case.store.connection.execute("UPDATE routing_deprecation_current SET version=?", (version,)); case.store.connection.commit()
                with self.subTest(version=version):
                    self.assertEqual("HOLD", case.readiness(second)["phase"])
                    with self.assertRaisesRegex(CoordinationError, "PROMOTION_CHAIN_INVALID"):
                        case.promote_current(repository=REPOSITORY, generation=1,
                            inventory_sha256=first["inventory_sha256"], expected_prior_generation=None,
                            expected_preview_sha256=first["preview_sha256"], remote_receipt_body=readback,
                            now="2026-08-24T10:20:00Z")
            finally: case.tearDown()

    def test_archive_validates_intact_multigeneration_history(self) -> None:
        second = self.promoted_second_generation()
        self.assertEqual("PASS", self.readiness(second)["phase"])

    def test_archive_holds_each_historic_promotion_preview_and_outbox_corruption(self) -> None:
        cases = {
            "prior_generation": ("DROP TRIGGER routing_deprecation_promotion_immutable_update", "UPDATE routing_deprecation_promotions SET prior_generation=99 WHERE generation=1"),
            "inventory_preview": ("DROP TRIGGER routing_deprecation_inventory_immutable_update", "UPDATE routing_deprecation_inventories SET preview_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE generation=1"),
            "promotion_preview": ("DROP TRIGGER routing_deprecation_promotion_immutable_update", "UPDATE routing_deprecation_promotions SET preview_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE generation=1"),
            "promotion_receipt": ("DROP TRIGGER routing_deprecation_promotion_immutable_update", "UPDATE routing_deprecation_promotions SET remote_receipt='comment:999' WHERE generation=1"),
            "outbox_state": (None, "UPDATE github_outbox SET state='PREPARED' WHERE id=(SELECT outbox_id FROM routing_deprecation_inventories WHERE generation=1)"),
            "outbox_receipt": (None, "UPDATE github_outbox SET remote_receipt='comment:999' WHERE id=(SELECT outbox_id FROM routing_deprecation_inventories WHERE generation=1)"),
            "outbox_payload": ("DROP TRIGGER routing_deprecation_outbox_envelope_immutable", "UPDATE github_outbox SET payload_json='{}' WHERE id=(SELECT outbox_id FROM routing_deprecation_inventories WHERE generation=1)"),
            "outbox_idempotency": ("DROP TRIGGER routing_deprecation_outbox_envelope_immutable", "UPDATE github_outbox SET idempotency_key='changed' WHERE id=(SELECT outbox_id FROM routing_deprecation_inventories WHERE generation=1)"),
            "outbox_source": ("DROP TRIGGER routing_deprecation_outbox_envelope_immutable", "UPDATE github_outbox SET expected_source_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id=(SELECT outbox_id FROM routing_deprecation_inventories WHERE generation=1)"),
        }
        for name, (setup_sql, mutation_sql) in cases.items():
            case = RoutingInventoryStoreTests()
            case.setUp()
            try:
                second = case.promoted_second_generation()
                if setup_sql:
                    case.store.connection.execute(setup_sql)
                case.store.connection.execute(mutation_sql)
                case.store.connection.commit()
                with self.subTest(name=name):
                    self.assertEqual("HOLD", case.readiness(second)["phase"])
            finally:
                case.tearDown()

    def test_archive_holds_each_historic_inventory_root_corruption(self) -> None:
        cases = {
            "kind": ("inventory", "kind='CHANGED'"), "state": ("inventory", "state='PREPARED'"),
            "issue_count": ("inventory", "issue_count=99"), "pull_request_count": ("inventory", "pull_request_count=99"),
            "classification_counts": ("inventory", "classification_counts_json='{}'"),
            "semantic_tag_counts": ("inventory", "semantic_tag_counts_json='{}'"),
            "classification_malformed": ("inventory", "classification_counts_json='{'"),
            "semantic_tag_malformed": ("inventory", "semantic_tag_counts_json='{'"),
            "occurrence_updated": ("occurrence", "object_updated_at='2099-01-01T00:00:00Z'"),
        }
        for name, (surface, assignment) in cases.items():
            case = RoutingInventoryStoreTests(); case.setUp()
            try:
                second = case.promoted_second_generation()
                case.store.connection.execute("PRAGMA ignore_check_constraints=ON")
                if surface == "inventory":
                    case.store.connection.execute("DROP TRIGGER routing_deprecation_inventory_immutable_update")
                    case.store.connection.execute(f"UPDATE routing_deprecation_inventories SET {assignment} WHERE generation=1")
                else:
                    case.store.connection.execute("DROP TRIGGER routing_deprecation_occurrence_immutable_update")
                    case.store.connection.execute(f"UPDATE routing_deprecation_occurrences SET {assignment} WHERE inventory_sha256=(SELECT inventory_sha256 FROM routing_deprecation_inventories WHERE generation=1)")
                case.store.connection.commit()
                with self.subTest(name=name): self.assertEqual("HOLD", case.readiness(second)["phase"])
            finally:
                case.tearDown()

    def test_archive_holds_coordinated_manifest_preview_outbox_tamper_with_unchanged_root(self) -> None:
        second = self.promoted_second_generation()
        row = self.store.connection.execute("SELECT * FROM routing_deprecation_inventories WHERE generation=1").fetchone()
        objects = json.loads(row["object_manifest_json"]); objects[0]["node_id"] = "tampered-node"
        object_digest = digest_json(objects)
        preview = {"repository": row["repository"], "generation": 1, "predecessor_inventory_sha256": None,
            "inventory_sha256": row["inventory_sha256"], "alias_source_sha256": row["alias_source_sha256"],
            "endpoint_state_sha256": row["endpoint_state_sha256"], "issue_179_source_sha256": row["issue_179_source_sha256"],
            "object_manifest_sha256": object_digest, "occurrence_manifest_sha256": row["occurrence_manifest_sha256"]}
        preview_digest = digest_json(preview)
        self.store.connection.execute("DROP TRIGGER routing_deprecation_inventory_immutable_update")
        self.store.connection.execute("DROP TRIGGER routing_deprecation_promotion_immutable_update")
        self.store.connection.execute("DROP TRIGGER routing_deprecation_outbox_envelope_immutable")
        self.store.connection.execute("UPDATE routing_deprecation_inventories SET object_manifest_json=?,object_manifest_sha256=?,preview_sha256=? WHERE generation=1", (canonical_json(objects), object_digest, preview_digest))
        self.store.connection.execute("UPDATE routing_deprecation_promotions SET preview_sha256=? WHERE generation=1", (preview_digest,))
        changed = self.store.connection.execute("SELECT * FROM routing_deprecation_inventories WHERE generation=1").fetchone()
        body = self.store._routing_deprecation_receipt_body(changed); payload = {"body": body}
        self.store.connection.execute("UPDATE github_outbox SET payload_json=?,payload_sha256=? WHERE id=?", (canonical_json(payload), digest_json(payload), row["outbox_id"]))
        self.store.connection.commit()
        self.assertEqual("HOLD", self.readiness(second)["phase"])

    def test_successor_prepare_is_non_authorizing_then_exact_promotion_is_idempotent(self) -> None:
        first, first_outbox = self.prepare()
        self.complete_outbox(first_outbox)
        old_inventory = dict(self.store.connection.execute(
            "SELECT * FROM routing_deprecation_inventories WHERE generation=1"
        ).fetchone())
        old_occurrences = [tuple(row) for row in self.store.connection.execute(
            "SELECT * FROM routing_deprecation_occurrences ORDER BY ordinal"
        )]
        changed_body = f"Immutable provenance: never dispatch to {self.alias}."
        self.source = self.store.ingest_snapshot(
            repository=REPOSITORY, object_kind="issue", object_number=179,
            payload={"number": 179, "body": changed_body, "updated_at": UPDATED},
            source_updated_at="2026-08-24T10:00:00Z", fetched_at="2026-08-24T10:00:01Z",
        )
        self.reader = StaticReader([node("issue", 179, changed_body)])
        preview = preview_inventory(self.store, repository=REPOSITORY, alias_path=ALIASES, page_reader=self.reader)
        candidate, _ = self.candidate()
        second, second_outbox = prepare_inventory(
            self.store, repository=REPOSITORY, alias_path=ALIASES,
            page_reader=self.reader, expected_inventory_sha256=candidate["inventory_sha256"],
            expected_endpoint_state_sha256=candidate["endpoint_state_sha256"],
            expected_issue_179_source_sha256=candidate["issue_179_source_sha256"],
            expected_preview_sha256=preview["preview_sha256"], expected_prior_generation=1,
            now="2026-08-24T10:00:02Z",
        )
        self.assertEqual(1, self.store.connection.execute(
            "SELECT generation FROM routing_deprecation_current"
        ).fetchone()[0])
        with self.assertRaisesRegex(CoordinationError, "RECEIPT_INCOMPLETE"):
            self.promote_current(
                repository=REPOSITORY, generation=2, inventory_sha256=second["inventory_sha256"],
                expected_prior_generation=1, expected_preview_sha256=preview["preview_sha256"],
                remote_receipt_body=published_receipt_body(second), now="2026-08-24T10:00:03Z",
            )
        self.complete_outbox(second_outbox)
        promoted = self.promote_current(
            repository=REPOSITORY, generation=2, inventory_sha256=second["inventory_sha256"],
            expected_prior_generation=1, expected_preview_sha256=preview["preview_sha256"],
            remote_receipt_body=published_receipt_body(second), now="2026-08-24T10:00:05Z",
        )
        replay = self.promote_current(
            repository=REPOSITORY, generation=2, inventory_sha256=second["inventory_sha256"],
            expected_prior_generation=1, expected_preview_sha256=preview["preview_sha256"],
            remote_receipt_body=published_receipt_body(second), now="2026-08-24T10:00:06Z",
        )
        self.assertEqual(promoted, replay)
        prepared_replay, replay_outbox = prepare_inventory(
            self.store, repository=REPOSITORY, alias_path=ALIASES,
            page_reader=self.reader, expected_inventory_sha256=second["inventory_sha256"],
            expected_endpoint_state_sha256=second["endpoint_state_sha256"],
            expected_issue_179_source_sha256=second["issue_179_source_sha256"],
            expected_preview_sha256=preview["preview_sha256"], expected_prior_generation=1,
            now="2026-08-24T10:00:07Z",
        )
        self.assertEqual((second["inventory_sha256"], second_outbox), (prepared_replay["inventory_sha256"], replay_outbox))
        self.assertEqual(2, self.store.connection.execute("SELECT generation FROM routing_deprecation_current").fetchone()[0])
        self.assertEqual(old_inventory, dict(self.store.connection.execute("SELECT * FROM routing_deprecation_inventories WHERE generation=1").fetchone()))
        self.assertEqual(old_occurrences, [tuple(row) for row in self.store.connection.execute("SELECT * FROM routing_deprecation_occurrences WHERE inventory_sha256=? ORDER BY ordinal", (first["inventory_sha256"],))])

    def downgrade_to_exact_legacy_v1(self):
        legacy = dict(self.store.connection.execute("SELECT * FROM routing_deprecation_inventories").fetchone())
        legacy = {key: value for key, value in legacy.items() if key not in {"generation", "predecessor_inventory_sha256", "preview_sha256"}}
        occurrences = [dict(row) for row in self.store.connection.execute("SELECT * FROM routing_deprecation_occurrences ORDER BY ordinal")]
        trigger_rows = list(self.store.connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name IN ('routing_deprecation_inventory_immutable_update','routing_deprecation_inventory_immutable_delete','routing_deprecation_occurrence_immutable_update','routing_deprecation_occurrence_immutable_delete','routing_deprecation_occurrence_append_fenced','routing_deprecation_outbox_envelope_immutable')"))
        self.store.connection.commit()
        self.store.connection.execute("PRAGMA foreign_keys=OFF")
        self.store.connection.execute("DROP TRIGGER routing_deprecation_promotion_immutable_delete")
        self.store.connection.execute("DELETE FROM routing_deprecation_promotions")
        self.store.connection.execute("DROP TRIGGER routing_deprecation_current_no_delete")
        self.store.connection.execute("DELETE FROM routing_deprecation_current")
        self.store._create_schema()
        for row in trigger_rows:
            self.store.connection.execute(f"DROP TRIGGER {row['name']}")
        self.store.connection.execute("DROP TABLE routing_deprecation_occurrences")
        self.store.connection.execute("DROP TABLE routing_deprecation_inventories")
        self.store.connection.executescript("""
        CREATE TABLE routing_deprecation_inventories (
          inventory_sha256 TEXT PRIMARY KEY, repository TEXT NOT NULL UNIQUE,
          kind TEXT NOT NULL CHECK(kind='TWINFINITY_ROUTING_DEPRECATION_INVENTORY_V1'), alias_source_sha256 TEXT NOT NULL,
          endpoint_state_sha256 TEXT NOT NULL, issue_179_source_sha256 TEXT NOT NULL, object_manifest_sha256 TEXT NOT NULL,
          occurrence_manifest_sha256 TEXT NOT NULL, object_manifest_json TEXT NOT NULL,
          object_count INTEGER NOT NULL CHECK(object_count >= 0), issue_count INTEGER NOT NULL CHECK(issue_count >= 0),
          pull_request_count INTEGER NOT NULL CHECK(pull_request_count >= 0), occurrence_count INTEGER NOT NULL CHECK(occurrence_count >= 0),
          classification_counts_json TEXT NOT NULL, semantic_tag_counts_json TEXT NOT NULL, outbox_id INTEGER NOT NULL UNIQUE,
          state TEXT NOT NULL CHECK(state='COMPLETE'), created_at TEXT NOT NULL, FOREIGN KEY(outbox_id) REFERENCES github_outbox(id));
        CREATE TABLE routing_deprecation_occurrences (
          inventory_sha256 TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
          object_kind TEXT NOT NULL CHECK(object_kind IN ('issue', 'pull_request')), object_number INTEGER NOT NULL CHECK(object_number > 0),
          node_id TEXT NOT NULL, object_updated_at TEXT NOT NULL, body_sha256 TEXT NOT NULL, alias TEXT NOT NULL,
          byte_start INTEGER NOT NULL CHECK(byte_start >= 0), byte_end INTEGER NOT NULL CHECK(byte_end > byte_start),
          line_number INTEGER NOT NULL CHECK(line_number > 0), byte_column INTEGER NOT NULL CHECK(byte_column > 0),
          classification TEXT NOT NULL CHECK(classification IN ('EXECUTABLE_ROUTE','ROUTING_REFERENCE','HISTORICAL_PROVENANCE','AMBIGUOUS_REFERENCE')),
          semantic_tags_json TEXT NOT NULL, PRIMARY KEY(inventory_sha256, ordinal),
          UNIQUE(inventory_sha256, object_kind, object_number, byte_start, alias),
          FOREIGN KEY(inventory_sha256) REFERENCES routing_deprecation_inventories(inventory_sha256));
        """)
        columns = list(legacy)
        self.store.connection.execute(f"INSERT INTO routing_deprecation_inventories({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", [legacy[key] for key in columns])
        occurrence_columns = list(occurrences[0]) if occurrences else []
        if occurrences:
            self.store.connection.executemany(f"INSERT INTO routing_deprecation_occurrences({','.join(occurrence_columns)}) VALUES ({','.join('?' for _ in occurrence_columns)})", [[item[key] for key in occurrence_columns] for item in occurrences])
        for row in trigger_rows:
            self.store.connection.execute(row["sql"])
        self.store.connection.commit()
        self.store.connection.execute("PRAGMA foreign_keys=ON")
        return legacy, occurrences

    def test_legacy_v1_migration_preserves_inventory_bytes_and_fails_closed(self) -> None:
        inventory, outbox_id = self.prepare()
        self.complete_outbox(outbox_id)
        legacy, _ = self.downgrade_to_exact_legacy_v1()
        result = self.store.migrate_legacy_routing_deprecation_inventory(
            expected_repository=REPOSITORY,
            expected_inventory_sha256=inventory["inventory_sha256"],
            expected_occurrence_count=inventory["occurrence_count"], now="2026-08-24T11:00:00Z",
        )
        self.assertFalse(result["replay"])
        migrated = dict(self.store.connection.execute("SELECT * FROM routing_deprecation_inventories").fetchone())
        for key, value in legacy.items():
            self.assertEqual(value, migrated[key])
        replay = self.store.migrate_legacy_routing_deprecation_inventory(expected_repository=REPOSITORY, expected_inventory_sha256=inventory["inventory_sha256"], expected_occurrence_count=inventory["occurrence_count"], now="2026-08-24T11:00:01Z")
        self.assertTrue(replay["replay"])

    def test_migrated_v2_schema_matches_fresh_canonical_sql_and_enforces_checks(self) -> None:
        inventory, outbox_id = self.prepare(); self.complete_outbox(outbox_id)
        self.downgrade_to_exact_legacy_v1()
        self.store.migrate_legacy_routing_deprecation_inventory(expected_repository=REPOSITORY, expected_inventory_sha256=inventory["inventory_sha256"], expected_occurrence_count=inventory["occurrence_count"], now="2026-08-24T11:01:00Z")
        actual = {row[0]: _normalized_schema_sql(row[1]) for row in self.store.connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name IN ('routing_deprecation_inventories','routing_deprecation_occurrences')")}
        self.assertEqual({"routing_deprecation_inventories": _normalized_schema_sql(ROUTING_INVENTORIES_TABLE_SQL), "routing_deprecation_occurrences": _normalized_schema_sql(ROUTING_OCCURRENCES_TABLE_SQL)}, actual)
        self.store.connection.execute("DROP TRIGGER routing_deprecation_occurrence_append_fenced")
        original = dict(self.store.connection.execute("SELECT * FROM routing_deprecation_occurrences LIMIT 1").fetchone())
        cases = {"byte_start": (-1, original["byte_end"]), "byte_end": (original["byte_start"], original["byte_start"]), "line_number": (original["byte_start"] + 100, original["byte_end"] + 100), "byte_column": (original["byte_start"] + 200, original["byte_end"] + 200), "classification": (original["byte_start"] + 300, original["byte_end"] + 300), "object_number_text": (original["byte_start"] + 400, original["byte_end"] + 400), "ordinal_float": (original["byte_start"] + 500, original["byte_end"] + 500)}
        for offset, (name, (start, end)) in enumerate(cases.items(), 10):
            row = dict(original); row["ordinal"] = offset; row["byte_start"] = start; row["byte_end"] = end
            row["line_number"] = 0 if name == "line_number" else row["line_number"]
            row["byte_column"] = 0 if name == "byte_column" else row["byte_column"]
            row["classification"] = "INVALID" if name == "classification" else row["classification"]
            row["object_number"] = "abc" if name == "object_number_text" else row["object_number"]
            row["ordinal"] = 1.5 if name == "ordinal_float" else row["ordinal"]
            columns = list(row)
            with self.subTest(name=name), self.assertRaises(sqlite3.IntegrityError):
                self.store.connection.execute(f"INSERT INTO routing_deprecation_occurrences({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", [row[key] for key in columns])
        self.store.connection.execute("DROP TRIGGER routing_deprecation_current_monotonic")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("UPDATE routing_deprecation_current SET version='abc'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("INSERT INTO routing_deprecation_promotions(repository,generation,prior_generation,inventory_sha256,preview_sha256,remote_receipt,promoted_at) VALUES ('other','abc',NULL,?,?,'comment:1','now')", ('f'*64,'e'*64))

    def test_v2_replay_rejects_degraded_check_schema_without_writes(self) -> None:
        inventory, outbox_id = self.prepare(); self.complete_outbox(outbox_id)
        self.store.connection.execute("PRAGMA writable_schema=ON")
        sql = self.store.connection.execute("SELECT sql FROM sqlite_master WHERE name='routing_deprecation_occurrences'").fetchone()[0]
        self.store.connection.execute("UPDATE sqlite_master SET sql=? WHERE name='routing_deprecation_occurrences'", (sql.replace(" CHECK(typeof(byte_start)='integer' AND byte_start >= 0)", ""),))
        self.store.connection.execute("PRAGMA writable_schema=OFF"); self.store.connection.commit()
        before = self.legacy_database_fingerprint()
        with self.assertRaisesRegex(CoordinationError, "MIGRATION_CONFLICT"):
            self.store.migrate_legacy_routing_deprecation_inventory(expected_repository=REPOSITORY, expected_inventory_sha256=inventory["inventory_sha256"], expected_occurrence_count=inventory["occurrence_count"], now="2026-08-24T11:02:00Z")
        self.assertEqual(before, self.legacy_database_fingerprint())

    def legacy_database_fingerprint(self):
        schema = [tuple(row) for row in self.store.connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name LIKE 'routing_deprecation_%' ORDER BY type,name"
        )]
        data = {}
        for table in ("routing_deprecation_inventories", "routing_deprecation_occurrences", "routing_deprecation_current", "routing_deprecation_promotions", "github_outbox"):
            data[table] = [tuple(row) for row in self.store.connection.execute(f"SELECT * FROM {table}")]
        return schema, data, int(self.store.connection.execute("PRAGMA foreign_keys").fetchone()[0])

    def assert_legacy_migration_hold_is_zero_write(self, inventory, error="LEGACY_SHAPE_INVALID"):
        before = self.legacy_database_fingerprint()
        with self.assertRaisesRegex(CoordinationError, error):
            self.store.migrate_legacy_routing_deprecation_inventory(
                expected_repository=REPOSITORY,
                expected_inventory_sha256=inventory["inventory_sha256"],
                expected_occurrence_count=inventory["occurrence_count"], now="2026-08-24T11:10:00Z",
            )
        self.assertEqual(before, self.legacy_database_fingerprint())

    def test_legacy_migration_rejects_ctas_missing_pk_unique_fk_not_null_and_checks(self) -> None:
        inventory, outbox_id = self.prepare(); self.complete_outbox(outbox_id)
        self.downgrade_to_exact_legacy_v1()
        self.store.connection.commit(); self.store.connection.execute("PRAGMA foreign_keys=OFF")
        self.store.connection.execute("ALTER TABLE routing_deprecation_inventories RENAME TO routing_deprecation_inventories_exact")
        self.store.connection.execute("CREATE TABLE routing_deprecation_inventories AS SELECT * FROM routing_deprecation_inventories_exact")
        self.store.connection.execute("DROP TABLE routing_deprecation_inventories_exact")
        self.store.connection.commit(); self.store.connection.execute("PRAGMA foreign_keys=ON")
        info = list(self.store.connection.execute("PRAGMA table_info(routing_deprecation_inventories)"))
        self.assertFalse(any(row[5] for row in info)); self.assertFalse(any(row[3] for row in info))
        self.assertEqual([], list(self.store.connection.execute("PRAGMA index_list(routing_deprecation_inventories)")))
        self.assertEqual([], list(self.store.connection.execute("PRAGMA foreign_key_list(routing_deprecation_inventories)")))
        self.assertNotIn("CHECK", self.store.connection.execute("SELECT sql FROM sqlite_master WHERE name='routing_deprecation_inventories'").fetchone()[0])
        self.assert_legacy_migration_hold_is_zero_write(inventory)

    def test_legacy_migration_rejects_altered_or_unexpected_trigger(self) -> None:
        inventory, outbox_id = self.prepare(); self.complete_outbox(outbox_id)
        self.downgrade_to_exact_legacy_v1()
        self.store.connection.execute("DROP TRIGGER routing_deprecation_inventory_immutable_update")
        self.store.connection.execute("CREATE TRIGGER routing_deprecation_inventory_immutable_update BEFORE UPDATE ON routing_deprecation_inventories BEGIN SELECT RAISE(ABORT,'CHANGED'); END")
        self.store.connection.execute("CREATE TRIGGER routing_deprecation_unexpected BEFORE INSERT ON routing_deprecation_inventories BEGIN SELECT 1; END")
        self.store.connection.commit()
        self.assert_legacy_migration_hold_is_zero_write(inventory)

    def test_legacy_migration_rejects_unexpected_relevant_index(self) -> None:
        inventory, outbox_id = self.prepare(); self.complete_outbox(outbox_id)
        self.downgrade_to_exact_legacy_v1()
        self.store.connection.execute("CREATE INDEX routing_deprecation_unexpected_index ON routing_deprecation_inventories(created_at)")
        self.store.connection.commit()
        self.assert_legacy_migration_hold_is_zero_write(inventory)

    def test_legacy_migration_rejects_partial_generation_state_atomically(self) -> None:
        inventory, outbox_id = self.prepare(); self.complete_outbox(outbox_id)
        legacy, _ = self.downgrade_to_exact_legacy_v1()
        self.store.connection.execute("INSERT INTO routing_deprecation_current VALUES (?,?,?,?,?)", (legacy["repository"],1,legacy["inventory_sha256"],1,"2026-08-24T11:09:00Z"))
        self.store.connection.commit()
        self.assert_legacy_migration_hold_is_zero_write(inventory, "LEGACY_PARTIAL_MIGRATION")

    def test_legacy_migration_rejects_orphan_occurrence_with_zero_writes(self) -> None:
        inventory, outbox_id = self.prepare(); self.complete_outbox(outbox_id)
        self.downgrade_to_exact_legacy_v1()
        row = dict(self.store.connection.execute("SELECT * FROM routing_deprecation_occurrences LIMIT 1").fetchone())
        row["inventory_sha256"] = "f" * 64
        self.store.connection.commit(); self.store.connection.execute("PRAGMA foreign_keys=OFF")
        columns = list(row)
        self.store.connection.execute(f"INSERT INTO routing_deprecation_occurrences({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", [row[key] for key in columns])
        self.store.connection.commit(); self.store.connection.execute("PRAGMA foreign_keys=ON")
        self.assert_legacy_migration_hold_is_zero_write(inventory)

    def test_legacy_migration_rejects_corrupt_inventory_roots_zero_write(self) -> None:
        for assignment in ("classification_counts_json='{}'", "object_manifest_json='[]'", "object_count=99"):
            case = RoutingInventoryStoreTests(); case.setUp()
            try:
                inventory, outbox_id = case.prepare(); case.complete_outbox(outbox_id); case.downgrade_to_exact_legacy_v1()
                case.store.connection.execute("PRAGMA ignore_check_constraints=ON")
                case.store.connection.execute("DROP TRIGGER routing_deprecation_inventory_immutable_update")
                case.store.connection.execute(f"UPDATE routing_deprecation_inventories SET {assignment}"); case.store.connection.commit()
                case.assert_legacy_migration_hold_is_zero_write(inventory)
            finally: case.tearDown()

    def test_legacy_migration_rolls_back_postcopy_failure_and_restores_foreign_keys(self) -> None:
        inventory, outbox_id = self.prepare(); self.complete_outbox(outbox_id)
        self.downgrade_to_exact_legacy_v1()
        before = self.legacy_database_fingerprint()
        with patch.object(self.store, "_routing_deprecation_migration_postcopy_check", side_effect=RuntimeError("injected-postcopy")):
            with self.assertRaisesRegex(RuntimeError, "injected-postcopy"):
                self.store.migrate_legacy_routing_deprecation_inventory(expected_repository=REPOSITORY, expected_inventory_sha256=inventory["inventory_sha256"], expected_occurrence_count=inventory["occurrence_count"], now="2026-08-24T11:20:00Z")
        self.assertEqual(before, self.legacy_database_fingerprint())
        self.store.connection.execute("PRAGMA foreign_keys=OFF")
        result = self.store.migrate_legacy_routing_deprecation_inventory(expected_repository=REPOSITORY, expected_inventory_sha256=inventory["inventory_sha256"], expected_occurrence_count=inventory["occurrence_count"], now="2026-08-24T11:20:01Z")
        self.assertFalse(result["replay"])
        self.assertEqual(0, self.store.connection.execute("PRAGMA foreign_keys").fetchone()[0])
        self.assertEqual([], list(self.store.connection.execute("PRAGMA foreign_key_check")))

    def test_legacy_migration_replay_revalidates_receipt_and_occurrence_count(self) -> None:
        inventory, outbox_id = self.prepare(); self.complete_outbox(outbox_id)
        self.downgrade_to_exact_legacy_v1()
        self.store.migrate_legacy_routing_deprecation_inventory(expected_repository=REPOSITORY, expected_inventory_sha256=inventory["inventory_sha256"], expected_occurrence_count=inventory["occurrence_count"], now="2026-08-24T11:30:00Z")
        self.store.connection.execute("UPDATE github_outbox SET state='PREPARED' WHERE id=?", (outbox_id,))
        self.store.connection.commit()
        before = self.legacy_database_fingerprint()
        with self.assertRaisesRegex(CoordinationError, "MIGRATION_CONFLICT"):
            self.store.migrate_legacy_routing_deprecation_inventory(expected_repository=REPOSITORY, expected_inventory_sha256=inventory["inventory_sha256"], expected_occurrence_count=999, now="2026-08-24T11:30:01Z")
        self.assertEqual(before, self.legacy_database_fingerprint())

    def test_two_successor_prepares_have_one_winner_and_no_orphan_outbox(self) -> None:
        _, first_outbox = self.prepare()
        self.complete_outbox(first_outbox)
        def install_candidate(body: str, stamp: str):
            self.store.ingest_snapshot(repository=REPOSITORY, object_kind="issue", object_number=179,
                payload={"number": 179, "body": body, "updated_at": UPDATED},
                source_updated_at=stamp, fetched_at=stamp)
            self.reader = StaticReader([node("issue", 179, body)])
            return self.candidate()[0], preview_inventory(self.store, repository=REPOSITORY, alias_path=ALIASES, page_reader=self.reader)
        winner, winner_preview = install_candidate(f"Never route to {self.alias}.", "2026-08-24T12:00:00Z")
        prepare_inventory(self.store, repository=REPOSITORY, alias_path=ALIASES, page_reader=self.reader,
            expected_inventory_sha256=winner["inventory_sha256"], expected_endpoint_state_sha256=winner["endpoint_state_sha256"],
            expected_issue_179_source_sha256=winner["issue_179_source_sha256"], expected_preview_sha256=winner_preview["preview_sha256"],
            expected_prior_generation=1, now="2026-08-24T12:00:01Z")
        loser, loser_preview = install_candidate(f"Immutable record of {self.alias}.", "2026-08-24T12:01:00Z")
        before = tuple(self.store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("routing_deprecation_inventories", "routing_deprecation_occurrences", "github_outbox"))
        with self.assertRaisesRegex(CoordinationError, "PREPARE_RACE_OR_FORK"):
            prepare_inventory(self.store, repository=REPOSITORY, alias_path=ALIASES, page_reader=self.reader,
                expected_inventory_sha256=loser["inventory_sha256"], expected_endpoint_state_sha256=loser["endpoint_state_sha256"],
                expected_issue_179_source_sha256=loser["issue_179_source_sha256"], expected_preview_sha256=loser_preview["preview_sha256"],
                expected_prior_generation=1, now="2026-08-24T12:01:01Z")
        after = tuple(self.store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("routing_deprecation_inventories", "routing_deprecation_occurrences", "github_outbox"))
        self.assertEqual(before, after)

    def test_internal_failure_rolls_back_outbox_inventory_and_occurrences(self) -> None:
        inventory, occurrences = self.candidate()
        preview = preview_inventory(self.store, repository=REPOSITORY, alias_path=ALIASES, page_reader=self.reader)
        with patch.object(self.store, "_event", side_effect=RuntimeError("fault")):
            with self.assertRaisesRegex(RuntimeError, "fault"):
                self.store.prepare_routing_deprecation_inventory(
                    inventory=inventory,
                    occurrences=occurrences,
                    alias_source_path=ALIASES,
                    outbox_idempotency_key="atomic-fault",
                    receipt_body="receipt",
                    expected_preview_sha256=preview["preview_sha256"],
                    expected_prior_generation=None,
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
        preview = preview_inventory(self.store, repository=REPOSITORY, alias_path=ALIASES, page_reader=self.reader)
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
                    expected_preview_sha256=preview["preview_sha256"],
                    expected_prior_generation=None,
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
