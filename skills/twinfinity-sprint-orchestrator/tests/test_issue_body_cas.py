from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

from tests.issue88_fixture import (
    CURRENT_SHA256,
    DESIRED_SHA256,
    EXPECTED_UPDATED_AT,
    current_body,
    desired_body,
)


SKILL_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = SKILL_ROOT / "scripts" / "issue_body_cas.py"
SPEC = importlib.util.spec_from_file_location("issue_body_cas", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
cas = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cas
SPEC.loader.exec_module(cas)

class FakeTransport:
    def __init__(
        self,
        initial: cas.IssueSnapshot,
        *,
        readback: cas.IssueSnapshot | None = None,
        patch_error: Exception | None = None,
        readback_error: Exception | None = None,
    ) -> None:
        self.initial = initial
        self.current = initial
        self.readback = readback
        self.patch_error = patch_error
        self.readback_error = readback_error
        self.patch_calls: list[cas.IssueBodyMutation] = []
        self.read_calls: list[tuple[str, int, bool]] = []
        self.before_atomic_write = None
        self.supports_atomic_compare_and_swap = True

    def read_canonical(
        self,
        repository: str,
        issue_number: int,
        *,
        no_cache: bool,
    ) -> cas.IssueSnapshot:
        self.read_calls.append((repository, issue_number, no_cache))
        if len(self.read_calls) == 1:
            return self.initial
        if self.readback_error is not None:
            raise self.readback_error
        if self.readback is not None:
            return self.readback
        return self.current

    def atomic_compare_and_swap_body(
        self,
        mutation: cas.IssueBodyMutation,
    ) -> cas.AtomicWriteDisposition:
        self.patch_calls.append(mutation)
        if self.before_atomic_write is not None:
            self.before_atomic_write(self)
        if self.patch_error is not None:
            raise self.patch_error
        if (
            self.current.body != mutation.expected_body
            or cas.sha256(self.current.body) != mutation.expected_body_sha256
            or self.current.updated_at != mutation.expected_updated_at
        ):
            return cas.AtomicWriteDisposition.CONFLICT
        self.current = cas.IssueSnapshot(
            body=mutation.desired_body,
            updated_at="2026-08-21T18:00:00Z",
        )
        return cas.AtomicWriteDisposition.APPLIED


class IssueBodyCASTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.current = current_body()
        cls.desired = desired_body()

    def setUp(self) -> None:
        self.mutation = cas.IssueBodyMutation.from_bodies(
            repository="twinfinityai/twinfinityapp",
            issue_number=88,
            expected_body=self.current,
            expected_updated_at=EXPECTED_UPDATED_AT,
            desired_body=self.desired,
        )

    def snapshot(self, body: bytes, timestamp: str = EXPECTED_UPDATED_AT):
        return cas.IssueSnapshot(body=body, updated_at=timestamp)

    def apply(self, transport, ledger=None):
        return cas.apply_issue_body_mutation(
            self.mutation,
            transport=transport,
            ledger=ledger or cas.InMemoryAttemptLedger(),
        )

    def test_reviewed_issue88_fixture_is_frozen_exactly(self) -> None:
        self.assertEqual(len(self.current), 16_163)
        self.assertEqual(len(self.desired), 19_047)
        self.assertEqual(cas.sha256(self.current), CURRENT_SHA256)
        self.assertEqual(cas.sha256(self.desired), DESIRED_SHA256)
        self.assertEqual(self.mutation.expected_body_sha256, CURRENT_SHA256)
        self.assertEqual(self.mutation.desired_body_sha256, DESIRED_SHA256)

    def test_valid_sequence_uses_exactly_one_patch_and_exact_readback(self) -> None:
        transport = FakeTransport(self.snapshot(self.current))
        result = self.apply(transport)

        self.assertEqual(result.outcome, cas.Outcome.APPLIED)
        self.assertEqual(result.patch_count, 1)
        self.assertEqual(result.canonical_read_count, 2)
        self.assertEqual(len(transport.patch_calls), 1)
        self.assertEqual(transport.patch_calls[0].desired_body, self.desired)
        self.assertEqual([call[2] for call in transport.read_calls], [True, True])
        self.assertEqual(result.observed_body_sha256, DESIRED_SHA256)

    def test_already_applied_is_idempotent_and_does_not_patch(self) -> None:
        transport = FakeTransport(
            self.snapshot(self.desired, "2026-08-21T18:00:00Z")
        )
        result = self.apply(transport)

        self.assertEqual(result.outcome, cas.Outcome.ALREADY_APPLIED)
        self.assertEqual(result.patch_count, 0)
        self.assertEqual(len(transport.patch_calls), 0)
        self.assertEqual(len(transport.read_calls), 1)
        self.assertTrue(transport.read_calls[0][2])

    def test_body_digest_conflict_does_not_patch(self) -> None:
        transport = FakeTransport(self.snapshot(self.current + b"\nconflict"))
        result = self.apply(transport)

        self.assertEqual(result.outcome, cas.Outcome.CONFLICT)
        self.assertEqual(result.patch_count, 0)
        self.assertEqual(len(transport.patch_calls), 0)

    def test_timestamp_conflict_does_not_patch(self) -> None:
        transport = FakeTransport(
            self.snapshot(self.current, "2026-08-21T06:21:33Z")
        )
        result = self.apply(transport)

        self.assertEqual(result.outcome, cas.Outcome.CONFLICT)
        self.assertEqual(result.patch_count, 0)
        self.assertEqual(len(transport.patch_calls), 0)

    def test_concurrent_writer_is_not_overwritten(self) -> None:
        transport = FakeTransport(self.snapshot(self.current))
        competing = self.current + b"\nconcurrent writer"

        def interleave(fake: FakeTransport) -> None:
            fake.current = self.snapshot(competing, "2026-08-21T18:00:00Z")

        transport.before_atomic_write = interleave
        result = self.apply(transport)

        self.assertEqual(result.outcome, cas.Outcome.CONFLICT)
        self.assertEqual(result.patch_count, 1)
        self.assertEqual(transport.current.body, competing)
        self.assertNotEqual(transport.current.body, self.desired)
        self.assertEqual(result.observed_body_sha256, cas.sha256(competing))

    def test_postcondition_mismatch_is_typed_and_consumes_attempt(self) -> None:
        transport = FakeTransport(
            self.snapshot(self.current),
            readback=self.snapshot(self.current, "2026-08-21T18:00:00Z"),
        )
        ledger = cas.InMemoryAttemptLedger()
        result = self.apply(transport, ledger)

        self.assertEqual(result.outcome, cas.Outcome.POSTCONDITION_FAILED)
        self.assertEqual(result.patch_count, 1)
        self.assertEqual(len(transport.patch_calls), 1)

        retry_transport = FakeTransport(self.snapshot(self.current))
        retry = self.apply(retry_transport, ledger)
        self.assertEqual(retry.outcome, cas.Outcome.POSTCONDITION_FAILED)
        self.assertTrue(retry.retry_suppressed)
        self.assertEqual(retry.patch_count, 0)
        self.assertEqual(len(retry_transport.patch_calls), 0)

    def test_patch_error_still_performs_one_canonical_readback(self) -> None:
        transport = FakeTransport(
            self.snapshot(self.current),
            readback=self.snapshot(self.current, "2026-08-21T18:00:00Z"),
            patch_error=RuntimeError("connector rejected"),
        )
        result = self.apply(transport)

        self.assertEqual(result.outcome, cas.Outcome.POSTCONDITION_FAILED)
        self.assertEqual(result.patch_count, 1)
        self.assertEqual(result.canonical_read_count, 2)
        self.assertEqual(len(transport.patch_calls), 1)
        self.assertEqual([call[2] for call in transport.read_calls], [True, True])

    def test_patch_error_with_desired_readback_is_applied(self) -> None:
        transport = FakeTransport(
            self.snapshot(self.current),
            readback=self.snapshot(self.desired, "2026-08-21T18:00:00Z"),
            patch_error=TimeoutError("ambiguous response"),
        )
        result = self.apply(transport)

        self.assertEqual(result.outcome, cas.Outcome.APPLIED)
        self.assertEqual(result.patch_count, 1)
        self.assertEqual(result.observed_body_sha256, DESIRED_SHA256)

    def test_installed_github_connector_is_rejected_before_unconditional_patch(self) -> None:
        update_calls = []

        def reader(repository: str, issue_number: int, no_cache: bool):
            del repository, issue_number
            self.assertTrue(no_cache)
            return self.snapshot(self.current)

        def updater(repository: str, issue_number: int, body: bytes):
            update_calls.append((repository, issue_number, body))

        transport = cas.GitHubConnectorTransport(
            canonical_reader=reader,
            unconditional_updater=updater,
        )
        result = self.apply(transport)

        self.assertEqual(result.outcome, cas.Outcome.POSTCONDITION_FAILED)
        self.assertEqual(result.detail, "transport_does_not_support_atomic_issue_body_cas")
        self.assertEqual(result.patch_count, 0)
        self.assertEqual(result.canonical_read_count, 0)
        self.assertEqual(update_calls, [])

    def test_readback_failure_is_typed_and_not_retried(self) -> None:
        ledger = cas.InMemoryAttemptLedger()
        transport = FakeTransport(
            self.snapshot(self.current),
            readback_error=ConnectionError("readback unavailable"),
        )
        result = self.apply(transport, ledger)
        self.assertEqual(result.outcome, cas.Outcome.POSTCONDITION_FAILED)
        self.assertEqual(result.patch_count, 1)
        self.assertEqual(len(transport.patch_calls), 1)

        retry_transport = FakeTransport(self.snapshot(self.current))
        retry = self.apply(retry_transport, ledger)
        self.assertTrue(retry.retry_suppressed)
        self.assertEqual(len(retry_transport.patch_calls), 0)

    def test_sqlite_ledger_suppresses_same_digest_across_instances(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "attempts.sqlite3"
            first = cas.SQLiteAttemptLedger(ledger_path)
            second = cas.SQLiteAttemptLedger(ledger_path)
            self.assertTrue(first.reserve_patch(self.mutation))
            self.assertFalse(second.reserve_patch(self.mutation))

    def test_digest_mismatch_is_rejected_before_transport_access(self) -> None:
        invalid = cas.IssueBodyMutation(
            repository=self.mutation.repository,
            issue_number=self.mutation.issue_number,
            expected_body=self.current,
            expected_updated_at=EXPECTED_UPDATED_AT,
            desired_body=self.desired,
            expected_body_sha256="0" * 64,
            desired_body_sha256=DESIRED_SHA256,
        )
        transport = FakeTransport(self.snapshot(self.current))
        with self.assertRaisesRegex(ValueError, "expected body digest"):
            cas.apply_issue_body_mutation(
                invalid,
                transport=transport,
                ledger=cas.InMemoryAttemptLedger(),
            )
        self.assertEqual(transport.read_calls, [])
        self.assertEqual(transport.patch_calls, [])


if __name__ == "__main__":
    unittest.main()
