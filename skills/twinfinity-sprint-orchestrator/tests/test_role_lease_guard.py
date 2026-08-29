from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from delivery_guard import pre_tool  # noqa: E402
from coordination_store import canonical_json, digest_json  # noqa: E402
from delivery_identity import (  # noqa: E402
    bind_delivery_identity,
    delivery_identity_sha256,
)
from run_role_executor import build_child_environment  # noqa: E402
from reviewed_endpoint_catalog_fixture import (  # noqa: E402
    apply_reviewed_current_endpoint_catalog,
)


REPOSITORY = "twinfinityai/twinfinityapp"
SOURCE_SHA = "1" * 64
BASE_SHA = "a" * 40
ATTEMPT_ID = "11111111-1111-4111-8111-111111111111"
INSTANCE_ID = "22222222-2222-4222-8222-222222222222"
TOKEN = "opaque-test-token"


class RoleLeaseGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.code_root = self.root / "code"
        self.code_root.mkdir(mode=0o700)
        self.identity_root_patch = patch(
            "delivery_identity.WORKSPACE_ROOT", self.code_root
        )
        self.identity_root_patch.start()
        self.database = self.root / "state.sqlite3"
        self.connection = sqlite3.connect(self.database)
        self.connection.row_factory = sqlite3.Row
        config = apply_reviewed_current_endpoint_catalog(
            self.connection,
            ROOT,
            operation_key="role-lease-guard-tests",
        )
        self._schema()
        self.endpoints = {
            role: endpoint.endpoint_id for role, endpoint in config.roles.items()
        }
        self.seed("development", ("scripts/allowed.py",))

    def tearDown(self) -> None:
        self.identity_root_patch.stop()
        self.connection.close()
        self.temp.cleanup()

    def _schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE github_current(
                repository TEXT, object_kind TEXT, object_number INTEGER,
                payload_sha256 TEXT
            );
            CREATE TABLE coordination_messages(
                id INTEGER PRIMARY KEY, idempotency_key TEXT,
                recipient_session_id TEXT, topic TEXT, payload_sha256 TEXT,
                payload_json TEXT, state TEXT, claimed_by TEXT
            );
            CREATE TABLE coordination_items(
                repository TEXT, issue_number INTEGER, status TEXT,
                allocation_class TEXT, generation INTEGER,
                accountable_session_id TEXT, lease_manifest_sha256 TEXT,
                source_payload_sha256 TEXT, version INTEGER
            );
            CREATE TABLE coordination_artifacts(
                repository TEXT, issue_number INTEGER, generation INTEGER,
                relative_path TEXT, content_sha256 TEXT, size_bytes INTEGER,
                device_id INTEGER, inode INTEGER, state TEXT
            );
            CREATE TABLE coordination_terminal_watches(
                watch_key TEXT PRIMARY KEY, repository TEXT,
                issue_number INTEGER, generation INTEGER,
                accountable_session_id TEXT, lease_manifest_sha256 TEXT,
                state TEXT
            );
            CREATE TABLE portfolio_readiness_current(
                repository TEXT, issue_number INTEGER, campaign_id INTEGER,
                finalized_candidate_id INTEGER, finalized_event_id INTEGER,
                state TEXT
            );
            CREATE TABLE portfolio_pull_buffer_candidates(
                id INTEGER PRIMARY KEY, state TEXT
            );
            CREATE TABLE portfolio_ready_finalizations(
                repository TEXT, issue_number INTEGER, generation INTEGER,
                campaign_id INTEGER, ready_candidate_id INTEGER,
                dirty_event_id INTEGER, finalization_sha256 TEXT,
                payload_json TEXT
            );
            CREATE TABLE hosted_operations(
                id INTEGER PRIMARY KEY, recipient_session_id TEXT, state TEXT
            );
            """
        )

    def seed(self, role: str, paths: tuple[str, ...]) -> None:
        for table in (
            "executor_attempts", "github_current", "coordination_messages",
            "coordination_items", "coordination_artifacts",
            "portfolio_readiness_current", "portfolio_pull_buffer_candidates",
            "portfolio_ready_finalizations",
        ):
            self.connection.execute(f"DELETE FROM {table}")
        endpoint = self.endpoints[role]
        worktree = self.code_root / f"twinfinityapp-issue-{92 if role == 'development' else 314}"
        worktree.mkdir(mode=0o700, exist_ok=True)
        for path in paths:
            target = worktree / path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_text("original\n", encoding="utf-8")
        issue = 92 if role == "development" else 314
        branch = f"codex/{issue}-role-lease-guard"
        manifest = {
            "repository": REPOSITORY,
            "issue_number": issue,
            "generation": 3,
            "base_sha": BASE_SHA,
            "branch": branch,
            "worktree_path": str(worktree),
            "no_additional_paths": True,
            "paths": [
                {"path": path, "mode": "100644", "type": "blob", "sha": None}
                for path in paths
            ],
        }
        raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        lease = self.root / "lease.json"
        lease.write_bytes(raw)
        metadata = lease.stat()
        digest = hashlib.sha256(raw).hexdigest()
        payload = {
            "source": {
                "repository": REPOSITORY,
                "object_kind": "issue",
                "object_number": issue,
                "payload_sha256": SOURCE_SHA,
            },
            "issue_number": issue,
            "generation": 3,
            "item_version": 1,
            "base_sha": BASE_SHA,
            "branch": branch,
            "worktree_path": str(worktree),
            "opaque_worktree_id": worktree.name,
            "accountable_session_id": endpoint,
            "lease_manifest_sha256": digest,
            "authority_sha256": "2" * 64,
            "capacity": {
                "development_units": 1 if role == "development" else 0,
                "shared_units": 0,
                "sre_units": 1 if role == "sre" else 0,
            },
            "action": "CONTINUE_IMPLEMENTATION_TO_ROUTINE_CLOSEOUT",
        }
        topic = f"{role}.admission"
        admission = {
            "item": {
                "repository": REPOSITORY,
                "issue_number": issue,
                "generation": 3,
                "expected_version": 0,
            },
            "message": {
                "idempotency_key": f"role-lease-guard-{role}-{issue}",
                "recipient_session_id": endpoint,
                "topic": topic,
                "payload": payload,
            },
        }
        identity = bind_delivery_identity(admission)
        identity_sha256 = delivery_identity_sha256(identity)
        finalization = {
            "schema": "twinfinity-kanban-ready-finalization/v2",
            "repository": REPOSITORY,
            "issue_number": issue,
            "generation": 3,
            "delivery_identity": identity,
            "delivery_identity_sha256": identity_sha256,
            "admission_transaction": admission,
            "admission_transaction_sha256": identity[
                "admission_transaction_sha256"
            ],
        }
        self.connection.execute(
            """
            INSERT INTO executor_attempts(
                attempt_id, instance_id, role, endpoint_id, token_sha256,
                target_kind, target_key, state, heartbeat_at, version,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'message', '11', 'RUNNING', ?, 1, ?, ?)
            """,
            (
                ATTEMPT_ID, INSTANCE_ID, role, endpoint,
                hashlib.sha256(TOKEN.encode()).hexdigest(),
                "2026-08-24T10:00:00Z",
                "2026-08-24T10:00:00Z",
                "2026-08-24T10:00:00Z",
            ),
        )
        self.connection.execute(
            "INSERT INTO github_current VALUES (?, 'issue', ?, ?)",
            (REPOSITORY, issue, SOURCE_SHA),
        )
        self.connection.execute(
            "INSERT INTO coordination_messages("
            "id,idempotency_key,recipient_session_id,topic,payload_sha256,"
            "payload_json,state,claimed_by) "
            "VALUES (11, ?, ?, ?, ?, ?, 'PREPARED', NULL)",
            (
                admission["message"]["idempotency_key"],
                endpoint,
                topic,
                digest_json(payload),
                canonical_json(payload),
            ),
        )
        self.connection.execute(
            "INSERT INTO coordination_items VALUES (?, ?, 'ACTIVE_FENCED', "
            "'ACTIVE', 3, ?, ?, ?, 1)",
            (REPOSITORY, issue, endpoint, digest, SOURCE_SHA),
        )
        self.connection.execute(
            "INSERT INTO coordination_artifacts VALUES (?, ?, 3, 'lease.json', "
            "?, ?, ?, ?, 'REGISTERED')",
            (
                REPOSITORY, issue, digest, metadata.st_size, metadata.st_dev,
                metadata.st_ino,
            ),
        )
        self.connection.execute(
            "INSERT INTO portfolio_pull_buffer_candidates VALUES (1, 'READY')"
        )
        self.connection.execute(
            "INSERT INTO portfolio_readiness_current VALUES (?, ?, 1, 1, 1, 'FINALIZED')",
            (REPOSITORY, issue),
        )
        self.connection.execute(
            "INSERT INTO portfolio_ready_finalizations VALUES "
            "(?, ?, 3, 1, 1, 1, ?, ?)",
            (
                REPOSITORY,
                issue,
                digest_json(finalization),
                canonical_json(finalization),
            ),
        )
        self.connection.commit()
        self.role = role
        self.endpoint = endpoint
        self.worktree = worktree

    @property
    def environ(self) -> dict[str, str]:
        return {
            "TWINFINITY_EXECUTOR_ATTEMPT_ID": ATTEMPT_ID,
            "TWINFINITY_EXECUTOR_INSTANCE_ID": INSTANCE_ID,
            "TWINFINITY_EXECUTOR_ROLE": self.role,
            "TWINFINITY_ROLE_ENDPOINT": self.endpoint,
            "TWINFINITY_EXECUTOR_TOKEN": TOKEN,
            "TWINFINITY_EXECUTOR_TARGET_KIND": "message",
            "TWINFINITY_EXECUTOR_TARGET_KEY": "11",
        }

    def event(self, tool: str, tool_input: dict) -> dict:
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
            "cwd": str(self.worktree),
        }

    def decision(self, event: dict, environ: dict[str, str] | None = None) -> dict:
        return pre_tool(
            event,
            environ=environ or self.environ,
            database_path=self.database,
            worktree_root=self.code_root,
        )

    def assert_denied(self, output: dict, reason: str | None = None) -> None:
        specific = output["hookSpecificOutput"]
        self.assertEqual("deny", specific["permissionDecision"])
        if reason is not None:
            self.assertEqual(reason, specific["permissionDecisionReason"])

    def test_role_executor_child_environment_binds_exact_attempt_and_target(self) -> None:
        environment = build_child_environment(
            {"SAFE_PARENT": "present"}, attempt_id=ATTEMPT_ID,
            instance_id=INSTANCE_ID, role="development",
            endpoint_id=self.endpoints["development"], token=TOKEN,
            target_kind="message", target_key="11",
        )
        self.assertEqual("message", environment["TWINFINITY_EXECUTOR_TARGET_KIND"])
        self.assertEqual("11", environment["TWINFINITY_EXECUTOR_TARGET_KEY"])
        self.assertEqual(ATTEMPT_ID, environment["TWINFINITY_EXECUTOR_ATTEMPT_ID"])
        self.assertEqual(TOKEN, environment["TWINFINITY_EXECUTOR_TOKEN"])

    def test_missing_delivery_identity_denies_writer_context(self) -> None:
        row = self.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=11"
        ).fetchone()
        payload = json.loads(row["payload_json"])
        del payload["delivery_identity"]
        self.connection.execute(
            "UPDATE coordination_messages SET payload_json=? WHERE id=11",
            (json.dumps(payload, sort_keys=True),),
        )
        self.connection.commit()

        output = self.decision(
            self.event(
                "apply_patch",
                {
                    "patch": "*** Begin Patch\n*** Update File: "
                    + str(self.worktree / "scripts" / "allowed.py")
                    + "\n@@\n-original\n+changed\n*** End Patch"
                },
            )
        )

        self.assert_denied(output, "DELIVERY_CONTEXT_INVALID")
        self.assertEqual(
            "original\n",
            (self.worktree / "scripts" / "allowed.py").read_text(
                encoding="utf-8"
            ),
        )

    def test_valid_shape_admission_substitution_denies_without_writes(self) -> None:
        row = self.connection.execute(
            "SELECT payload_json FROM coordination_messages WHERE id=11"
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["authority_sha256"] = "f" * 64
        self.connection.execute(
            "UPDATE coordination_messages SET payload_json=?,payload_sha256=? "
            "WHERE id=11",
            (canonical_json(payload), digest_json(payload)),
        )
        self.connection.commit()
        before = (
            self.connection.total_changes,
            tuple(
                self.connection.execute(
                    "SELECT * FROM coordination_messages WHERE id=11"
                ).fetchone()
            ),
            tuple(
                self.connection.execute(
                    "SELECT * FROM coordination_items"
                ).fetchone()
            ),
        )
        output = self.decision(
            self.event(
                "apply_patch",
                {
                    "patch": "*** Begin Patch\n*** Update File: "
                    + str(self.worktree / "scripts" / "allowed.py")
                    + "\n@@\n-original\n+changed\n*** End Patch"
                },
            )
        )
        self.assert_denied(output, "DELIVERY_CONTEXT_INVALID")
        self.assertEqual("original\n", (
            self.worktree / "scripts" / "allowed.py"
        ).read_text(encoding="utf-8"))
        self.assertEqual(
            before,
            (
                self.connection.total_changes,
                tuple(
                    self.connection.execute(
                        "SELECT * FROM coordination_messages WHERE id=11"
                    ).fetchone()
                ),
                tuple(
                    self.connection.execute(
                        "SELECT * FROM coordination_items"
                    ).fetchone()
                ),
            ),
        )

    def test_stale_endpoint_fails_closed_even_for_read_only_operation(self) -> None:
        self.connection.execute(
            "UPDATE executor_role_endpoint_current "
            "SET endpoint_id='role.development.v3', pointer_version=pointer_version+1 "
            "WHERE role='development'"
        )
        self.connection.commit()
        self.assert_denied(
            self.decision(self.event("exec_command", {"cmd": "rg -n guard scripts"})),
            "DELIVERY_CONTEXT_INVALID",
        )

    def test_wrong_role_fails_closed(self) -> None:
        wrong = {**self.environ, "TWINFINITY_EXECUTOR_ROLE": "sre"}
        self.assert_denied(
            self.decision(self.event("exec_command", {"cmd": "rg -n guard scripts"}), wrong)
        )

    def test_terminal_target_fails_closed(self) -> None:
        self.connection.execute(
            "UPDATE coordination_messages SET state='COMPLETE' WHERE id=11"
        )
        self.connection.commit()
        self.assert_denied(
            self.decision(self.event("exec_command", {"cmd": "rg -n guard scripts"}))
        )

    def test_out_of_lease_apply_patch_and_shell_write_are_denied(self) -> None:
        patch_event = self.event(
            "apply_patch",
            {"patch": "*** Begin Patch\n*** Update File: scripts/other.py\n*** End Patch"},
        )
        shell_event = self.event(
            "exec_command",
            {"cmd": "printf x > scripts/other.py", "workdir": str(self.worktree)},
        )
        chained_shell_event = self.event(
            "exec_command",
            {"cmd": "rg -n guard scripts && touch scripts/other.py"},
        )
        for event in (patch_event, shell_event, chained_shell_event):
            with self.subTest(tool=event["tool_name"]):
                self.assert_denied(
                    self.decision(event), "DELIVERY_WRITE_OUTSIDE_EXACT_LEASE"
                )

    def test_nested_literal_apply_patch_is_fenced_to_exact_lease(self) -> None:
        allowed = self.event(
            "functions.exec",
            {"source": "await tools.apply_patch(\"*** Begin Patch\\n*** Update File: scripts/allowed.py\\n*** End Patch\")"},
        )
        denied = self.event(
            "functions.exec",
            {"source": "await tools.apply_patch(\"*** Begin Patch\\n*** Update File: scripts/other.py\\n*** End Patch\")"},
        )
        self.assertEqual({}, self.decision(allowed))
        self.assert_denied(
            self.decision(denied), "DELIVERY_WRITE_OUTSIDE_EXACT_LEASE"
        )

    def test_nested_dynamic_write_inputs_fail_closed(self) -> None:
        template_patch = (
            "await tools.apply_patch(" + chr(96)
            + "*** Begin Patch\\n*** Update File: $" + "{path}\\n*** End Patch"
            + chr(96) + ")"
        )
        for source in (
            "await tools.apply_patch(patch)",
            "await tools.exec_command({cmd: command})",
            template_patch,
            "const op = 'exec_command'; await tools[op]({cmd: 'rg guard'})",
            "const op = tools.exec_command; await op({cmd: 'rg guard'})",
            "const t = tools; await t.exec_command({cmd: 'rg guard'})",
            "await tools.exec_command({cmd: 'rg guard' + suffix})",
            "await tools.exec_command.call(null, {cmd: 'rg guard'})",
            "const t = globalThis['to' + 'ols']; await t.exec_command({cmd: 'rg guard'})",
            "const t = ({}).constructor.constructor('return tools')(); await t.exec_command({cmd: 'rg guard'})",
            "await tools.exec_command({cmd: `rg ${pattern} scripts`})",
        ):
            with self.subTest(source=source):
                self.assert_denied(
                    self.decision(self.event("functions.exec", {"source": source})),
                    "DELIVERY_NESTED_TOOL_INPUT_UNDETERMINED",
                )

    def test_shell_and_interpreter_wrappers_cannot_hide_out_of_lease_writes(self) -> None:
        unsafe = (
            "bash -lc 'printf x > scripts/other.py'",
            "sh -c 'touch scripts/other.py'",
            "env bash -c 'truncate -s 0 scripts/other.py'",
            "command sh -c 'rm scripts/other.py'",
            "timeout 30 bash -c 'printf x > scripts/other.py'",
            "python3 -c 'open(\"scripts/other.py\", \"w\").write(\"x\")'",
            "bash scripts/mutate.sh",
            "python3 scripts/mutate.py",
            "bash -c 'cd /tmp; touch scripts/allowed.py'",
            "bash -c 'install source scripts/other.py'",
            "bash -c 'dd if=/dev/null of=scripts/other.py'",
            "bash -c 'find scripts -type f -delete'",
            "bash -c 'source scripts/mutate.sh'",
        )
        for command in unsafe:
            with self.subTest(command=command):
                self.assert_denied(self.decision(self.event("exec_command", {"cmd": command})))

    def test_literal_wrapped_read_and_in_lease_write_remain_allowed(self) -> None:
        safe = (
            "bash -lc 'rg -n guard scripts'",
            "env command rg -n guard scripts",
            "bash -c 'printf x > scripts/allowed.py'",
            "python3 -c 'open(\"scripts/allowed.py\", \"w\").write(\"x\")'",
        )
        for command in safe:
            with self.subTest(command=command):
                self.assertEqual({}, self.decision(self.event("exec_command", {"cmd": command})))

    def test_wrappers_cannot_hide_provider_raw_push_or_open_wait(self) -> None:
        unsafe = (
            "bash -lc 'gcloud run deploy twinfinity'",
            "env sh -c 'git push origin HEAD'",
            "python3 -c 'import subprocess; subprocess.run([\"git\", \"push\"])'",
            "command bash -c 'while true; do sleep 1; done'",
            "python3 -c 'while True: time.sleep(1)'",
        )
        for command in unsafe:
            with self.subTest(command=command):
                self.assert_denied(self.decision(self.event("exec_command", {"cmd": command})))

    def test_dynamic_shell_executable_and_substitution_fail_closed(self) -> None:
        for command in (
            "$TOOL run deploy twinfinity",
            "g$(printf cloud) run deploy twinfinity",
            "bash -c '$(printf git) push origin HEAD'",
        ):
            with self.subTest(command=command):
                self.assert_denied(self.decision(self.event("exec_command", {"cmd": command})))

    def test_symlinked_lease_path_or_parent_is_rejected(self) -> None:
        allowed = self.worktree / "scripts" / "allowed.py"
        outside = self.root / "outside.py"
        outside.write_text("outside\n", encoding="utf-8")
        allowed.unlink()
        allowed.symlink_to(outside)
        self.assert_denied(
            self.decision(
                self.event(
                    "apply_patch",
                    {"patch": "*** Begin Patch\n*** Update File: scripts/allowed.py\n*** End Patch"},
                )
            ),
            "DELIVERY_WRITE_OUTSIDE_EXACT_LEASE",
        )

    def test_symlinked_worktree_is_rejected(self) -> None:
        moved = self.code_root / "moved-worktree"
        self.worktree.rename(moved)
        self.worktree.symlink_to(moved, target_is_directory=True)
        self.assert_denied(
            self.decision(
                self.event(
                    "apply_patch",
                    {"patch": "*** Begin Patch\n*** Update File: scripts/allowed.py\n*** End Patch"},
                )
            ),
            "DELIVERY_WRITE_OUTSIDE_EXACT_LEASE",
        )

    def test_nested_exec_command_and_tools_are_role_fenced(self) -> None:
        allowed_read = self.event(
            "functions.exec",
            {"source": "await tools.exec_command({cmd: \"rg -n guard scripts\"})"},
        )
        provider = self.event(
            "functions.exec",
            {"source": "await tools.gcloud_deploy({service: \"twinfinity\"})"},
        )
        unknown_mutation = self.event(
            "functions.exec",
            {"source": "await tools.create_remote_resource({name: \"x\"})"},
        )
        disguised_mutation = self.event(
            "functions.exec",
            {"source": "await tools.get_then_delete_resource({name: \"x\"})"},
        )
        self.assertEqual({}, self.decision(allowed_read))
        self.assert_denied(
            self.decision(provider),
            "DEVELOPMENT_HOSTED_PROVIDER_OPERATION_FORBIDDEN",
        )
        self.assert_denied(
            self.decision(unknown_mutation),
            "DELIVERY_NESTED_MUTATION_TOOL_FORBIDDEN",
        )
        self.assert_denied(
            self.decision(disguised_mutation),
            "DELIVERY_NESTED_MUTATION_TOOL_FORBIDDEN",
        )

    def test_nested_read_only_command_may_quote_tools_or_comment_about_tools(self) -> None:
        event = self.event(
            "functions.exec",
            {
                "source": (
                    "// tools aliases are forbidden\n"
                    "await tools.exec_command({cmd: \"rg -n 'tools[op]' scripts\"})"
                )
            },
        )
        self.assertEqual({}, self.decision(event))

    def test_development_provider_operation_is_denied(self) -> None:
        self.assert_denied(
            self.decision(
                self.event("exec_command", {"cmd": "gcloud run deploy twinfinity"})
            ),
            "DEVELOPMENT_HOSTED_PROVIDER_OPERATION_FORBIDDEN",
        )

    def test_sre_unrelated_application_write_is_denied(self) -> None:
        self.seed("sre", (".github/workflows/ci.yml",))
        self.assert_denied(
            self.decision(
                self.event(
                    "apply_patch",
                    {"patch": "*** Begin Patch\n*** Update File: frontend/src/App.tsx\n*** End Patch"},
                )
            ),
            "DELIVERY_WRITE_OUTSIDE_EXACT_LEASE",
        )

    def test_valid_in_lease_patch_shell_write_and_read_only_operation_pass(self) -> None:
        events = (
            self.event(
                "apply_patch",
                {"patch": "*** Begin Patch\n*** Update File: scripts/allowed.py\n*** End Patch"},
            ),
            self.event(
                "exec_command",
                {"cmd": "printf x > scripts/allowed.py", "workdir": str(self.worktree)},
            ),
            self.event(
                "exec_command",
                {"cmd": "rg -n guard /tmp/read-only-outside-worktree"},
            ),
        )
        for event in events:
            with self.subTest(tool=event["tool_name"]):
                self.assertEqual({}, self.decision(event))


if __name__ == "__main__":
    unittest.main()
