from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import delivery_guard  # noqa: E402
from delivery_guard import (  # noqa: E402
    CANONICAL_PREPUSH_CONTROL,
    TRUSTED_PREPUSH_INTERPRETER,
    DeliveryContext,
    pre_tool,
)


class DeliveryGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = patch.object(
            delivery_guard,
            "_load_context",
            return_value=DeliveryContext(
                role="development",
                endpoint_id="role.development.v4",
                target_kind="message",
                target_key="1",
                topic="development.admission",
                worktree=Path.cwd(),
                lease_paths=frozenset({Path.cwd() / "docs" / "allowed.md"}),
                repository_writes=True,
            ),
        )
        self.load_context = self.context.start()

    def tearDown(self) -> None:
        self.context.stop()

    def event(self, tool: str, tool_input: dict):
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
        }

    def assert_denied(self, output: dict) -> None:
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"]
        )

    def test_invalid_bound_identity_fails_before_writer_context(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE coordination_messages ("
            "id INTEGER PRIMARY KEY,state TEXT,topic TEXT,"
            "recipient_session_id TEXT,payload_json TEXT)"
        )
        connection.executemany(
            "INSERT INTO coordination_messages VALUES (?,'PREPARED',"
            "'development.admission','role.development.v4',?)",
            (
                (1, json.dumps({"delivery_identity": {"schema": "invalid"}})),
                (2, json.dumps({})),
            ),
        )
        try:
            for message_id in (1, 2):
                with self.subTest(message_id=message_id), self.assertRaisesRegex(
                    delivery_guard.GuardError, "DELIVERY_IDENTITY_INVALID"
                ):
                    delivery_guard._message_context(
                        connection,
                        Path("/tmp/disposable.sqlite3"),
                        role="development",
                        endpoint_id="role.development.v4",
                        target_key=str(message_id),
                        worktree_root=Path("/home/ubuntu/code"),
                    )
        finally:
            connection.close()

    def test_denies_direct_and_code_mode_git_push(self) -> None:
        unsafe = (
            self.event("exec_command", {"cmd": "git push origin HEAD"}),
            self.event("exec_command", {"cmd": "bash -lc 'git push origin HEAD'"}),
            self.event("exec_command", {"cmd": "command git push origin HEAD"}),
            self.event("exec_command", {"cmd": "/bin/git push origin HEAD"}),
            self.event(
                "exec_command",
                {"cmd": "python3 -c 'import subprocess; subprocess.run([\"git\", \"push\", \"origin\", \"HEAD\"])'"},
            ),
            self.event(
                "exec_command",
                {"cmd": "python3 -c 'import subprocess; subprocess.run([\"g\"+\"it\", \"pu\"+\"sh\", \"origin\", \"HEAD\"])'"},
            ),
            self.event(
                "exec_command",
                {"cmd": "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.p GIT_CONFIG_VALUE_0=push git p origin HEAD"},
            ),
            self.event(
                "functions.exec",
                {
                    "source": 'const r = await tools.exec_command({cmd:"git -C /tmp/repo push origin HEAD"});'
                },
            ),
            self.event("shell", {"command": "true && sudo git push origin HEAD"}),
            self.event(
                "exec_command",
                {"cmd": "rg -n pattern docs && git push origin HEAD"},
            ),
        )
        for event in unsafe:
            with self.subTest(event=event):
                self.assert_denied(pre_tool(event))

    def test_allows_guarded_command_and_read_only_mentions(self) -> None:
        self.load_context.return_value = DeliveryContext(
            role="development",
            endpoint_id="role.development.v4",
            target_kind="message",
            target_key="1",
            topic="development.admission",
            worktree=Path.cwd(),
            lease_paths=frozenset({Path.cwd() / "docs" / "allowed.md"}),
            repository_writes=True,
            branch="codex/1-guarded-publication",
            repository="twinfinityai/twinfinityapp",
            owning_issue_number=1,
        )
        safe = (
            self.event(
                "exec_command",
                {
                    "cmd": f"{TRUSTED_PREPUSH_INTERPRETER} {CANONICAL_PREPUSH_CONTROL} guarded-push --repository twinfinityai/twinfinityapp --issue 1"
                },
            ),
            self.event("exec_command", {"cmd": "rg -n 'git push' docs"}),
            self.event("read_file", {"path": "docs/git-push-policy.md"}),
        )
        for event in safe:
            with self.subTest(event=event):
                self.assertEqual({}, pre_tool(event))

    def test_harness_guarded_push_is_bound_to_repository_issue_and_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            worktree = Path(temporary) / "twinfinity-harness-issue-36"
            worktree.mkdir()
            self.load_context.return_value = DeliveryContext(
                role="development",
                endpoint_id="role.development.v4",
                target_kind="message",
                target_key="36",
                topic="development.admission",
                worktree=worktree,
                lease_paths=frozenset({worktree / "docs" / "allowed.md"}),
                repository_writes=True,
                branch="change/36-complete-harness-source-lane",
                repository="jayendusharma/twinfinity-harness",
                owning_issue_number=36,
            )
            exact = (
                f"{TRUSTED_PREPUSH_INTERPRETER} {CANONICAL_PREPUSH_CONTROL} guarded-push "
                "--repository jayendusharma/twinfinity-harness --issue 36"
            )
            self.assertEqual(
                {},
                pre_tool(
                    self.event(
                        "exec_command",
                        {"cmd": exact, "workdir": str(worktree)},
                    )
                ),
            )
            denied = (
                exact.replace("jayendusharma/twinfinity-harness", "twinfinityai/twinfinityapp"),
                exact.replace("--issue 36", "--issue 35"),
                exact.replace(" --issue 36", ""),
            )
            for command in denied:
                with self.subTest(command=command):
                    self.assert_denied(
                        pre_tool(
                            self.event(
                                "exec_command",
                                {"cmd": command, "workdir": str(worktree)},
                            )
                        )
                    )
            self.assert_denied(
                pre_tool(
                    self.event(
                        "exec_command",
                        {"cmd": exact, "workdir": str(worktree.parent)},
                    )
                )
            )

    def test_guarded_push_requires_direct_trusted_interpreter_and_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            worktree = Path(temporary) / "twinfinity-harness-issue36"
            worktree.mkdir()
            self.load_context.return_value = DeliveryContext(
                role="development",
                endpoint_id="role.development.v6",
                target_kind="message",
                target_key="36",
                topic="development.admission",
                worktree=worktree,
                lease_paths=frozenset({worktree / "allowed.py"}),
                repository_writes=True,
                branch="change/36-guarded-push-boundary-repair",
                repository="jayendusharma/twinfinity-harness",
                owning_issue_number=36,
            )
            arguments = (
                f"{CANONICAL_PREPUSH_CONTROL} guarded-push "
                "--repository jayendusharma/twinfinity-harness --issue 36"
            )
            exact = f"{TRUSTED_PREPUSH_INTERPRETER} {arguments}"
            self.assertEqual(
                {},
                pre_tool(
                    self.event(
                        "exec_command",
                        {"cmd": exact, "workdir": str(worktree)},
                    )
                ),
            )
            denied = (
                f"/tmp/python3 {arguments}",
                f"python3 {arguments}",
                str(arguments),
                f"PATH=/tmp {exact}",
                f"PYTHONPATH=/tmp/evil {exact}",
                f"PATH=/tmp PYTHONPATH=/tmp/evil {exact}",
                f"env PATH=/tmp PYTHONPATH=/tmp/evil {exact}",
                f"export PYTHONPATH=/tmp/evil && {exact}",
                f"PATH=/tmp; {exact}",
                f"command {exact}",
                f"exec {exact}",
                f"xargs {TRUSTED_PREPUSH_INTERPRETER} {arguments}",
            )
            for command in denied:
                with self.subTest(command=command):
                    self.assert_denied(
                        pre_tool(
                            self.event(
                                "exec_command",
                                {"cmd": command, "workdir": str(worktree)},
                            )
                        )
                    )

    def test_guarded_push_uses_transferred_owning_issue_not_surface_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            worktree = Path(temporary) / "twinfinityapp-issue-314"
            worktree.mkdir()
            context = DeliveryContext(
                role="sre",
                endpoint_id="role.sre.v6",
                target_kind="terminal_watch",
                target_key="terminal:twinfinityai/twinfinityapp:issue:320:generation:1",
                topic=None,
                worktree=worktree,
                lease_paths=frozenset({worktree / "allowed.py"}),
                repository_writes=True,
                branch="codex/314-ci-hardening",
                repository="twinfinityai/twinfinityapp",
                owning_issue_number=320,
            )
            self.load_context.return_value = context
            prefix = (
                f"{TRUSTED_PREPUSH_INTERPRETER} {CANONICAL_PREPUSH_CONTROL} "
                "guarded-push --repository twinfinityai/twinfinityapp --issue "
            )
            self.assertEqual(
                {},
                pre_tool(
                    self.event(
                        "exec_command",
                        {"cmd": f"{prefix}320", "workdir": str(worktree)},
                    )
                ),
            )
            for owning_issue, command_issue in ((320, 314), (320, 321), (None, 320)):
                with self.subTest(
                    owning_issue=owning_issue,
                    command_issue=command_issue,
                ):
                    self.load_context.return_value = replace(
                        context,
                        owning_issue_number=owning_issue,
                    )
                    self.assert_denied(
                        pre_tool(
                            self.event(
                                "exec_command",
                                {
                                    "cmd": f"{prefix}{command_issue}",
                                    "workdir": str(worktree),
                                },
                            )
                        )
                    )

    def test_exact_admitted_git_metadata_can_reach_auto_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "twinfinityapp"
            worktree = root / "twinfinityapp-issue-328-v3"
            canonical.mkdir()
            branch = "codex/328-evaluation-client-validation-v3"
            base_sha = "a" * 40
            self.load_context.return_value = DeliveryContext(
                role="development",
                endpoint_id="role.development.v6",
                target_kind="terminal_watch",
                target_key="watch-328",
                topic=None,
                worktree=worktree,
                lease_paths=frozenset({worktree / "docs" / "allowed.md"}),
                repository_writes=True,
                canonical_checkout=canonical,
                branch=branch,
                base_sha=base_sha,
                repository="twinfinityai/twinfinityapp",
                owning_issue_number=328,
            )
            escalation = {
                "sandbox_permissions": "require_escalated",
                "justification": "Use only admitted Git metadata",
            }
            add = self.event(
                "exec_command",
                {
                    "cmd": f"git worktree add -b {branch} {worktree} {base_sha}",
                    "workdir": str(canonical),
                    **escalation,
                },
            )
            self.assertEqual({}, pre_tool(add))

            worktree.mkdir()
            (worktree / "docs").mkdir()
            (worktree / "docs" / "allowed.md").touch()
            commit = self.event(
                "exec_command",
                {
                    "cmd": "git commit -m bounded-change",
                    "workdir": str(worktree),
                    **escalation,
                },
            )
            self.assertEqual({}, pre_tool(commit))
            self.assertEqual(
                {},
                pre_tool(
                    self.event(
                        "exec_command",
                        {
                            "cmd": "git add docs/allowed.md",
                            "workdir": str(worktree),
                            **escalation,
                        },
                    )
                ),
            )
            remove = self.event(
                "exec_command",
                {
                    "cmd": f"git worktree remove {worktree}",
                    "workdir": str(canonical),
                    **escalation,
                },
            )
            self.assertEqual({}, pre_tool(remove))

    def test_escalation_stays_inside_exact_git_and_publication_fences(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "twinfinityapp"
            worktree = root / "twinfinityapp-issue-328-v3"
            unrelated = root / "twinfinityapp-issue-999"
            canonical.mkdir()
            worktree.mkdir()
            unrelated.mkdir()
            (worktree / "docs").mkdir()
            (worktree / "docs" / "allowed.md").touch()
            branch = "codex/328-evaluation-client-validation-v3"
            base_sha = "a" * 40
            self.load_context.return_value = DeliveryContext(
                role="development",
                endpoint_id="role.development.v6",
                target_kind="terminal_watch",
                target_key="watch-328",
                topic=None,
                worktree=worktree,
                lease_paths=frozenset({worktree / "docs" / "allowed.md"}),
                repository_writes=True,
                canonical_checkout=canonical,
                branch=branch,
                base_sha=base_sha,
                repository="twinfinityai/twinfinityapp",
                owning_issue_number=328,
            )
            escalation = {
                "sandbox_permissions": "require_escalated",
                "justification": "Use only admitted Git metadata",
            }
            denied = (
                self.event(
                    "exec_command",
                    {
                        "cmd": f"git worktree add -b codex/328-wrong {worktree} {base_sha}",
                        "workdir": str(canonical),
                        **escalation,
                    },
                ),
                self.event(
                    "exec_command",
                    {
                        "cmd": f"git worktree remove {unrelated}",
                        "workdir": str(canonical),
                        **escalation,
                    },
                ),
                self.event(
                    "exec_command",
                    {
                        "cmd": "git commit -m canonical-edit",
                        "workdir": str(canonical),
                        **escalation,
                    },
                ),
                self.event(
                    "exec_command",
                    {
                        "cmd": "git commit -m unrelated-edit",
                        "workdir": str(unrelated),
                        **escalation,
                    },
                ),
                self.event(
                    "exec_command",
                    {
                        "cmd": "git add docs/outside.md",
                        "workdir": str(worktree),
                        **escalation,
                    },
                ),
                self.event(
                    "exec_command",
                    {
                        "cmd": "git commit -a -m broad-commit",
                        "workdir": str(worktree),
                        **escalation,
                    },
                ),
                self.event(
                    "exec_command",
                    {
                        "cmd": "git push origin HEAD",
                        "workdir": str(worktree),
                        **escalation,
                    },
                ),
                self.event(
                    "exec_command",
                    {
                        "cmd": "python3 /opt/prepush_control.py guarded-push --repository x/y --issue 328",
                        "workdir": str(worktree),
                        **escalation,
                    },
                ),
            )
            for event in denied:
                with self.subTest(event=event):
                    self.assert_denied(pre_tool(event))

            guarded = self.event(
                "exec_command",
                {
                    "cmd": f"{TRUSTED_PREPUSH_INTERPRETER} {CANONICAL_PREPUSH_CONTROL} guarded-push --repository twinfinityai/twinfinityapp --issue 328",
                    "workdir": str(worktree),
                    **escalation,
                },
            )
            self.assertEqual({}, pre_tool(guarded))
            self.assertEqual(
                {},
                pre_tool(
                    self.event(
                        "exec_command",
                        {
                            "cmd": "gh pr create --draft",
                            "workdir": str(worktree),
                            **escalation,
                        },
                    )
                ),
            )

    def test_auto_review_closes_git_and_outbound_mutation_routes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "twinfinityapp"
            worktree = root / "twinfinityapp-issue-328-v3"
            unrelated = root / "twinfinityapp-issue-999"
            for path in (canonical, worktree, unrelated):
                path.mkdir()
            (worktree / "docs").mkdir()
            (worktree / "docs" / "allowed.md").touch()
            branch = "codex/328-evaluation-client-validation-v3"
            base_sha = "a" * 40
            self.load_context.return_value = DeliveryContext(
                role="development",
                endpoint_id="role.development.v6",
                target_kind="terminal_watch",
                target_key="watch-328",
                topic=None,
                worktree=worktree,
                lease_paths=frozenset({worktree / "docs" / "allowed.md"}),
                repository_writes=True,
                canonical_checkout=canonical,
                branch=branch,
                base_sha=base_sha,
                repository="twinfinityai/twinfinityapp",
                owning_issue_number=328,
            )
            denied = (
                f"git --git-dir={unrelated}/.git --work-tree={worktree} commit -m redirected",
                f"GIT_DIR={unrelated}/.git git commit -m redirected",
                f"git -C {unrelated} commit -m unrelated",
                f"git -C {worktree} update-ref refs/heads/{branch} {base_sha}",
                "GIT_EXTERNAL_DIFF=/tmp/mutator git diff --ext-diff",
                "git diff --ext-diff",
                "git log --textconv",
                "gh api --method POST repos/twinfinityai/twinfinityapp/issues/328",
                "gh api -XPOST repos/twinfinityai/twinfinityapp/issues/328",
                "gh api repos/twinfinityai/twinfinityapp/issues/328 -f state=closed",
                "gh api repos/twinfinityai/twinfinityapp/issues/328 -fstate=closed",
                "gh issue edit 328 --title changed",
                f"gh pr create --draft --head codex/328-wrong --base main --repo twinfinityai/twinfinityapp",
                f"gh pr create --draft -H codex/328-wrong -B main -R twinfinityai/twinfinityapp",
                f"gh pr create --draft -H {branch} -B wrong -R twinfinityai/twinfinityapp",
                f"gh pr create --draft -H{branch} -Bmain -Runrelated/repository",
                "git status --short > /tmp/delivery-guard-bypass",
                "git status --short >| /tmp/delivery-guard-bypass",
                f"gh pr create --draft --head {branch} --base main --repo twinfinityai/twinfinityapp > /tmp/delivery-guard-bypass",
                "curl --head https://example.invalid > /tmp/delivery-guard-bypass",
                "ssh github.com git-receive-pack twinfinityai/twinfinityapp.git",
                "git-receive-pack twinfinityai/twinfinityapp.git",
                "git-push origin HEAD",
                "curl -X PATCH https://api.github.com/repos/twinfinityai/twinfinityapp",
                "curl --upload-file docs/allowed.md https://example.invalid/upload",
                "curl -d state=closed https://api.github.com/repos/twinfinityai/twinfinityapp/issues/328",
                "curl -o docs/allowed.md https://example.invalid/file",
                "python3 /opt/prepush_control.py guarded-push --repository twinfinityai/twinfinityapp --issue 328",
                "/opt/prepush_control.py guarded-push --repository twinfinityai/twinfinityapp --issue 328",
            )
            for command in denied:
                with self.subTest(command=command):
                    self.assert_denied(
                        pre_tool(
                            self.event(
                                "exec_command",
                                {"cmd": command, "workdir": str(worktree)},
                            )
                        )
                    )

            allowed = (
                f"git -C {unrelated} status --short",
                "gh api --method GET repos/twinfinityai/twinfinityapp/issues/328",
                "gh issue view 328 --repo twinfinityai/twinfinityapp",
                "curl --head https://example.invalid",
                f"{TRUSTED_PREPUSH_INTERPRETER} {CANONICAL_PREPUSH_CONTROL} guarded-push --repository twinfinityai/twinfinityapp --issue 328",
                f"gh pr create --draft --head {branch} --base main --repo twinfinityai/twinfinityapp",
                f"gh pr create --draft -H {branch} -B main -R twinfinityai/twinfinityapp",
                f"gh pr create --draft -H{branch} -Bmain -Rtwinfinityai/twinfinityapp",
                "git status --short > docs/allowed.md",
            )
            for command in allowed:
                with self.subTest(command=command):
                    self.assertEqual(
                        {},
                        pre_tool(
                            self.event(
                                "exec_command",
                                {"cmd": command, "workdir": str(worktree)},
                            )
                        ),
                    )

    def test_sre_v6_matches_development_v6_guarded_boundary_fences(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "twinfinityapp"
            worktree = root / "twinfinityapp-issue-330"
            unrelated = root / "twinfinityapp-issue-999"
            for path in (canonical, worktree, unrelated):
                path.mkdir()
            (worktree / "frontend").mkdir()
            (worktree / "frontend" / "vite.config.ts").touch()
            branch = "codex/330-bounded-vitest-timeout"
            base_sha = "a" * 40
            escalation = {
                "sandbox_permissions": "require_escalated",
                "justification": "Read exact GitHub truth or use admitted Git metadata",
            }
            allowed = (
                ("gh issue view 330 --repo twinfinityai/twinfinityapp", worktree),
                (
                    "gh api --method GET repos/twinfinityai/twinfinityapp/issues/330",
                    worktree,
                ),
                ("git fetch origin main", canonical),
                (
                    f"gh pr create --draft --head {branch} --base main "
                    "--repo twinfinityai/twinfinityapp",
                    worktree,
                ),
            )
            denied = (
                ("gh issue edit 330 --title changed", worktree),
                (
                    "curl -X PATCH "
                    "https://api.github.com/repos/twinfinityai/twinfinityapp",
                    worktree,
                ),
                ("git push origin HEAD", worktree),
                ("git commit -m unrelated", unrelated),
                ("gcloud run services list", worktree),
            )
            for role, endpoint_id in (
                ("development", "role.development.v6"),
                ("sre", "role.sre.v6"),
            ):
                self.load_context.return_value = DeliveryContext(
                    role=role,
                    endpoint_id=endpoint_id,
                    target_kind="message",
                    target_key="1",
                    topic=f"{role}.admission",
                    worktree=worktree,
                    lease_paths=frozenset(
                        {worktree / "frontend" / "vite.config.ts"}
                    ),
                    repository_writes=True,
                    canonical_checkout=canonical,
                    branch=branch,
                    base_sha=base_sha,
                    repository="twinfinityai/twinfinityapp",
                )
                for command, workdir in allowed:
                    with self.subTest(role=role, allowed=command):
                        self.assertEqual(
                            {},
                            pre_tool(
                                self.event(
                                    "exec_command",
                                    {
                                        "cmd": command,
                                        "workdir": str(workdir),
                                        **escalation,
                                    },
                                )
                            ),
                        )
                for command, workdir in denied:
                    with self.subTest(role=role, denied=command):
                        self.assert_denied(
                            pre_tool(
                                self.event(
                                    "exec_command",
                                    {
                                        "cmd": command,
                                        "workdir": str(workdir),
                                        **escalation,
                                    },
                                )
                            )
                        )

    def test_sre_readiness_notice_can_read_github_but_cannot_mutate(self) -> None:
        self.load_context.return_value = DeliveryContext(
            role="sre",
            endpoint_id="role.sre.v6",
            target_kind="message",
            target_key="1",
            topic="coordination.notice",
            worktree=None,
            lease_paths=frozenset(),
            repository_writes=False,
        )
        escalation = {
            "sandbox_permissions": "require_escalated",
            "justification": "Read exact GitHub readiness evidence",
        }
        for command in (
            "gh issue view 330 --repo twinfinityai/twinfinityapp",
            "gh api --method GET repos/twinfinityai/twinfinityapp/issues/330",
        ):
            with self.subTest(allowed=command):
                self.assertEqual(
                    {},
                    pre_tool(
                        self.event(
                            "exec_command", {"cmd": command, **escalation}
                        )
                    ),
                )
        for command in (
            "git fetch origin main",
            "gh issue edit 330 --title changed",
            "gh pr create --draft",
            "gcloud run services list",
            "touch readiness-result.json",
        ):
            with self.subTest(denied=command):
                self.assert_denied(
                    pre_tool(
                        self.event(
                            "exec_command", {"cmd": command, **escalation}
                        )
                    )
                )

    def test_native_delivery_guard_remains_scoped_to_native_controls(self) -> None:
        """The native hook guards delivery flow without disabling role capabilities."""
        native_only = (
            self.event("exec_command", {"cmd": "docker compose ps"}),
            self.event("exec_command", {"cmd": "gh issue view 44"}),
            self.event("exec_command", {"cmd": "curl https://example.invalid"}),
            self.event("exec_command", {"cmd": "d'o'cker compose ps"}),
            self.event("exec_command", {"cmd": "env g'h' issue view 44"}),
            self.event(
                "exec_command", {"cmd": "bash -c \"'c''url' https://example.invalid\""}
            ),
            self.event("exec_command", {"cmd": "npm --prefix frontend ci"}),
            self.event(
                "exec_command",
                {
                    "cmd": "python3 -c 'import requests as r; r.get(\"https://example.invalid\")'"
                },
            ),
        )
        for event in native_only:
            with self.subTest(event=event):
                self.assertEqual({}, pre_tool(event))

    def test_dynamic_shell_executable_fails_closed(self) -> None:
        for command in (
            "d$'o'cker ps",
            "cu$'rl' https://example.invalid",
            "$TOOL status",
            "$(printf git) push origin HEAD",
        ):
            with self.subTest(command=command):
                output = pre_tool(self.event("exec_command", {"cmd": command}))
                self.assert_denied(output)

    def test_read_only_provider_mentions_remain_allowed(self) -> None:
        for command in (
            "rg -n gcloud docs",
            "grep -R 'supabase deploy' docs",
            "bash -lc 'rg -n terraform docs'",
        ):
            with self.subTest(command=command):
                self.assertEqual({}, pre_tool(self.event("exec_command", {"cmd": command})))

    def test_canonical_delivery_guard_bytes_are_unchanged(self) -> None:
        expected = {
            SCRIPTS / "delivery_guard.py":
                "28a03a0f83962f1dfd1addb8fddeeaea52343df4078b89d100ad84803a06a49c",
            SCRIPTS / "delivery_identity.py":
                "463ae0e3409c3105c20d2f33d3278c768edaf46e68ab5351fea7fca0fb9f3efe",
            SCRIPTS / "repository_delivery_policy.py":
                "d2e29d35bee26ef4d343ec845f8b33785cbff7f65a423b9684998dbe8f754ab8",
        }
        for path, digest in expected.items():
            with self.subTest(path=path):
                self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_denies_open_ended_local_and_ci_waits(self) -> None:
        unsafe = (
            self.event(
                "exec_command",
                {
                    "cmd": """input_dir=/tmp/review-input
while [ ! -d \"$input_dir\" ] || [ \"$(find -P \"$input_dir\" -type f | wc -l)\" -eq 0 ]; do
  sleep 10
done"""
                },
            ),
            self.event(
                "exec_command",
                {"cmd": "until test -f /tmp/agent-output; do sleep 10; done"},
            ),
            self.event(
                "exec_command", {"cmd": "until test -f /tmp/agent-output; do :; done"}
            ),
            self.event(
                "exec_command", {"cmd": "while [ ! -f /tmp/input ]; do :; done"}
            ),
            self.event("exec_command", {"cmd": "while true; do sleep 10; done"}),
            self.event("exec_command", {"cmd": "for ((;;)); do sleep 10; done"}),
            self.event("exec_command", {"cmd": "gh run watch 123 --interval 10"}),
            self.event(
                "exec_command",
                {"cmd": "gh --repo twinfinityai/twinfinityapp run watch 123"},
            ),
            self.event(
                "exec_command",
                {
                    "cmd": "python3 -c 'while not ready: time.sleep(10)'"
                },
            ),
            self.event("exec_command", {"cmd": "tail --follow=name /tmp/output"}),
            self.event("exec_command", {"cmd": "journalctl --follow -u service"}),
            self.event("exec_command", {"cmd": "inotifywait --monitor /tmp/input"}),
            self.event("exec_command", {"cmd": "watch -n 10 test -f /tmp/input"}),
            self.event("exec_command", {"cmd": "sleep 61"}),
            self.event("exec_command", {"cmd": "sleep infinity"}),
            self.event(
                "functions.exec",
                {
                    "source": """const r = await tools.exec_command({
  cmd: \"until test -f /tmp/review; do sleep 10; done\"
});"""
                },
            ),
            self.event(
                "exec_command",
                {"cmd": "timeout 60 true; while true; do sleep 10; done"},
            ),
            self.event(
                "exec_command",
                {"cmd": "timeout 61 bash -c 'while true; do sleep 10; done'"},
            ),
        )
        for event in unsafe:
            with self.subTest(event=event):
                output = pre_tool(event)
                self.assert_denied(output)
                self.assertEqual(
                    "OPEN_ENDED_WAIT_FORBIDDEN_USE_SESSION_WAIT_OR_MAX_60S_POLL",
                    output["hookSpecificOutput"]["permissionDecisionReason"],
                )

    def test_allows_one_shot_finite_and_explicitly_bounded_waits(self) -> None:
        safe = (
            self.event("exec_command", {"cmd": "test -d /tmp/input && find /tmp/input"}),
            self.event("exec_command", {"cmd": "sleep 60"}),
            self.event(
                "exec_command",
                {"cmd": "while read -r line; do printf '%s\\n' \"$line\"; done < input"},
            ),
            self.event(
                "exec_command",
                {"cmd": "for attempt in 1 2 3; do sleep 1; test -f /tmp/input && break; done"},
            ),
            self.event(
                "exec_command",
                {"cmd": "timeout 60 bash -c 'while true; do sleep 10; done'"},
            ),
            self.event(
                "exec_command", {"cmd": "/usr/bin/timeout 45s gh run watch 123"}
            ),
            self.event("exec_command", {"cmd": "rg -n 'gh run watch' docs"}),
            self.event(
                "exec_command",
                {"cmd": "grep -R 'while true; do sleep 10; done' docs"},
            ),
        )
        for event in safe:
            with self.subTest(event=event):
                self.assertEqual({}, pre_tool(event))

    def test_malformed_event_fails_closed(self) -> None:
        self.assert_denied(pre_tool({"tool_name": "exec_command"}))


if __name__ == "__main__":
    unittest.main()
