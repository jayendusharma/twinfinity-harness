from __future__ import annotations

from pathlib import Path
import hashlib
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import delivery_guard  # noqa: E402
from delivery_guard import (  # noqa: E402
    CANONICAL_PREPUSH_CONTROL,
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
        safe = (
            self.event(
                "exec_command",
                {
                    "cmd": f"python3 {CANONICAL_PREPUSH_CONTROL} guarded-push --repository x/y --issue 1"
                },
            ),
            self.event("exec_command", {"cmd": "rg -n 'git push' docs"}),
            self.event("read_file", {"path": "docs/git-push-policy.md"}),
        )
        for event in safe:
            with self.subTest(event=event):
                self.assertEqual({}, pre_tool(event))

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
                    "cmd": f"python3 {CANONICAL_PREPUSH_CONTROL} guarded-push --repository x/y --issue 328",
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
                f"python3 {CANONICAL_PREPUSH_CONTROL} guarded-push --repository twinfinityai/twinfinityapp --issue 328",
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
                "28006350055fdd44670d1f96334231eef240eb199e681f6107f65f745c2f579a",
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
