from __future__ import annotations

from pathlib import Path
import hashlib
import sys
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import delivery_guard  # noqa: E402
from delivery_guard import DeliveryContext, pre_tool  # noqa: E402


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
        self.context.start()

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
                    "cmd": "python3 /opt/prepush_control.py guarded-push --repository x/y --issue 1"
                },
            ),
            self.event("exec_command", {"cmd": "rg -n 'git push' docs"}),
            self.event("read_file", {"path": "docs/git-push-policy.md"}),
        )
        for event in safe:
            with self.subTest(event=event):
                self.assertEqual({}, pre_tool(event))

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
                "984be7830e5ffc64fef126d3e018b059ee7507c9ce250d5db0992b9ab152ee35",
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
