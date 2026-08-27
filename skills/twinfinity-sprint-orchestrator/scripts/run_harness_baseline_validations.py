#!/usr/bin/env python3
"""Run the reviewed harness validator and source-control baseline at base SHA."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VALIDATOR_SKILL_ROOTS = (
    "skills/.system/imagegen",
    "skills/.system/openai-docs",
    "skills/.system/plugin-creator",
    "skills/.system/review-agent",
    "skills/.system/skill-creator",
    "skills/.system/skill-installer",
    "skills/twinfinity-development-executor",
    "skills/twinfinity-devops-sre",
    "skills/twinfinity-product-strategist",
    "skills/twinfinity-skill-governor",
    "skills/twinfinity-sprint-orchestrator",
)


def _environment(temp_root: Path) -> dict[str, str]:
    return {
        "HOME": os.fspath(temp_root),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": os.fspath(temp_root),
    }


def _extract_base_tree(base_sha: str, temp_root: Path) -> Path:
    result = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT), "archive", "--format=tar", base_sha],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise SystemExit("PREPUSH_BASELINE_ARCHIVE_FAILED")
    extracted = temp_root / "base-tree"
    extracted.mkdir(mode=0o700)
    archive = temp_root / "base.tar"
    archive.write_bytes(result.stdout)
    with tarfile.open(archive) as bundle:
        bundle.extractall(extracted, filter="data")
    return extracted


def _run(argv: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    result = subprocess.run(argv, cwd=cwd, check=False, env=env)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-sha", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="twinfinity-harness-baseline-") as root:
        temp_root = Path(root)
        env = _environment(temp_root)
        base_tree = _extract_base_tree(args.base_sha, temp_root)
        validator = (
            base_tree
            / "skills"
            / ".system"
            / "skill-creator"
            / "scripts"
            / "quick_validate.py"
        )
        for skill_root in VALIDATOR_SKILL_ROOTS:
            _run(
                [sys.executable, str(validator), str(base_tree / skill_root)],
                cwd=base_tree,
                env=env,
            )
        _run(
            [
                sys.executable,
                str(
                    base_tree
                    / "skills"
                    / "twinfinity-sprint-orchestrator"
                    / "scripts"
                    / "executor_registry.py"
                ),
                "--config",
                str(
                    base_tree
                    / "skills"
                    / "twinfinity-sprint-orchestrator"
                    / "references"
                    / "twinfinity-executor-registry.toml"
                ),
                "--profile-root",
                str(
                    base_tree
                    / "skills"
                    / "twinfinity-sprint-orchestrator"
                    / "references"
                ),
                "audit-config",
            ],
            cwd=base_tree,
            env=env,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
