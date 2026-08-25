from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

import source_install_atom as atom


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SourceInstallAtomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="source-install-atom-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.source = self.root / "source"
        self.destination = self.root / "destination"
        self.source.mkdir(mode=0o700)
        self.destination.mkdir(mode=0o700)
        (self.source / "new.txt").write_text("new\n", encoding="utf-8")
        (self.source / "second.txt").write_text("second-new\n", encoding="utf-8")
        (self.destination / "installed.txt").write_text("old\n", encoding="utf-8")
        (self.destination / "second-installed.txt").write_text(
            "second-old\n", encoding="utf-8"
        )
        (self.source / "new.txt").chmod(0o600)
        (self.source / "second.txt").chmod(0o600)
        (self.destination / "installed.txt").chmod(0o600)
        (self.destination / "second-installed.txt").chmod(0o600)
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "add", "new.txt", "second.txt"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.source),
                "-c",
                "user.name=Twinfinity Test",
                "-c",
                "user.email=test@twinfinity.invalid",
                "commit",
                "-q",
                "-m",
                "source fixture",
            ],
            check=True,
        )
        self.source_commit = subprocess.run(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest(self, *, two_entries: bool = False) -> dict[str, object]:
        prior = self.destination / "installed.txt"
        source = self.source / "new.txt"
        value: dict[str, object] = {
            "schema": atom.SCHEMA,
            "manifest_sha256": "0" * 64,
            "atom_id": "test-install",
            "source_commit": self.source_commit,
            "entries": [
                {
                    "source_path": "new.txt",
                    "destination_path": "installed.txt",
                    "source_sha256": sha(source),
                    "source_mode": 0o600,
                    "destination_mode": 0o600,
                    "destination_uid": os.getuid(),
                    "destination_gid": os.getgid(),
                    "destination_prior": {
                        "state": "PRESENT",
                        "sha256": sha(prior),
                        "mode": 0o600,
                        "uid": os.getuid(),
                        "gid": os.getgid(),
                    },
                }
            ],
        }
        if two_entries:
            second_source = self.source / "second.txt"
            second_prior = self.destination / "second-installed.txt"
            value["entries"].append(  # type: ignore[union-attr]
                {
                    "source_path": "second.txt",
                    "destination_path": "second-installed.txt",
                    "source_sha256": sha(second_source),
                    "source_mode": 0o600,
                    "destination_mode": 0o600,
                    "destination_uid": os.getuid(),
                    "destination_gid": os.getgid(),
                    "destination_prior": {
                        "state": "PRESENT",
                        "sha256": sha(second_prior),
                        "mode": 0o600,
                        "uid": os.getuid(),
                        "gid": os.getgid(),
                    },
                }
            )
        value["manifest_sha256"] = atom.manifest_digest(value)
        return value

    def test_stage_validate_apply_and_rollback(self) -> None:
        manifest = self.manifest()
        manifest["entries"][0]["destination_mode"] = 0o644  # type: ignore[index]
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]
        stage = self.root / "stage"
        rollback = self.root / "rollback"
        staged = atom.stage_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        self.assertEqual("STAGED", staged["state"])
        validation = atom.validate_stage(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        self.assertEqual("PASS", validation["state"])
        installed = atom.apply_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
            rollback_root=rollback,
            confirmation=f"INSTALL:{manifest['manifest_sha256']}",
        )
        self.assertEqual("INSTALLED", installed["state"])
        self.assertEqual("new\n", (self.destination / "installed.txt").read_text(encoding="utf-8"))
        installed_metadata = (self.destination / "installed.txt").stat()
        self.assertEqual(0o644, stat.S_IMODE(installed_metadata.st_mode))
        self.assertEqual((os.getuid(), os.getgid()), (installed_metadata.st_uid, installed_metadata.st_gid))
        self.assertTrue((rollback / atom.ROLLBACK_RECEIPT).is_file())
        result = atom.rollback_atom(
            manifest=manifest,
            destination_root=self.destination,
            rollback_root=rollback,
            confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
        )
        self.assertEqual("ROLLED_BACK", result["state"])
        self.assertEqual("old\n", (self.destination / "installed.txt").read_text(encoding="utf-8"))
        restored_metadata = (self.destination / "installed.txt").stat()
        self.assertEqual(0o600, stat.S_IMODE(restored_metadata.st_mode))
        self.assertEqual((os.getuid(), os.getgid()), (restored_metadata.st_uid, restored_metadata.st_gid))

    def test_manifest_tamper_prior_mismatch_and_stage_tamper_fail(self) -> None:
        manifest = self.manifest()
        tampered = dict(manifest)
        tampered["atom_id"] = "tampered"
        with self.assertRaisesRegex(atom.SourceInstallAtomError, "INSTALL_ATOM_MANIFEST_INVALID"):
            atom._validate_manifest(tampered)
        (self.destination / "installed.txt").write_text("drift\n", encoding="utf-8")
        with self.assertRaisesRegex(atom.SourceInstallAtomError, "INSTALL_ATOM_PRIOR_HASH_MISMATCH"):
            atom.stage_atom(
                manifest=manifest,
                source_root=self.source,
                destination_root=self.destination,
                stage_root=self.root / "rejected-stage",
            )
        (self.destination / "installed.txt").write_text("old\n", encoding="utf-8")
        stage = self.root / "stage"
        atom.stage_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        (stage / "installed.txt").write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(atom.SourceInstallAtomError, "INSTALL_ATOM_STAGE_VALIDATION_FAILED"):
            atom.validate_stage(
                manifest=manifest,
                source_root=self.source,
                destination_root=self.destination,
                stage_root=stage,
            )

    def test_rollback_receipt_tamper_fails_before_destination_mutation(self) -> None:
        manifest = self.manifest()
        stage = self.root / "stage"
        rollback = self.root / "rollback"
        atom.stage_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        atom.apply_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
            rollback_root=rollback,
            confirmation=f"INSTALL:{manifest['manifest_sha256']}",
        )
        receipt_path = rollback / atom.ROLLBACK_RECEIPT
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["entries"] = []
        receipt_path.write_text(atom.canonical_json(receipt), encoding="utf-8")
        receipt_path.chmod(0o600)
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROLLBACK_DATA_INVALID"
        ):
            atom.rollback_atom(
                manifest=manifest,
                destination_root=self.destination,
                rollback_root=rollback,
                confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
            )
        self.assertEqual(
            "new\n", (self.destination / "installed.txt").read_text(encoding="utf-8")
        )

    def test_destination_parent_symlink_cannot_escape_during_apply(self) -> None:
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        destination_parent = self.destination / "link"
        destination_parent.mkdir(mode=0o700)
        manifest = self.manifest()
        entry = manifest["entries"][0]  # type: ignore[index]
        entry["destination_path"] = "link/escaped.txt"
        entry["destination_prior"] = {"state": "ABSENT"}
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]
        stage = self.root / "stage"
        atom.stage_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        destination_parent.rmdir()
        destination_parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_DIRECTORY_UNSAFE"
        ):
            atom.apply_atom(
                manifest=manifest,  # type: ignore[arg-type]
                source_root=self.source,
                destination_root=self.destination,
                stage_root=stage,
                rollback_root=self.root / "rollback",
                confirmation=f"INSTALL:{manifest['manifest_sha256']}",
            )
        self.assertFalse((outside / "escaped.txt").exists())

    def test_post_replace_exception_restores_just_replaced_entry(self) -> None:
        manifest = self.manifest()
        stage = self.root / "stage"
        rollback = self.root / "rollback"
        atom.stage_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        real_replace = atom.os.replace
        injected = False

        def replace_then_raise(*args, **kwargs):
            nonlocal injected
            result = real_replace(*args, **kwargs)
            if args[1] == "installed.txt" and not injected:
                injected = True
                raise OSError("post-replace injection")
            return result

        with patch.object(atom.os, "replace", side_effect=replace_then_raise):
            with self.assertRaisesRegex(OSError, "post-replace injection"):
                atom.apply_atom(
                    manifest=manifest,
                    source_root=self.source,
                    destination_root=self.destination,
                    stage_root=stage,
                    rollback_root=rollback,
                    confirmation=f"INSTALL:{manifest['manifest_sha256']}",
                )
        self.assertEqual(
            "old\n", (self.destination / "installed.txt").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "ROLLED_BACK",
            json.loads((rollback / atom.ROLLBACK_RECEIPT).read_text())["state"],
        )

    def test_mid_series_and_receipt_update_failures_restore_every_entry(self) -> None:
        for failure_kind in ("mid-series", "receipt-update"):
            with self.subTest(failure_kind=failure_kind):
                manifest = self.manifest(two_entries=True)
                stage = self.root / f"stage-{failure_kind}"
                rollback = self.root / f"rollback-{failure_kind}"
                atom.stage_atom(
                    manifest=manifest,
                    source_root=self.source,
                    destination_root=self.destination,
                    stage_root=stage,
                )
                if failure_kind == "mid-series":
                    real_atomic = atom._atomic_replace_at
                    injected = False

                    def fail_second(root_descriptor, relative, contents, **kwargs):
                        nonlocal injected
                        if relative.as_posix() == "second-installed.txt" and not injected:
                            injected = True
                            raise OSError("mid-series injection")
                        return real_atomic(root_descriptor, relative, contents, **kwargs)

                    context = patch.object(
                        atom, "_atomic_replace_at", side_effect=fail_second
                    )
                    expected = "mid-series injection"
                else:
                    real_receipt = atom._replace_receipt_at
                    injected = False

                    def fail_installed_receipt(descriptor, receipt):
                        nonlocal injected
                        result = real_receipt(descriptor, receipt)
                        if receipt["state"] == "INSTALLED" and not injected:
                            injected = True
                            raise OSError("receipt-update injection")
                        return result

                    context = patch.object(
                        atom, "_replace_receipt_at", side_effect=fail_installed_receipt
                    )
                    expected = "receipt-update injection"
                with context, self.assertRaisesRegex(OSError, expected):
                    atom.apply_atom(
                        manifest=manifest,
                        source_root=self.source,
                        destination_root=self.destination,
                        stage_root=stage,
                        rollback_root=rollback,
                        confirmation=f"INSTALL:{manifest['manifest_sha256']}",
                    )
                self.assertEqual(
                    "old\n",
                    (self.destination / "installed.txt").read_text(encoding="utf-8"),
                )
                self.assertEqual(
                    "second-old\n",
                    (self.destination / "second-installed.txt").read_text(
                        encoding="utf-8"
                    ),
                )

    def test_interrupted_rollback_recovers_from_mixed_filesystem_state(self) -> None:
        manifest = self.manifest(two_entries=True)
        stage = self.root / "stage"
        rollback = self.root / "rollback"
        atom.stage_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        atom.apply_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
            rollback_root=rollback,
            confirmation=f"INSTALL:{manifest['manifest_sha256']}",
        )
        real_replace = atom.os.replace
        injected = False

        def rollback_replace_then_raise(*args, **kwargs):
            nonlocal injected
            result = real_replace(*args, **kwargs)
            if args[1] == "second-installed.txt" and not injected:
                injected = True
                raise OSError("rollback interruption")
            return result

        with patch.object(atom.os, "replace", side_effect=rollback_replace_then_raise):
            with self.assertRaisesRegex(OSError, "rollback interruption"):
                atom.rollback_atom(
                    manifest=manifest,
                    destination_root=self.destination,
                    rollback_root=rollback,
                    confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
                )
        result = atom.rollback_atom(
            manifest=manifest,
            destination_root=self.destination,
            rollback_root=rollback,
            confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
        )
        self.assertEqual("ROLLED_BACK", result["state"])
        self.assertEqual(
            "old\n", (self.destination / "installed.txt").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "second-old\n",
            (self.destination / "second-installed.txt").read_text(encoding="utf-8"),
        )

    def test_source_commit_and_fixed_owner_group_are_enforced(self) -> None:
        manifest = self.manifest()
        manifest["source_commit"] = "f" * 40
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_SOURCE_COMMIT_MISMATCH"
        ):
            atom.stage_atom(
                manifest=manifest,  # type: ignore[arg-type]
                source_root=self.source,
                destination_root=self.destination,
                stage_root=self.root / "commit-rejected",
            )
        manifest = self.manifest()
        manifest["entries"][0]["destination_gid"] = os.getgid() + 1  # type: ignore[index]
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ENTRY_SCHEMA_INVALID"
        ):
            atom._validate_manifest(manifest)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
