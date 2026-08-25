from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

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
        (self.destination / "installed.txt").write_text("old\n", encoding="utf-8")
        (self.source / "new.txt").chmod(0o600)
        (self.destination / "installed.txt").chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest(self) -> dict[str, object]:
        prior = self.destination / "installed.txt"
        source = self.source / "new.txt"
        value: dict[str, object] = {
            "schema": atom.SCHEMA,
            "manifest_sha256": "0" * 64,
            "atom_id": "test-install",
            "source_commit": "a" * 40,
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
        value["manifest_sha256"] = atom.manifest_digest(value)
        return value

    def test_stage_validate_apply_and_rollback(self) -> None:
        manifest = self.manifest()
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
        self.assertTrue((rollback / atom.ROLLBACK_RECEIPT).is_file())
        result = atom.rollback_atom(
            manifest=manifest,
            destination_root=self.destination,
            rollback_root=rollback,
            confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
        )
        self.assertEqual("ROLLED_BACK", result["state"])
        self.assertEqual("old\n", (self.destination / "installed.txt").read_text(encoding="utf-8"))

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


if __name__ == "__main__":
    unittest.main()
