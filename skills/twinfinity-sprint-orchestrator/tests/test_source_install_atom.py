from __future__ import annotations

import hashlib
import itertools
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
        (self.source / "absent.txt").write_text("absent-new\n", encoding="utf-8")
        (self.source / "changed.txt").write_text("changed-new\n", encoding="utf-8")
        (self.source / "equal.txt").write_text("equal\n", encoding="utf-8")
        (self.destination / "installed.txt").write_text("old\n", encoding="utf-8")
        (self.destination / "second-installed.txt").write_text(
            "second-old\n", encoding="utf-8"
        )
        (self.source / "new.txt").chmod(0o600)
        (self.source / "second.txt").chmod(0o600)
        (self.source / "absent.txt").chmod(0o600)
        (self.source / "changed.txt").chmod(0o600)
        (self.source / "equal.txt").chmod(0o600)
        (self.destination / "installed.txt").chmod(0o600)
        (self.destination / "second-installed.txt").chmod(0o600)
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.source),
                "add",
                "new.txt",
                "second.txt",
                "absent.txt",
                "changed.txt",
                "equal.txt",
            ],
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
            "destination_root_identity": atom.destination_root_identity(
                self.destination
            ),
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

    def mixed_manifest(
        self,
        order: tuple[str, ...],
        *,
        destination: Path,
    ) -> dict[str, object]:
        destination.mkdir(mode=0o700)
        (destination / "changed-installed.txt").write_text(
            "changed-old\n", encoding="utf-8"
        )
        (destination / "equal-installed.txt").write_text(
            "equal\n", encoding="utf-8"
        )
        (destination / "changed-installed.txt").chmod(0o600)
        (destination / "equal-installed.txt").chmod(0o600)
        mapping = {
            atom.ABSENT_TO_PRESENT: ("absent.txt", "absent-installed.txt"),
            atom.CHANGED_PRESENT: ("changed.txt", "changed-installed.txt"),
            atom.SOURCE_EQUAL: ("equal.txt", "equal-installed.txt"),
        }
        entries: list[dict[str, object]] = []
        for equivalence in order:
            source_name, destination_name = mapping[equivalence]
            source = self.source / source_name
            target = destination / destination_name
            if equivalence == atom.ABSENT_TO_PRESENT:
                prior: dict[str, object] = {"state": "ABSENT"}
            else:
                prior = {
                    "state": "PRESENT",
                    "sha256": sha(target),
                    "mode": 0o600,
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                }
            entries.append(
                {
                    "source_path": source_name,
                    "destination_path": destination_name,
                    "source_sha256": sha(source),
                    "source_mode": 0o600,
                    "destination_mode": 0o600,
                    "destination_uid": os.getuid(),
                    "destination_gid": os.getgid(),
                    "destination_prior": prior,
                }
            )
        manifest: dict[str, object] = {
            "schema": atom.SCHEMA,
            "manifest_sha256": "0" * 64,
            "atom_id": "mixed-install",
            "source_commit": self.source_commit,
            "destination_root_identity": atom.destination_root_identity(
                destination
            ),
            "entries": entries,
        }
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)
        return manifest

    def assert_mixed_prior(self, destination: Path) -> None:
        self.assertFalse((destination / "absent-installed.txt").exists())
        self.assertEqual(
            "changed-old\n",
            (destination / "changed-installed.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            "equal\n",
            (destination / "equal-installed.txt").read_text(encoding="utf-8"),
        )

    def assert_mixed_installed(self, destination: Path) -> None:
        self.assertEqual(
            "absent-new\n",
            (destination / "absent-installed.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            "changed-new\n",
            (destination / "changed-installed.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            "equal\n",
            (destination / "equal-installed.txt").read_text(encoding="utf-8"),
        )

    def test_three_classes_are_derived_and_bound_without_manifest_attestation(
        self,
    ) -> None:
        order = (
            atom.ABSENT_TO_PRESENT,
            atom.CHANGED_PRESENT,
            atom.SOURCE_EQUAL,
        )
        destination = self.root / "derived-destination"
        manifest = self.mixed_manifest(order, destination=destination)
        self.assertNotIn("install_equivalence", manifest["entries"][0])  # type: ignore[index]
        stage = self.root / "derived-stage"
        staged = atom.stage_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=destination,
            stage_root=stage,
        )
        validated = atom.validate_stage(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=destination,
            stage_root=stage,
        )
        for receipt in (staged, validated):
            self.assertEqual(
                list(order),
                [entry["install_equivalence"] for entry in receipt["entries"]],
            )
            self.assertEqual(receipt["receipt_sha256"], atom.receipt_digest(receipt))
        changed = self.mixed_manifest(
            (atom.SOURCE_EQUAL,),
            destination=self.root / "metadata-destination",
        )
        changed["entries"][0]["destination_mode"] = 0o644  # type: ignore[index]
        changed["manifest_sha256"] = atom.manifest_digest(changed)  # type: ignore[arg-type]
        self.assertEqual(
            atom.CHANGED_PRESENT,
            atom._install_equivalence(changed["entries"][0]),  # type: ignore[index]
        )

    def test_source_equal_has_zero_destination_mutation_or_backup(self) -> None:
        destination = self.root / "equal-destination"
        manifest = self.mixed_manifest(
            (atom.SOURCE_EQUAL,), destination=destination
        )
        target = destination / "equal-installed.txt"
        before = target.stat()
        stage = self.root / "equal-stage"
        rollback = self.root / "equal-rollback"
        atom.stage_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=destination,
            stage_root=stage,
        )
        replaced: list[str] = []
        original_replace = atom._atomic_replace_leaf_at

        def observe_replace(*args: object, **kwargs: object) -> None:
            replaced.append(str(args[1]))
            original_replace(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(atom, "_atomic_replace_leaf_at", side_effect=observe_replace):
            installed = atom.apply_atom(
                manifest=manifest,  # type: ignore[arg-type]
                source_root=self.source,
                destination_root=destination,
                stage_root=stage,
                rollback_root=rollback,
                confirmation=f"INSTALL:{manifest['manifest_sha256']}",
            )
            rolled_back = atom.rollback_atom(
                manifest=manifest,  # type: ignore[arg-type]
                destination_root=destination,
                rollback_root=rollback,
                confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
            )
        after = target.stat()
        self.assertEqual(before.st_ino, after.st_ino)
        self.assertEqual(before.st_mode, after.st_mode)
        self.assertEqual((before.st_uid, before.st_gid), (after.st_uid, after.st_gid))
        self.assertNotIn("equal-installed.txt", replaced)
        self.assertFalse((rollback / "files/equal-installed.txt").exists())
        self.assertEqual(atom.SOURCE_EQUAL, installed["entries"][0]["install_equivalence"])
        self.assertEqual(atom.SOURCE_EQUAL, rolled_back["entries"][0]["install_equivalence"])

    def test_all_six_mixed_orderings_apply_rollback_and_replay(self) -> None:
        classes = (
            atom.ABSENT_TO_PRESENT,
            atom.CHANGED_PRESENT,
            atom.SOURCE_EQUAL,
        )
        for index, order in enumerate(itertools.permutations(classes)):
            with self.subTest(order=order):
                destination = self.root / f"ordering-destination-{index}"
                manifest = self.mixed_manifest(order, destination=destination)
                equal_inode = (destination / "equal-installed.txt").stat().st_ino
                stage = self.root / f"ordering-stage-{index}"
                rollback = self.root / f"ordering-rollback-{index}"
                staged = atom.stage_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    source_root=self.source,
                    destination_root=destination,
                    stage_root=stage,
                )
                installed = atom.apply_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    source_root=self.source,
                    destination_root=destination,
                    stage_root=stage,
                    rollback_root=rollback,
                    confirmation=f"INSTALL:{manifest['manifest_sha256']}",
                )
                self.assert_mixed_installed(destination)
                first = atom.rollback_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    destination_root=destination,
                    rollback_root=rollback,
                    confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
                )
                replay = atom.rollback_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    destination_root=destination,
                    rollback_root=rollback,
                    confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
                )
                durable = json.loads(
                    (rollback / atom.ROLLBACK_RECEIPT).read_text(encoding="utf-8")
                )
                self.assert_mixed_prior(destination)
                self.assertEqual(equal_inode, (destination / "equal-installed.txt").stat().st_ino)
                self.assertEqual(list(order), [entry["install_equivalence"] for entry in staged["entries"]])
                self.assertEqual(list(order), [entry["install_equivalence"] for entry in installed["entries"]])
                self.assertEqual(first, replay)
                self.assertEqual(replay, durable)

    def test_partial_apply_recovers_all_six_mixed_orderings(self) -> None:
        classes = (
            atom.ABSENT_TO_PRESENT,
            atom.CHANGED_PRESENT,
            atom.SOURCE_EQUAL,
        )
        mutable_leaves = {"absent-installed.txt", "changed-installed.txt"}
        for index, order in enumerate(itertools.permutations(classes)):
            with self.subTest(order=order):
                destination = self.root / f"apply-failure-destination-{index}"
                manifest = self.mixed_manifest(order, destination=destination)
                equal_inode = (destination / "equal-installed.txt").stat().st_ino
                stage = self.root / f"apply-failure-stage-{index}"
                rollback = self.root / f"apply-failure-rollback-{index}"
                atom.stage_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    source_root=self.source,
                    destination_root=destination,
                    stage_root=stage,
                )
                original_replace = atom._atomic_replace_leaf_at
                failed = False

                def fail_after_first_effect(*args: object, **kwargs: object) -> None:
                    nonlocal failed
                    original_replace(*args, **kwargs)  # type: ignore[arg-type]
                    if str(args[1]) in mutable_leaves and not failed:
                        failed = True
                        raise RuntimeError("issue-172 apply interruption")

                with patch.object(
                    atom,
                    "_atomic_replace_leaf_at",
                    side_effect=fail_after_first_effect,
                ):
                    with self.assertRaisesRegex(RuntimeError, "apply interruption"):
                        atom.apply_atom(
                            manifest=manifest,  # type: ignore[arg-type]
                            source_root=self.source,
                            destination_root=destination,
                            stage_root=stage,
                            rollback_root=rollback,
                            confirmation=f"INSTALL:{manifest['manifest_sha256']}",
                        )
                self.assertTrue(failed)
                self.assert_mixed_prior(destination)
                self.assertEqual(equal_inode, (destination / "equal-installed.txt").stat().st_ino)
                durable = json.loads(
                    (rollback / atom.ROLLBACK_RECEIPT).read_text(encoding="utf-8")
                )
                self.assertEqual("ROLLED_BACK", durable["state"])
                replay = atom.rollback_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    destination_root=destination,
                    rollback_root=rollback,
                    confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
                )
                self.assertEqual(durable, replay)

    def test_partial_rollback_replays_all_six_mixed_orderings(self) -> None:
        classes = (
            atom.ABSENT_TO_PRESENT,
            atom.CHANGED_PRESENT,
            atom.SOURCE_EQUAL,
        )
        for index, order in enumerate(itertools.permutations(classes)):
            with self.subTest(order=order):
                destination = self.root / f"rollback-failure-destination-{index}"
                manifest = self.mixed_manifest(order, destination=destination)
                equal_inode = (destination / "equal-installed.txt").stat().st_ino
                stage = self.root / f"rollback-failure-stage-{index}"
                rollback = self.root / f"rollback-failure-rollback-{index}"
                atom.stage_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    source_root=self.source,
                    destination_root=destination,
                    stage_root=stage,
                )
                atom.apply_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    source_root=self.source,
                    destination_root=destination,
                    stage_root=stage,
                    rollback_root=rollback,
                    confirmation=f"INSTALL:{manifest['manifest_sha256']}",
                )
                original_replace = atom._atomic_replace_leaf_at
                original_unlink = atom._unlink_regular_leaf_at
                failed = False

                def fail_replace(*args: object, **kwargs: object) -> None:
                    nonlocal failed
                    original_replace(*args, **kwargs)  # type: ignore[arg-type]
                    if str(args[1]) == "changed-installed.txt" and not failed:
                        failed = True
                        raise RuntimeError("issue-172 rollback interruption")

                def fail_unlink(*args: object, **kwargs: object) -> None:
                    nonlocal failed
                    original_unlink(*args, **kwargs)  # type: ignore[arg-type]
                    if str(args[1]) == "absent-installed.txt" and not failed:
                        failed = True
                        raise RuntimeError("issue-172 rollback interruption")

                with (
                    patch.object(atom, "_atomic_replace_leaf_at", side_effect=fail_replace),
                    patch.object(atom, "_unlink_regular_leaf_at", side_effect=fail_unlink),
                ):
                    with self.assertRaisesRegex(RuntimeError, "rollback interruption"):
                        atom.rollback_atom(
                            manifest=manifest,  # type: ignore[arg-type]
                            destination_root=destination,
                            rollback_root=rollback,
                            confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
                        )
                self.assertTrue(failed)
                durable_prepared = json.loads(
                    (rollback / atom.ROLLBACK_RECEIPT).read_text(encoding="utf-8")
                )
                self.assertEqual("PREPARED", durable_prepared["state"])
                recovered = atom.rollback_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    destination_root=destination,
                    rollback_root=rollback,
                    confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
                )
                replay = atom.rollback_atom(
                    manifest=manifest,  # type: ignore[arg-type]
                    destination_root=destination,
                    rollback_root=rollback,
                    confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
                )
                self.assert_mixed_prior(destination)
                self.assertEqual(equal_inode, (destination / "equal-installed.txt").stat().st_ino)
                self.assertEqual("ROLLED_BACK", recovered["state"])
                self.assertEqual(recovered, replay)

    def test_stale_noncanonical_and_impossible_receipts_fail_closed(self) -> None:
        order = (
            atom.ABSENT_TO_PRESENT,
            atom.CHANGED_PRESENT,
            atom.SOURCE_EQUAL,
        )
        destination = self.root / "receipt-destination"
        manifest = self.mixed_manifest(order, destination=destination)
        stage = self.root / "receipt-stage"
        rollback = self.root / "receipt-rollback"
        staged = atom.stage_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=destination,
            stage_root=stage,
        )
        stage_path = stage / atom.STAGE_RECEIPT
        stale_stage = json.loads(atom.canonical_json(staged))
        stale_stage["entries"][0].pop("install_equivalence")
        stale_stage["receipt_sha256"] = atom.receipt_digest(stale_stage)
        stage_path.write_text(atom.canonical_json(stale_stage), encoding="utf-8")
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_STAGE_RECEIPT_INVALID"
        ):
            atom.validate_stage(
                manifest=manifest,  # type: ignore[arg-type]
                source_root=self.source,
                destination_root=destination,
                stage_root=stage,
            )
        stage_path.write_text(atom.canonical_json(staged), encoding="utf-8")
        atom.apply_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=destination,
            stage_root=stage,
            rollback_root=rollback,
            confirmation=f"INSTALL:{manifest['manifest_sha256']}",
        )
        receipt_path = rollback / atom.ROLLBACK_RECEIPT
        accepted = json.loads(receipt_path.read_text(encoding="utf-8"))
        other_root = self.root / "other-root"
        other_root.mkdir(mode=0o700)

        def old_shape(value: dict[str, object]) -> None:
            value.pop("lifecycle")

        def wrong_manifest(value: dict[str, object]) -> None:
            value["manifest_sha256"] = "f" * 64

        def wrong_root(value: dict[str, object]) -> None:
            value["destination_root_identity"] = atom.destination_root_identity(other_root)

        def wrong_order(value: dict[str, object]) -> None:
            value["entries"] = list(reversed(value["entries"]))  # type: ignore[arg-type]

        def wrong_class(value: dict[str, object]) -> None:
            value["entries"][0]["install_equivalence"] = atom.SOURCE_EQUAL  # type: ignore[index]

        def wrong_tuple(value: dict[str, object]) -> None:
            value["entries"][0]["installed_sha256"] = "e" * 64  # type: ignore[index]

        def impossible_transition(value: dict[str, object]) -> None:
            value["lifecycle"]["transition"] = atom.PREPARED_TO_ROLLED_BACK  # type: ignore[index]

        def mismatched_result(value: dict[str, object]) -> None:
            value["lifecycle"]["result_state"] = "ROLLED_BACK"  # type: ignore[index]

        mutations = (
            old_shape,
            wrong_manifest,
            wrong_root,
            wrong_order,
            wrong_class,
            wrong_tuple,
            impossible_transition,
            mismatched_result,
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation.__name__):
                forged = json.loads(atom.canonical_json(accepted))
                mutation(forged)
                forged["receipt_sha256"] = atom.receipt_digest(forged)
                receipt_path.write_text(atom.canonical_json(forged), encoding="utf-8")
                with self.assertRaisesRegex(
                    atom.SourceInstallAtomError,
                    "INSTALL_ATOM_ROLLBACK_DATA_INVALID",
                ):
                    atom.rollback_atom(
                        manifest=manifest,  # type: ignore[arg-type]
                        destination_root=destination,
                        rollback_root=rollback,
                        confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
                    )
                self.assert_mixed_installed(destination)
        receipt_path.write_text(json.dumps(accepted, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROLLBACK_DATA_INVALID"
        ):
            atom.rollback_atom(
                manifest=manifest,  # type: ignore[arg-type]
                destination_root=destination,
                rollback_root=rollback,
                confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
            )
        receipt_path.write_text(atom.canonical_json(accepted), encoding="utf-8")
        receipt_path.write_text(
            atom.canonical_json({**accepted, "receipt_sha256": "0" * 64}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROLLBACK_DATA_INVALID"
        ):
            atom.rollback_atom(
                manifest=manifest,  # type: ignore[arg-type]
                destination_root=destination,
                rollback_root=rollback,
                confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
            )
        receipt_path.write_text(atom.canonical_json(accepted), encoding="utf-8")
        atom.rollback_atom(
            manifest=manifest,  # type: ignore[arg-type]
            destination_root=destination,
            rollback_root=rollback,
            confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
        )
        self.assert_mixed_prior(destination)

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
        self.assertEqual(
            manifest["destination_root_identity"],
            staged["destination_root_identity"],
        )
        validation = atom.validate_stage(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        self.assertEqual("PASS", validation["state"])
        self.assertEqual(
            manifest["destination_root_identity"],
            validation["destination_root_identity"],
        )
        installed = atom.apply_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
            rollback_root=rollback,
            confirmation=f"INSTALL:{manifest['manifest_sha256']}",
        )
        self.assertEqual("INSTALLED", installed["state"])
        self.assertEqual(
            manifest["destination_root_identity"],
            installed["destination_root_identity"],
        )
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
        self.assertEqual(
            manifest["destination_root_identity"],
            result["destination_root_identity"],
        )
        self.assertEqual("old\n", (self.destination / "installed.txt").read_text(encoding="utf-8"))
        restored_metadata = (self.destination / "installed.txt").stat()
        self.assertEqual(0o600, stat.S_IMODE(restored_metadata.st_mode))
        self.assertEqual((os.getuid(), os.getgid()), (restored_metadata.st_uid, restored_metadata.st_gid))

        receipts = (
            staged,
            validation,
            installed,
            json.loads((rollback / atom.ROLLBACK_RECEIPT).read_text()),
            result,
        )
        for receipt in receipts:
            self.assertEqual(
                manifest["destination_root_identity"],
                receipt["destination_root_identity"],
            )
            self.assertEqual(receipt["receipt_sha256"], atom.receipt_digest(receipt))
            self.assertNotIn(str(self.destination), atom.canonical_json(receipt))

    def test_identical_source_fanout_stages_applies_and_rolls_back_each_destination(
        self,
    ) -> None:
        manifest = self.manifest(two_entries=True)
        first, second = manifest["entries"]  # type: ignore[misc]
        for key in ("source_path", "source_sha256", "source_mode"):
            second[key] = first[key]
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]

        stage = self.root / "fanout-stage"
        rollback = self.root / "fanout-rollback"
        staged = atom.stage_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        validation = atom.validate_stage(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        installed = atom.apply_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
            rollback_root=rollback,
            confirmation=f"INSTALL:{manifest['manifest_sha256']}",
        )

        self.assertEqual("STAGED", staged["state"])
        self.assertEqual("PASS", validation["state"])
        self.assertEqual("INSTALLED", installed["state"])
        self.assertEqual(
            ["installed.txt", "second-installed.txt"],
            [entry["destination_path"] for entry in installed["entries"]],
        )
        self.assertEqual(
            ["new\n", "new\n"],
            [
                (self.destination / "installed.txt").read_text(encoding="utf-8"),
                (self.destination / "second-installed.txt").read_text(
                    encoding="utf-8"
                ),
            ],
        )

        rolled_back = atom.rollback_atom(
            manifest=manifest,  # type: ignore[arg-type]
            destination_root=self.destination,
            rollback_root=rollback,
            confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
        )
        self.assertEqual("ROLLED_BACK", rolled_back["state"])
        self.assertEqual(
            ["old\n", "second-old\n"],
            [
                (self.destination / "installed.txt").read_text(encoding="utf-8"),
                (self.destination / "second-installed.txt").read_text(
                    encoding="utf-8"
                ),
            ],
        )
        for receipt in (staged, validation, installed, rolled_back):
            self.assertEqual(receipt["receipt_sha256"], atom.receipt_digest(receipt))

    def test_conflicting_repeated_source_binding_fails_before_stage_creation(
        self,
    ) -> None:
        for field, conflicting_value in (
            ("source_sha256", "0" * 64),
            ("source_mode", 0o644),
        ):
            with self.subTest(field=field):
                manifest = self.manifest(two_entries=True)
                first, second = manifest["entries"]  # type: ignore[misc]
                for key in ("source_path", "source_sha256", "source_mode"):
                    second[key] = first[key]
                second[field] = conflicting_value
                manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]
                stage = self.root / f"conflicting-{field}-stage"

                with self.assertRaisesRegex(
                    atom.SourceInstallAtomError,
                    "INSTALL_ATOM_ENTRY_SCHEMA_INVALID",
                ):
                    atom.stage_atom(
                        manifest=manifest,  # type: ignore[arg-type]
                        source_root=self.source,
                        destination_root=self.destination,
                        stage_root=stage,
                    )

                self.assertFalse(stage.exists())
                self.assertEqual(
                    "old\n",
                    (self.destination / "installed.txt").read_text(
                        encoding="utf-8"
                    ),
                )
                self.assertEqual(
                    "second-old\n",
                    (self.destination / "second-installed.txt").read_text(
                        encoding="utf-8"
                    ),
                )

    def test_duplicate_destination_stays_rejected_before_stage_creation(
        self,
    ) -> None:
        manifest = self.manifest(two_entries=True)
        first, second = manifest["entries"]  # type: ignore[misc]
        for key in ("source_path", "source_sha256", "source_mode"):
            second[key] = first[key]
        second["destination_path"] = first["destination_path"]
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]
        stage = self.root / "duplicate-destination-stage"

        with self.assertRaisesRegex(
            atom.SourceInstallAtomError,
            "INSTALL_ATOM_ENTRY_SCHEMA_INVALID",
        ):
            atom.stage_atom(
                manifest=manifest,  # type: ignore[arg-type]
                source_root=self.source,
                destination_root=self.destination,
                stage_root=stage,
            )

        self.assertFalse(stage.exists())
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

    def test_root_identity_is_versioned_opaque_and_stable_across_root_contents(
        self,
    ) -> None:
        identity = atom.destination_root_identity(self.destination)
        self.assertEqual(
            atom.DESTINATION_ROOT_IDENTITY_SCHEMA, identity["schema"]
        )
        self.assertEqual(
            {
                "schema",
                "canonical_path_sha256",
                "filesystem_identity_sha256",
                "identity_sha256",
            },
            set(identity),
        )
        self.assertNotIn(str(self.destination), atom.canonical_json(identity))
        nested = self.destination / "nested"
        nested.mkdir(mode=0o700)
        (nested / "new-leaf").write_text("contents\n", encoding="utf-8")
        self.assertEqual(identity, atom.destination_root_identity(self.destination))

    def test_digest_command_derives_identity_from_the_exact_root(self) -> None:
        manifest = self.manifest()
        manifest.pop("destination_root_identity")
        manifest_path = self.root / "manifest-without-root-identity.json"
        manifest_path.write_text(atom.canonical_json(manifest), encoding="utf-8")
        manifest_path.chmod(0o600)
        result = subprocess.run(
            [
                sys.executable,
                str(SKILL_ROOT / "scripts/source_install_atom.py"),
                "digest",
                "--manifest",
                str(manifest_path),
                "--destination-root",
                str(self.destination),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        receipt = json.loads(result.stdout)
        expected_identity = atom.destination_root_identity(self.destination)
        candidate = dict(manifest)
        candidate["destination_root_identity"] = expected_identity
        self.assertEqual(expected_identity, receipt["destination_root_identity"])
        self.assertEqual(atom.manifest_digest(candidate), receipt["manifest_sha256"])
        self.assertNotIn(str(self.destination), result.stdout)

    def test_schema_v2_sealing_workflow_writes_an_accepted_manifest_and_rejects_v1(
        self,
    ) -> None:
        manifest = self.manifest()
        template = {
            key: value
            for key, value in manifest.items()
            if key not in {"destination_root_identity", "manifest_sha256"}
        }
        template_path = self.root / "reviewed-v2-template.json"
        template_path.write_text(
            atom.canonical_json(template), encoding="utf-8"
        )
        template_path.chmod(0o600)
        sealed_path = self.root / "sealed-v2-manifest.json"

        result = subprocess.run(
            [
                sys.executable,
                str(SKILL_ROOT / "scripts/source_install_atom.py"),
                "seal-manifest",
                "--manifest",
                str(template_path),
                "--destination-root",
                str(self.destination),
                "--output",
                str(sealed_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
        atom._validate_manifest(sealed)
        receipt = json.loads(result.stdout)
        self.assertEqual(atom.SCHEMA, sealed["schema"])
        self.assertEqual(
            atom.destination_root_identity(self.destination),
            sealed["destination_root_identity"],
        )
        self.assertEqual(atom.manifest_digest(sealed), sealed["manifest_sha256"])
        self.assertEqual(sealed["manifest_sha256"], receipt["manifest_sha256"])
        self.assertEqual("SEALED", receipt["state"])
        self.assertEqual(receipt["receipt_sha256"], atom.receipt_digest(receipt))
        self.assertEqual(0o600, stat.S_IMODE(sealed_path.stat().st_mode))
        self.assertNotIn(str(self.destination), result.stdout)

        legacy = dict(template)
        legacy["schema"] = "twinfinity-source-install-atom/v1"
        legacy_path = self.root / "substituted-v1-template.json"
        legacy_path.write_text(atom.canonical_json(legacy), encoding="utf-8")
        legacy_path.chmod(0o600)
        rejected_output = self.root / "rejected-v1-manifest.json"
        rejected = subprocess.run(
            [
                sys.executable,
                str(SKILL_ROOT / "scripts/source_install_atom.py"),
                "seal-manifest",
                "--manifest",
                str(legacy_path),
                "--destination-root",
                str(self.destination),
                "--output",
                str(rejected_output),
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("INSTALL_ATOM_MANIFEST_SCHEMA_INVALID", rejected.stderr)
        self.assertFalse(rejected_output.exists())

    def test_shadow_alias_noncanonical_and_replaced_roots_fail_before_effect(
        self,
    ) -> None:
        manifest = self.manifest()

        shadow = self.root / "shadow"
        shadow.mkdir(mode=0o700)
        (shadow / "installed.txt").write_text("old\n", encoding="utf-8")
        (shadow / "installed.txt").chmod(0o600)
        shadow_stage = self.root / "shadow-stage"
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROOT_IDENTITY_MISMATCH"
        ):
            atom.stage_atom(
                manifest=manifest,
                source_root=self.source,
                destination_root=shadow,
                stage_root=shadow_stage,
            )
        self.assertFalse(shadow_stage.exists())

        alias = self.root / "destination-alias"
        alias.symlink_to(self.destination, target_is_directory=True)
        alias_stage = self.root / "alias-stage"
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROOT_INVALID"
        ):
            atom.stage_atom(
                manifest=manifest,
                source_root=self.source,
                destination_root=alias,
                stage_root=alias_stage,
            )
        self.assertFalse(alias_stage.exists())

        spelling = self.root / "spelling"
        spelling.mkdir(mode=0o700)
        alternate = spelling / ".." / "destination"
        alternate_stage = self.root / "alternate-stage"
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROOT_NONCANONICAL"
        ):
            atom.stage_atom(
                manifest=manifest,
                source_root=self.source,
                destination_root=alternate,
                stage_root=alternate_stage,
            )
        self.assertFalse(alternate_stage.exists())

        original = self.root / "destination-original"
        os.replace(self.destination, original)
        self.destination.mkdir(mode=0o700)
        (self.destination / "installed.txt").write_text("old\n", encoding="utf-8")
        (self.destination / "installed.txt").chmod(0o600)
        replacement_stage = self.root / "replacement-stage"
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROOT_IDENTITY_MISMATCH"
        ):
            atom.stage_atom(
                manifest=manifest,
                source_root=self.source,
                destination_root=self.destination,
                stage_root=replacement_stage,
            )
        self.assertFalse(replacement_stage.exists())
        self.assertEqual("old\n", (self.destination / "installed.txt").read_text())

    def test_missing_schema_substitution_and_manifest_rebinding_fail_closed(
        self,
    ) -> None:
        manifest = self.manifest()
        missing = dict(manifest)
        missing.pop("destination_root_identity")
        missing["manifest_sha256"] = atom.manifest_digest(missing)
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_MANIFEST_SCHEMA_INVALID"
        ):
            atom._validate_manifest(missing)

        legacy = dict(manifest)
        legacy["schema"] = "twinfinity-source-install-atom/v1"
        legacy["manifest_sha256"] = atom.manifest_digest(legacy)
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_MANIFEST_INVALID"
        ):
            atom._validate_manifest(legacy)

        substituted_identity = dict(manifest)
        root_identity = dict(manifest["destination_root_identity"])  # type: ignore[arg-type]
        root_identity["schema"] = "twinfinity-destination-root-identity/v2"
        root_identity["identity_sha256"] = atom.digest_json(
            {
                "schema": root_identity["schema"],
                "canonical_path_sha256": root_identity[
                    "canonical_path_sha256"
                ],
                "filesystem_identity_sha256": root_identity[
                    "filesystem_identity_sha256"
                ],
            }
        )
        substituted_identity["destination_root_identity"] = root_identity
        substituted_identity["manifest_sha256"] = atom.manifest_digest(
            substituted_identity
        )
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError,
            "INSTALL_ATOM_ROOT_IDENTITY_INVALID",
        ):
            atom._validate_manifest(substituted_identity)

        shadow = self.root / "rebound-shadow"
        shadow.mkdir(mode=0o700)
        (shadow / "installed.txt").write_text("old\n", encoding="utf-8")
        (shadow / "installed.txt").chmod(0o600)
        rebound = dict(manifest)
        rebound["destination_root_identity"] = atom.destination_root_identity(
            shadow
        )
        rebound["manifest_sha256"] = atom.manifest_digest(rebound)
        rebound_stage = self.root / "rebound-stage"
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROOT_IDENTITY_MISMATCH"
        ):
            atom.stage_atom(
                manifest=rebound,
                source_root=self.source,
                destination_root=self.destination,
                stage_root=rebound_stage,
            )
        self.assertFalse(rebound_stage.exists())

    def test_stage_receipt_digest_rebinding_cannot_change_root_identity(self) -> None:
        manifest = self.manifest()
        stage = self.root / "stage-rebinding"
        atom.stage_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        shadow = self.root / "receipt-shadow"
        shadow.mkdir(mode=0o700)
        receipt_path = stage / atom.STAGE_RECEIPT
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["destination_root_identity"] = atom.destination_root_identity(
            shadow
        )
        receipt["receipt_sha256"] = atom.receipt_digest(receipt)
        receipt_path.write_text(atom.canonical_json(receipt), encoding="utf-8")
        receipt_path.chmod(0o600)
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_STAGE_RECEIPT_INVALID"
        ):
            atom.validate_stage(
                manifest=manifest,
                source_root=self.source,
                destination_root=self.destination,
                stage_root=stage,
            )

        missing_stage = self.root / "stage-missing-root-binding"
        atom.stage_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=missing_stage,
        )
        missing_path = missing_stage / atom.STAGE_RECEIPT
        missing_receipt = json.loads(missing_path.read_text(encoding="utf-8"))
        missing_receipt.pop("destination_root_identity")
        missing_receipt["receipt_sha256"] = atom.receipt_digest(missing_receipt)
        missing_path.write_text(
            atom.canonical_json(missing_receipt), encoding="utf-8"
        )
        missing_path.chmod(0o600)
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_STAGE_RECEIPT_INVALID"
        ):
            atom.validate_stage(
                manifest=manifest,
                source_root=self.source,
                destination_root=self.destination,
                stage_root=missing_stage,
            )

    def test_root_swap_during_stage_receipt_write_leaves_no_staged_claim(
        self,
    ) -> None:
        manifest = self.manifest()
        stage = self.root / "stage-receipt-root-race"
        displaced = self.root / "stage-bound-root-displaced"
        real_write = atom._write_file_exclusive
        swapped = False

        def write_then_swap(path, contents, mode):
            nonlocal swapped
            result = real_write(path, contents, mode)
            if path.name == atom.STAGE_RECEIPT and not swapped:
                swapped = True
                os.replace(self.destination, displaced)
                self.destination.mkdir(mode=0o700)
            return result

        with patch.object(
            atom, "_write_file_exclusive", side_effect=write_then_swap
        ), self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROOT_IDENTITY_MISMATCH"
        ):
            atom.stage_atom(
                manifest=manifest,
                source_root=self.source,
                destination_root=self.destination,
                stage_root=stage,
            )
        self.assertTrue(swapped)
        self.assertFalse(stage.exists())
        self.assertFalse((stage / atom.STAGE_RECEIPT).exists())
        self.assertEqual("old\n", (displaced / "installed.txt").read_text())
        self.assertFalse((self.destination / "installed.txt").exists())

    def test_prepared_recovery_and_terminal_receipts_preserve_root_identity(
        self,
    ) -> None:
        manifest = self.manifest()
        stage = self.root / "stage-prepared"
        rollback = self.root / "rollback-prepared"
        atom.stage_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        with patch.object(
            atom,
            "_atomic_replace_leaf_at",
            side_effect=OSError("before first destination effect"),
        ), patch.object(
            atom,
            "_recover_entries",
            side_effect=atom.SourceInstallAtomError("recovery handoff"),
        ), self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_RECOVERY_REQUIRED"
        ):
            atom.apply_atom(
                manifest=manifest,
                source_root=self.source,
                destination_root=self.destination,
                stage_root=stage,
                rollback_root=rollback,
                confirmation=f"INSTALL:{manifest['manifest_sha256']}",
            )
        prepared = json.loads(
            (rollback / atom.ROLLBACK_RECEIPT).read_text(encoding="utf-8")
        )
        self.assertEqual("PREPARED", prepared["state"])
        self.assertEqual(
            manifest["destination_root_identity"],
            prepared["destination_root_identity"],
        )
        self.assertEqual(
            prepared["receipt_sha256"], atom.receipt_digest(prepared)
        )
        self.assertNotIn(str(self.destination), atom.canonical_json(prepared))
        self.assertEqual("old\n", (self.destination / "installed.txt").read_text())

        terminal = atom.rollback_atom(
            manifest=manifest,
            destination_root=self.destination,
            rollback_root=rollback,
            confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
        )
        recovered = json.loads(
            (rollback / atom.ROLLBACK_RECEIPT).read_text(encoding="utf-8")
        )
        for receipt in (recovered, terminal):
            self.assertEqual("ROLLED_BACK", receipt["state"])
            self.assertEqual(
                manifest["destination_root_identity"],
                receipt["destination_root_identity"],
            )
            self.assertEqual(
                receipt["receipt_sha256"], atom.receipt_digest(receipt)
            )
            self.assertNotIn(str(self.destination), atom.canonical_json(receipt))

    def test_lifecycle_receipt_digest_rebinding_fails_before_rollback(self) -> None:
        manifest = self.manifest()
        stage = self.root / "stage-lifecycle-rebinding"
        rollback = self.root / "rollback-lifecycle-rebinding"
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
        shadow = self.root / "lifecycle-rebinding-shadow"
        shadow.mkdir(mode=0o700)
        receipt_path = rollback / atom.ROLLBACK_RECEIPT
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["destination_root_identity"] = atom.destination_root_identity(
            shadow
        )
        receipt["receipt_sha256"] = atom.receipt_digest(receipt)
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
        self.assertEqual("new\n", (self.destination / "installed.txt").read_text())

        receipt.pop("destination_root_identity")
        receipt["receipt_sha256"] = atom.receipt_digest(receipt)
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
        self.assertEqual("new\n", (self.destination / "installed.txt").read_text())

    def test_root_replacement_after_stage_blocks_apply_before_effect(self) -> None:
        manifest = self.manifest()
        stage = self.root / "stage-before-replacement"
        atom.stage_atom(
            manifest=manifest,
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        bound = self.root / "bound-destination"
        os.replace(self.destination, bound)
        self.destination.mkdir(mode=0o700)
        (self.destination / "installed.txt").write_text("old\n", encoding="utf-8")
        (self.destination / "installed.txt").chmod(0o600)
        rollback = self.root / "replacement-rollback"
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROOT_IDENTITY_MISMATCH"
        ):
            atom.apply_atom(
                manifest=manifest,
                source_root=self.source,
                destination_root=self.destination,
                stage_root=stage,
                rollback_root=rollback,
                confirmation=f"INSTALL:{manifest['manifest_sha256']}",
            )
        self.assertFalse(rollback.exists())
        self.assertEqual("old\n", (bound / "installed.txt").read_text())
        self.assertEqual("old\n", (self.destination / "installed.txt").read_text())

    def test_rollback_replay_refuses_complete_shadow_root(self) -> None:
        manifest = self.manifest()
        stage = self.root / "stage-shadow-rollback"
        rollback = self.root / "rollback-shadow-rollback"
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
        shadow = self.root / "rollback-shadow"
        shadow.mkdir(mode=0o700)
        (shadow / "installed.txt").write_text("new\n", encoding="utf-8")
        (shadow / "installed.txt").chmod(0o600)
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError, "INSTALL_ATOM_ROOT_IDENTITY_MISMATCH"
        ):
            atom.rollback_atom(
                manifest=manifest,
                destination_root=shadow,
                rollback_root=rollback,
                confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
            )
        self.assertEqual("new\n", (shadow / "installed.txt").read_text())
        self.assertEqual(
            "new\n", (self.destination / "installed.txt").read_text()
        )

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
                    real_atomic = atom._atomic_replace_leaf_at
                    injected = False

                    def fail_second(parent_descriptor, leaf, contents, **kwargs):
                        nonlocal injected
                        if leaf == "second-installed.txt" and not injected:
                            injected = True
                            raise OSError("mid-series injection")
                        return real_atomic(
                            parent_descriptor, leaf, contents, **kwargs
                        )

                    context = patch.object(
                        atom, "_atomic_replace_leaf_at", side_effect=fail_second
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

    def test_nested_parent_substitution_fails_and_recovers_held_tree(self) -> None:
        manifest = self.manifest(two_entries=True)
        nested = self.destination / "nested"
        nested.mkdir(mode=0o700)
        os.replace(self.destination / "installed.txt", nested / "installed.txt")
        os.replace(
            self.destination / "second-installed.txt",
            nested / "second-installed.txt",
        )
        manifest["entries"][0]["destination_path"] = "nested/installed.txt"  # type: ignore[index]
        manifest["entries"][1]["destination_path"] = "nested/second-installed.txt"  # type: ignore[index]
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]
        stage = self.root / "stage-parent-race"
        rollback = self.root / "rollback-parent-race"
        atom.stage_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        displaced = self.destination / "nested-displaced"
        real_atomic = atom._atomic_replace_leaf_at
        substituted = False

        def substitute_after_first(parent_descriptor, leaf, contents, **kwargs):
            nonlocal substituted
            result = real_atomic(parent_descriptor, leaf, contents, **kwargs)
            if leaf == "installed.txt" and not substituted:
                substituted = True
                os.replace(nested, displaced)
                nested.mkdir(mode=0o700)
                (nested / "installed.txt").write_text(
                    "substitute-first\n", encoding="utf-8"
                )
                (nested / "second-installed.txt").write_text(
                    "substitute-second\n", encoding="utf-8"
                )
                (nested / "installed.txt").chmod(0o600)
                (nested / "second-installed.txt").chmod(0o600)
            return result

        with patch.object(
            atom,
            "_atomic_replace_leaf_at",
            side_effect=substitute_after_first,
        ), self.assertRaisesRegex(
            atom.SourceInstallAtomError,
            "INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT",
        ):
            atom.apply_atom(
                manifest=manifest,  # type: ignore[arg-type]
                source_root=self.source,
                destination_root=self.destination,
                stage_root=stage,
                rollback_root=rollback,
                confirmation=f"INSTALL:{manifest['manifest_sha256']}",
            )
        self.assertEqual(
            "old\n", (displaced / "installed.txt").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "second-old\n",
            (displaced / "second-installed.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            "substitute-first\n",
            (nested / "installed.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            "ROLLED_BACK",
            json.loads((rollback / atom.ROLLBACK_RECEIPT).read_text())["state"],
        )

    def test_multi_parent_post_replace_failure_rolls_back_every_entry(self) -> None:
        manifest = self.manifest(two_entries=True)
        first_parent = self.destination / "first-parent"
        second_parent = self.destination / "second-parent"
        first_parent.mkdir(mode=0o700)
        second_parent.mkdir(mode=0o700)
        os.replace(
            self.destination / "installed.txt", first_parent / "installed.txt"
        )
        os.replace(
            self.destination / "second-installed.txt",
            second_parent / "second-installed.txt",
        )
        manifest["entries"][0]["destination_path"] = "first-parent/installed.txt"  # type: ignore[index]
        manifest["entries"][1]["destination_path"] = "second-parent/second-installed.txt"  # type: ignore[index]
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]
        stage = self.root / "stage-multi-parent"
        rollback = self.root / "rollback-multi-parent"
        atom.stage_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        real_atomic = atom._atomic_replace_leaf_at
        injected = False

        def replace_second_then_fail(parent_descriptor, leaf, contents, **kwargs):
            nonlocal injected
            result = real_atomic(parent_descriptor, leaf, contents, **kwargs)
            if leaf == "second-installed.txt" and not injected:
                injected = True
                raise OSError("multi-parent post-replace injection")
            return result

        with patch.object(
            atom,
            "_atomic_replace_leaf_at",
            side_effect=replace_second_then_fail,
        ), self.assertRaisesRegex(OSError, "multi-parent post-replace injection"):
            atom.apply_atom(
                manifest=manifest,  # type: ignore[arg-type]
                source_root=self.source,
                destination_root=self.destination,
                stage_root=stage,
                rollback_root=rollback,
                confirmation=f"INSTALL:{manifest['manifest_sha256']}",
            )
        self.assertEqual(
            "old\n", (first_parent / "installed.txt").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "second-old\n",
            (second_parent / "second-installed.txt").read_text(encoding="utf-8"),
        )
        receipt = json.loads((rollback / atom.ROLLBACK_RECEIPT).read_text())
        self.assertEqual("ROLLED_BACK", receipt["state"])
        self.assertTrue(
            all(
                entry["destination_parent_identity"]
                for entry in receipt["entries"]
            )
        )

    def test_later_rollback_refuses_nested_parent_identity_substitution(self) -> None:
        manifest = self.manifest()
        nested = self.destination / "nested-later"
        nested.mkdir(mode=0o700)
        os.replace(self.destination / "installed.txt", nested / "installed.txt")
        manifest["entries"][0]["destination_path"] = "nested-later/installed.txt"  # type: ignore[index]
        manifest["manifest_sha256"] = atom.manifest_digest(manifest)  # type: ignore[arg-type]
        stage = self.root / "stage-later-parent"
        rollback = self.root / "rollback-later-parent"
        atom.stage_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
        )
        atom.apply_atom(
            manifest=manifest,  # type: ignore[arg-type]
            source_root=self.source,
            destination_root=self.destination,
            stage_root=stage,
            rollback_root=rollback,
            confirmation=f"INSTALL:{manifest['manifest_sha256']}",
        )
        displaced = self.destination / "nested-later-displaced"
        os.replace(nested, displaced)
        nested.mkdir(mode=0o700)
        (nested / "installed.txt").write_text(
            "substitute-installed\n", encoding="utf-8"
        )
        (nested / "installed.txt").chmod(0o600)
        with self.assertRaisesRegex(
            atom.SourceInstallAtomError,
            "INSTALL_ATOM_DESTINATION_IDENTITY_DRIFT",
        ):
            atom.rollback_atom(
                manifest=manifest,  # type: ignore[arg-type]
                destination_root=self.destination,
                rollback_root=rollback,
                confirmation=f"ROLLBACK:{manifest['manifest_sha256']}",
            )
        self.assertEqual(
            "new\n", (displaced / "installed.txt").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "substitute-installed\n",
            (nested / "installed.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            "INSTALLED",
            json.loads((rollback / atom.ROLLBACK_RECEIPT).read_text())["state"],
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
