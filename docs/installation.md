# On-demand installation

This package supports the owner paths `/home/ubuntu/.codex`,
`/home/ubuntu/.config/systemd/user`, and
`/home/ubuntu/code/twinfinityapp` on native Ubuntu. It requires Python 3 with
`tomllib`, Git, Codex, and a working systemd user manager. Installation and
runtime activation require their own current authority; merged source alone is
not installed or live.

Prepare a reviewed `twinfinity-source-install-atom/v2` template containing
exactly `schema`, `atom_id`, `source_commit`, and `entries`. The entries bind
the prior destination bytes, installed skill/profile files, and the six unit
files in `systemd/user/`; the template does not contain
`destination_root_identity` or `manifest_sha256`. Seal that template to the
exact canonical destination root with the source tool:

```bash
/usr/bin/python3 \
  skills/twinfinity-sprint-orchestrator/scripts/source_install_atom.py \
  seal-manifest \
  --manifest /path/to/reviewed-v2-template.json \
  --destination-root /home/ubuntu \
  --output /path/to/private-install-evidence/sealed-v2-manifest.json
```

The output path must be a new absolute path under an existing owner-controlled
directory. The command writes a mode-`0600` canonical manifest, validates that
the result is accepted schema v2, and prints a privacy-safe sealing receipt. A
schema-v1 template or an existing, aliased, unsafe, or noncanonical output is
rejected without producing an accepted manifest. Review the sealed manifest
before use. Sealing is source preparation only: it grants no installation,
activation, endpoint, systemd, or SQLite authority.

Use private, unique stage and rollback directories. The default installation
command only stages and validates through the existing installation atom:

```bash
scripts/install.sh \
  --manifest /path/to/private-install-evidence/sealed-v2-manifest.json \
  --source-root "$(pwd -P)" \
  --destination-root /home/ubuntu \
  --stage-root /home/ubuntu/.codex/twinfinity-install/stage.<id>
```

After reviewing that result and obtaining separate stopped-state installation
authority, reuse the same stage for explicit apply:

```bash
scripts/install.sh --apply \
  --manifest /path/to/private-install-evidence/sealed-v2-manifest.json \
  --source-root "$(pwd -P)" \
  --destination-root /home/ubuntu \
  --stage-root /home/ubuntu/.codex/twinfinity-install/stage.<id> \
  --rollback-root /home/ubuntu/.codex/twinfinity-install/rollback.<id>
```

Apply delegates validation, replacement, journal creation, and failure rollback
to `source_install_atom.py`. It does not reload systemd, enable a timer, start a
unit, change an endpoint pointer, or touch SQLite.

With separately authorized live use, validate the installed manifest and the
current registry-derived Planner, Development, and SRE profiles, then reload
the user manager and start the three timers without enabling them:

```bash
scripts/start.sh \
  --manifest /path/to/private-install-evidence/sealed-v2-manifest.json \
  --source-root /path/to/reviewed/harness-source \
  --destination-root /home/ubuntu
```

Stop on demand with `scripts/stop.sh`. It first stops the three timers and three
supervisor services, then waits up to 30 seconds for transient role executors.
It never kills an executor; a still-active executor or an observation failure
returns nonzero and must be resolved from authoritative attempt state.
