# On-demand installation

This package supports the owner paths `/home/ubuntu/.codex`,
`/home/ubuntu/.config/systemd/user`, and
`/home/ubuntu/code/twinfinityapp` on native Ubuntu. It requires Python 3 with
`tomllib`, Git, Codex, and a working systemd user manager. Installation and
runtime activation require their own current authority; merged source alone is
not installed or live.

Prepare a reviewed `twinfinity-source-install-atom/v1` manifest that binds the
exact source commit, prior destination bytes, installed skill/profile files,
and the six unit files in `systemd/user/`. Use a private, unique stage and
rollback directory. The default command only stages and validates through the
existing installation atom:

```bash
scripts/install.sh \
  --manifest /path/to/reviewed-install-manifest.json \
  --source-root "$(pwd -P)" \
  --destination-root /home/ubuntu \
  --stage-root /home/ubuntu/.codex/twinfinity-install/stage.<id>
```

After reviewing that result and obtaining separate stopped-state installation
authority, reuse the same stage for explicit apply:

```bash
scripts/install.sh --apply \
  --manifest /path/to/reviewed-install-manifest.json \
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
  --manifest /path/to/reviewed-install-manifest.json \
  --source-root /path/to/reviewed/harness-source \
  --destination-root /home/ubuntu
```

Stop on demand with `scripts/stop.sh`. It first stops the three timers and three
supervisor services, then waits up to 30 seconds for transient role executors.
It never kills an executor; a still-active executor or an observation failure
returns nonzero and must be resolved from authoritative attempt state.
