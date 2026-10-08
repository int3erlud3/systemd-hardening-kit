# systemd-hardening-kit

[![CI](https://github.com/int3erlud3/systemd-hardening-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/int3erlud3/systemd-hardening-kit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```text
              _                _
   ____  _ __| |_ ___ _ __  __| |
  (_-< || (_-<  _/ -_) '  \/ _` |
  /__/\_, /__/\__\___|_|_|_\__,_|
      |__/
   _                _          _               _   _ _
  | |_  __ _ _ _ __| |___ _ _ (_)_ _  __ _ ___| |_(_) |_
  | ' \/ _` | '_/ _` / -_) ' \| | ' \/ _` |___| / / |  _|
  |_||_\__,_|_| \__,_\___|_||_|_|_||_\__, |   |_\_\_|\__|
                                     |___/

+====================================================================+
|  SYSTEMD HARDENING KIT  ::  Service Sandboxing Toolkit             |
+--------------------------------------------------------------------+
|  Hardened drop-ins and ranked systemd-analyze security reports     |
|  v1.0.0  -  Bastion Ops Toolkit  -  by int3erlud3                  |
+====================================================================+
```

Practical service sandboxing for systemd: **ready-to-use hardening drop-ins**, a
**fully hardened unit template**, a **ranked report** built on
`systemd-analyze security`, and a **dry-run-first helper** that applies drop-ins and
rolls back automatically if the service no longer starts.

## What's inside

| Path | Purpose |
|---|---|
| [`dropins/baseline.conf`](src/systemd_hardening_kit/dropins/baseline.conf) | safe for most daemons: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, `ProtectHome=read-only`, kernel/cgroup/clock/hostname protection, `RestrictSUIDSGID`, `RestrictNamespaces`, `LockPersonality`, native syscalls only, `UMask=0027` |
| [`dropins/strict.conf`](src/systemd_hardening_kit/dropins/strict.conf) | on top of baseline: `ProtectSystem=strict`, `PrivateDevices`, `ProtectProc=invisible`, empty `CapabilityBoundingSet=`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service ~@privileged @resources` |
| [`dropins/no-network.conf`](src/systemd_hardening_kit/dropins/no-network.conf) | `PrivateNetwork=yes`, `AF_UNIX` only, `IPAddressDeny=any` – for jobs that never use the network |
| [`dropins/bind-low-port.conf`](src/systemd_hardening_kit/dropins/bind-low-port.conf) | only `CAP_NET_BIND_SERVICE`, for unprivileged services on ports < 1024 |
| [`units/example-webapp.service`](units/example-webapp.service) | complete hardened template (`DynamicUser`, private state/cache/log dirs, syscall filter, IP allow-list) |
| `systemd-hardening-kit` (Python) | ranked exposure report, per-setting gaps and drop-in suggestions, text/JSON |
| [`scripts/apply-dropin`](scripts/apply-dropin) | installs drop-ins (dry-run by default), reloads, optional restart with automatic rollback |

Measured with `systemd-analyze security --offline` (systemd 255/257) for a plain
`ExecStart=` unit – verified in CI by [`tests/verify-units.sh`](tests/verify-units.sh):

| Unit | Exposure |
|---|---|
| plain unit | 9.4 UNSAFE |
| + baseline | 5.9 MEDIUM |
| + baseline + strict | 1.6 OK |
| + baseline + strict + no-network | 1.0 OK |
| `units/example-webapp.service` | 1.0 OK |

## Installation

```bash
git clone https://github.com/int3erlud3/systemd-hardening-kit.git
cd systemd-hardening-kit
python3 -m pip install .          # Python 3.10+, no runtime dependencies; needs systemd >= 250
```

## Ranked report

```bash
systemd-hardening-kit                          # all services, most exposed first
systemd-hardening-kit --details --top 5        # plus the biggest gaps per unit
systemd-hardening-kit --unit nginx.service --unit ssh.service
systemd-hardening-kit --unit-file units/example-webapp.service   # offline, before deploying
systemd-hardening-kit --format json --details | jq '.units[0]'
systemd-hardening-kit --fail-above 7.0         # exit 1 if any unit is above 7.0 (CI / monitoring)

# analyse elsewhere: save the overview on the server, rank it on your workstation
systemd-analyze security --no-pager > scores.txt
systemd-hardening-kit --input scores.txt --min-exposure 9
```

```text
  #  UNIT                                         EXPOSURE  PREDICATE
  1  user@1000.service                                 9.8  UNSAFE
  2  accounts-daemon.service                           9.6  UNSAFE
  3  cron.service                                      9.6  UNSAFE
  4  getty@tty1.service                                9.6  UNSAFE
  5  oracle-ohasd.service                              9.6  UNSAFE
  6  ssh.service                                       9.6  UNSAFE

6 unit(s), average exposure 9.6, worst user@1000.service (9.8)
```

With `--details` / `--unit` each unit lists its highest-weighted missing settings and the
drop-ins that address them:

```text
  #  UNIT                                         EXPOSURE  PREDICATE
  1  legacy-app.service                                9.0  UNSAFE
       - PrivateNetwork=                          +0.5  Service has access to the host's network
       - User=/DynamicUser=                       +0.4  Service runs as root user
       - CapabilityBoundingSet=~CAP_SET(UID|GID|PCAP) +0.3  Service may change UID/GID identities/capabilities
       - CapabilityBoundingSet=~CAP_SYS_ADMIN     +0.3  Service has administrator privileges
       > suggested drop-ins: baseline, strict
```

Network-related gaps never trigger an automatic suggestion – whether a service may use
the network is a design decision (`no-network` is opt-in).

Exit codes: `0` OK, `1` a unit is above `--fail-above`, `3` error (e.g. systemd not running).

## Applying drop-ins

```bash
scripts/apply-dropin nginx.service baseline strict             # dry-run: shows files + current score
sudo scripts/apply-dropin --apply nginx.service baseline       # install + daemon-reload + new score
sudo scripts/apply-dropin --apply --restart nginx.service baseline strict   # restart, roll back on failure
```

Drop-ins are written as `/etc/systemd/system/<unit>.d/50-hardening-<profile>.conf`, so
they are easy to spot and remove; existing overrides are left untouched. Always test the
service after hardening – `journalctl -u <unit>` shows `EPERM`/`EACCES` errors caused by a
too-strict setting, which can then be relaxed in a later drop-in (e.g. `ReadWritePaths=`).

The banner of both tools is printed to **stderr** on interactive terminals only (never with
`--format json`); disable it with `--no-banner` or `NO_BANNER=1`.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
make lint test shell verify security
```

- pytest with canned `systemd-analyze` output (overview, text and `--json=short` details)
- bats tests for `apply-dropin` with mocked `systemctl`/`systemd-analyze` (dry-run, apply, rollback)
- `tests/verify-units.sh` runs the real `systemd-analyze security --offline --threshold` on the drop-ins
- ruff, ShellCheck, Bandit, pip-audit and gitleaks in CI

## License

[MIT](LICENSE)
