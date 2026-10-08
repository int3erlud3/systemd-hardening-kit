# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository
instead. You can expect an initial response within 7 days.

## Security review notes

- The report is read-only: it only runs `systemd-analyze security` (no shell, fixed
  `PATH`/locale, timeout) and validates unit names before passing them on.
- `scripts/apply-dropin` changes nothing unless `--apply` is given, validates unit and
  profile names, writes only `50-hardening-*.conf` files and rolls back on a failed restart.
- CI runs ruff (incl. flake8-bandit rules), Bandit, pip-audit, ShellCheck, bats and a
  gitleaks secret scan on every push and pull request; GitHub Actions are pinned to commit
  SHAs and run with `contents: read` only.
