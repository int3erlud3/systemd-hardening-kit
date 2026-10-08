#!/usr/bin/env bash
# Verifies the shipped drop-ins and the unit template with the real systemd-analyze
# in offline mode (no running systemd needed; systemd >= 250).
#   plain unit                 -> exposure reported (reference, ~9.4)
#   + baseline                 -> must be <= 6.5
#   + baseline + strict        -> must be <= 2.5
#   units/example-webapp       -> must be <= 2.0
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
dropins=src/systemd_hardening_kit/dropins
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

sa() { systemd-analyze security --no-pager --offline=true "$@"; }
score() { sa "$1" | sed -nE 's/^(→|->) Overall exposure level for [^:]+: ([0-9.]+).*/\2/p'; }
body() { grep -v '^\[Service\]' "$dropins/$1.conf"; }

printf '[Unit]\nDescription=verify\n\n[Service]\nExecStart=/usr/bin/sleep infinity\n' >"$tmp/plain.service"
{ cat "$tmp/plain.service"; body baseline; } >"$tmp/baseline.service"
{ cat "$tmp/baseline.service"; body strict; } >"$tmp/strict.service"
{ cat "$tmp/strict.service"; body no-network; } >"$tmp/no-network.service"

fail=0
check() { # name file threshold
  local s
  s=$(score "$2")
  printf '%-22s exposure %-4s (threshold %s)\n' "$1" "${s:-?}" "$3"
  # --threshold makes systemd-analyze exit non-zero above the limit
  if ! sa --threshold="$3" "$2" >/dev/null; then
    echo "  FAIL: above threshold" >&2
    fail=1
  fi
}

printf '%-22s exposure %s (reference)\n' plain "$(score "$tmp/plain.service")"
check "+ baseline" "$tmp/baseline.service" 65
check "+ baseline + strict" "$tmp/strict.service" 25
check "+ ... + no-network" "$tmp/no-network.service" 15
check "example-webapp" units/example-webapp.service 20

# Every drop-in must only contain directives systemd knows (unknown ones are warned about).
for f in "$dropins"/*.conf; do
  { cat "$tmp/plain.service"; body "$(basename "$f" .conf)"; } >"$tmp/check.service"
  if sa "$tmp/check.service" 2>&1 >/dev/null | grep -Ei 'unknown|failed to parse|invalid'; then
    echo "  FAIL: $f has invalid directives" >&2
    fail=1
  fi
done
exit "$fail"
