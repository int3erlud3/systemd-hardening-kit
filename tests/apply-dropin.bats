#!/usr/bin/env bats
# Tests for scripts/apply-dropin with mocked systemctl / systemd-analyze.

setup() {
  AD="$BATS_TEST_DIRNAME/../scripts/apply-dropin"
  export SHK_SYSTEMD_DIR="$BATS_TEST_TMPDIR/etc/systemd/system"
  export MOCK_LOG="$BATS_TEST_TMPDIR/calls.log"
  export SHK_SETTLE_SECONDS=0
  export PATH="$BATS_TEST_DIRNAME/mocks:$PATH"
  mkdir -p "$SHK_SYSTEMD_DIR"
  : >"$MOCK_LOG"
  unset NO_BANNER MOCK_ACTIVE
}

@test "dry-run is the default and changes nothing" {
  run "$AD" nginx.service baseline strict
  [ "$status" -eq 0 ]
  [[ "$output" == *"exposure: 9.6 UNSAFE"* ]]
  [[ "$output" == *"would write $SHK_SYSTEMD_DIR/nginx.service.d/50-hardening-baseline.conf"* ]]
  [[ "$output" == *"would write $SHK_SYSTEMD_DIR/nginx.service.d/50-hardening-strict.conf"* ]]
  [[ "$output" == *"NoNewPrivileges=yes"* ]]
  [[ "$output" == *"dry-run: nothing changed"* ]]
  [ ! -e "$SHK_SYSTEMD_DIR/nginx.service.d" ]
  [ "$(grep -c '^systemctl' "$MOCK_LOG")" -eq 0 ]
}

@test "--apply installs drop-ins, reloads systemd, does not restart" {
  run "$AD" --apply nginx.service baseline
  [ "$status" -eq 0 ]
  [ -f "$SHK_SYSTEMD_DIR/nginx.service.d/50-hardening-baseline.conf" ]
  [ "$(stat -c %a "$SHK_SYSTEMD_DIR/nginx.service.d/50-hardening-baseline.conf")" = 644 ]
  [[ "$output" == *"exposure: 4.2 OK :-) (after)"* ]]
  grep -qx 'systemctl daemon-reload' "$MOCK_LOG"
  [ "$(grep -c 'systemctl restart' "$MOCK_LOG")" -eq 0 ]
  [[ "$output" == *"not restarted"* ]]
}

@test "--restart keeps drop-ins when the service comes up" {
  run "$AD" --apply --restart nginx.service baseline
  [ "$status" -eq 0 ]
  [[ "$output" == *"restarted and active"* ]]
  grep -qx 'systemctl restart nginx.service' "$MOCK_LOG"
  [ -f "$SHK_SYSTEMD_DIR/nginx.service.d/50-hardening-baseline.conf" ]
}

@test "--restart rolls back when the service fails" {
  mkdir -p "$SHK_SYSTEMD_DIR/nginx.service.d"
  echo "[Service]" >"$SHK_SYSTEMD_DIR/nginx.service.d/override.conf"
  MOCK_ACTIVE=3 run "$AD" --apply --restart nginx.service baseline strict
  [ "$status" -eq 1 ]
  [[ "$output" == *"rolling back"* ]]
  [ ! -e "$SHK_SYSTEMD_DIR/nginx.service.d/50-hardening-baseline.conf" ]
  [ ! -e "$SHK_SYSTEMD_DIR/nginx.service.d/50-hardening-strict.conf" ]
  [ -f "$SHK_SYSTEMD_DIR/nginx.service.d/override.conf" ]
  [ "$(grep -c 'systemctl daemon-reload' "$MOCK_LOG")" -eq 2 ]
}

@test "invalid input is rejected with exit 2" {
  run "$AD" nginx baseline
  [ "$status" -eq 2 ]
  run "$AD" "../evil.service" baseline
  [ "$status" -eq 2 ]
  run "$AD" nginx.service nonexistent
  [ "$status" -eq 2 ]
  run "$AD" nginx.service "../../etc/passwd"
  [ "$status" -eq 2 ]
  run "$AD" nginx.service
  [ "$status" -eq 2 ]
  run "$AD" --restart nginx.service baseline
  [ "$status" -eq 2 ]
  run "$AD" --bogus nginx.service baseline
  [ "$status" -eq 2 ]
}

@test "--help lists the profiles" {
  run "$AD" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"baseline"* && "$output" == *"no-network"* && "$output" == *"strict"* ]]
}

# script(1) runs the command on a pseudo-terminal, so stdout/stderr are a TTY.
on_tty() {
  command -v script >/dev/null || skip "script(1) not available"
  run script -qefc "$(printf '%q ' "$@")" /dev/null </dev/null
}

@test "banner on a terminal only, and suppressible" {
  on_tty "$AD" nginx.service baseline
  [[ "$output" == *"Bastion Ops Toolkit"* ]]
  run "$AD" nginx.service baseline
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
  on_tty "$AD" --no-banner nginx.service baseline
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
  on_tty env NO_BANNER=1 "$AD" nginx.service baseline
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
  on_tty "$AD" --version
  [[ "$output" == *"Bastion Ops Toolkit"* ]]
}
