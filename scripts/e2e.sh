#!/usr/bin/env bash
# Copyright (c) 2026 iamvirul. All rights reserved.
# Use of this source code is governed by the MIT license.
#
# Live end-to-end examples: runs the README's sarc commands for real (pipes, HTTP,
# age keys, memory bounds) against a built binary and fails on any broken example.
#
# Usage: scripts/e2e.sh SARC_BINARY AGE_BIN_DIR [REPORT_MD]
#   SARC_BINARY  path to the sarc CLI under test
#   AGE_BIN_DIR  directory containing the age and age-keygen binaries, and optionally
#                age-plugin-sarctest (built from tests/testdata) for the plugin example
#   REPORT_MD    optional Markdown report path (for example $GITHUB_STEP_SUMMARY)
# Env: E2E_BIG_MB (default 1024), E2E_MAX_RSS_MB (default 256)

set -euo pipefail

SARC="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
AGE_DIR="$(cd "$2" && pwd)"
REPORT="${3:-/dev/null}"
BIG_MB="${E2E_BIG_MB:-1024}"
MAX_RSS_MB="${E2E_MAX_RSS_MB:-256}"
PASS="e2e-password-123"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

failures=0
results=()

# record NAME STATUS DETAIL: STATUS is PASS, SKIP, or FAIL; only FAIL fails the run.
record() {
  results+=("| $1 | $2 | ${3//|/\\|} |")
  echo "[$2] $1 - $3"
  if [ "$2" = "FAIL" ]; then failures=$((failures + 1)); fi
}

# run_example NAME FUNCTION: runs FUNCTION in a subshell, in a fresh directory with the
# shared inputs at ./in, so one failure cannot affect the rest. A file literally named
# "-" means "-" was treated as a path instead of stdin/stdout, which fails the example.
# The last output line is the detail; a detail starting "skipped:" records SKIP.
run_example() {
  local name="$1" fn="$2" detail
  if detail="$( (
    set -euo pipefail
    cd "$(mktemp -d "$WORK/example.XXXXXX")"
    ln -s "$WORK/in" in
    "$fn"
    if [ -e ./- ]; then echo "a file named '-' was created instead of using stdin/stdout"; exit 1; fi
  ) 2>&1 | tail -n 1)"; then
    case "$detail" in
      skipped:*) record "$name" SKIP "$detail" ;;
      *) record "$name" PASS "$detail" ;;
    esac
  else
    record "$name" FAIL "${detail:-exited with an error}"
  fi
}

sha() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# same_files DIR_A DIR_B: every file in DIR_A has an identical copy in DIR_B.
same_files() {
  local f
  for f in "$1"/*; do
    [ "$(sha "$f")" = "$(sha "$2/$(basename "$f")")" ] || { echo "content mismatch: $(basename "$f")"; return 1; }
  done
}

# count_files DIR: number of visible regular files directly in DIR (following symlinks).
count_files() {
  find -L "$1" -mindepth 1 -maxdepth 1 -type f ! -name '.*' | wc -l | tr -d ' '
}

# no_leftovers DIR: no extracted files and no in-progress temp files in DIR.
no_leftovers() {
  if [ -d "$1" ] && [ -n "$(find "$1" -mindepth 1 -maxdepth 1)" ]; then
    echo "unexpected output left in $1: $(find "$1" -mindepth 1 -maxdepth 1 -exec basename {} \; | tr '\n' ' ')"
    return 1
  fi
}

# nonempty FILE: fails unless FILE exists and has content (an archive captured from stdout).
nonempty() {
  [ -s "$1" ] || { echo "$1 is empty: nothing was written to stdout"; return 1; }
}

# max_rss_mb LOG CMD...: runs CMD, writes its peak resident set size in MB to LOG, and
# returns CMD's exit status.
max_rss_mb() {
  local out="$1" log="time.log" status=0
  shift
  if [ "$(uname)" = "Darwin" ]; then
    /usr/bin/time -l "$@" 2>"$log" >/dev/null || status=$?
    awk '/maximum resident set size/ {printf "%d", $1 / 1048576}' "$log" >"$out"
  else
    /usr/bin/time -v "$@" 2>"$log" >/dev/null || status=$?
    awk -F: '/Maximum resident set size/ {printf "%d", $2 / 1024}' "$log" >"$out"
  fi
  return "$status"
}

mkdir -p in
head -c 3000000 /dev/urandom >in/photo.jpg
for i in $(seq 1 40); do printf 'func handler%d() error { return render(%d) }\n' "$i" "$i"; done >in/main.go
seq 1 200000 | sed 's/^/2026-10-18T12:00:00Z level=info msg="request done" id=/' >in/app.log
printf '' >in/empty.txt

example_pipe_roundtrip() {
  "$SARC" archive -p "$PASS" -o - in/* 2>/dev/null | "$SARC" extract -p "$PASS" -a - -o out-pipe >/dev/null
  same_files in out-pipe
  echo "archive -o - | extract -a -: $(count_files in) files identical"
}

example_http_download() {
  "$SARC" archive -p "$PASS" -o served.sarc in/* >/dev/null
  mkdir -p www && mv served.sarc www/
  local port
  port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
  (cd www && exec python3 -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1) &
  http_server=$!
  trap 'kill "$http_server" 2>/dev/null || true' EXIT
  for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$port/served.sarc" -o /dev/null && break; sleep 0.2; done
  curl -sf "http://127.0.0.1:$port/served.sarc" | "$SARC" extract -p "$PASS" -a - -o out-http >/dev/null
  same_files in out-http
  echo "curl | sarc extract -a -: files identical"
}

example_multi_recipient_age() {
  "$AGE_DIR/age-keygen" -o bob.key 2>/dev/null
  local bob carol
  bob="$("$AGE_DIR/age-keygen" -y bob.key)"
  "$SARC" keygen -o carol.key 2>carol.pub
  carol="$(grep -o 'age1[0-9a-z]*' carol.pub)"
  "$AGE_DIR/age-keygen" -o mallory.key 2>/dev/null
  "$SARC" archive -p "$PASS" -r "$bob" -r "$carol" -o - in/* 2>/dev/null >shared.sarc
  nonempty shared.sarc
  "$SARC" extract -p "$PASS" -a - -o out-alice <shared.sarc >/dev/null && same_files in out-alice
  "$SARC" extract -i bob.key -a - -o out-bob <shared.sarc >/dev/null && same_files in out-bob
  "$SARC" extract -i carol.key -a - -o out-carol <shared.sarc >/dev/null && same_files in out-carol
  if "$SARC" extract -i mallory.key -a - -o out-mallory <shared.sarc >/dev/null 2>&1; then
    echo "non-recipient opened the archive"; return 1
  fi
  no_leftovers out-mallory
  [ "$(echo "age interop" | "$AGE_DIR/age" -r "$carol" | "$AGE_DIR/age" -d -i carol.key)" = "age interop" ]
  echo "password, age-keygen key, sarc keygen key all open it; non-recipient refused; age CLI reads sarc keys"
}

example_solid_pipe() {
  "$SARC" archive -p "$PASS" --solid --compress-level 19 -o - in/* 2>/dev/null >solid.sarc
  nonempty solid.sarc
  "$SARC" list -p "$PASS" -a - <solid.sarc | grep -q 'zstd+solid'
  "$SARC" extract -p "$PASS" -a - -o out-solid <solid.sarc >/dev/null
  same_files in out-solid
  echo "--solid through a pipe: $(wc -c <solid.sarc | tr -d ' ') bytes, files identical"
}

example_verify_stdin() {
  "$SARC" archive -p "$PASS" -o v.sarc in/* >/dev/null
  "$SARC" verify -a - <v.sarc | grep -q PASSED
  cp v.sarc corrupt.sarc
  # Flip every bit of one byte; overwriting with a fixed value is a no-op 1 time in 256.
  local byte
  byte="$(od -An -tu1 -j 5000 -N 1 v.sarc | tr -d ' ')"
  # shellcheck disable=SC2059
  printf "\\$(printf '%03o' $((byte ^ 255)))" | dd of=corrupt.sarc bs=1 seek=5000 conv=notrunc 2>/dev/null
  cmp -s v.sarc corrupt.sarc && { echo "corruption did not change the archive"; return 1; }
  if "$SARC" verify -a - <corrupt.sarc >/dev/null 2>&1; then
    echo "verify accepted a corrupted stream"; return 1
  fi
  echo "verify -a - passes intact stream, rejects corrupted one"
}

example_truncated_and_wrong_password() {
  "$SARC" archive -p "$PASS" -o t.sarc in/* >/dev/null
  local half=$(( $(wc -c <t.sarc) / 2 ))
  if head -c "$half" t.sarc | "$SARC" extract -p "$PASS" -a - -o out-trunc >/dev/null 2>&1; then
    echo "truncated stream extracted successfully"; return 1
  fi
  [ -d out-trunc ] || { echo "extract never read the stream"; return 1; }
  # Entries completed before the cut are verified and may be published; the cut entry
  # must not be, and no temp file may remain.
  local f
  for f in out-trunc/* out-trunc/.sarc-extract-*; do
    [ -e "$f" ] || continue
    case "$(basename "$f")" in .sarc-extract-*) echo "temp file left behind"; return 1 ;; esac
    [ "$(sha "$f")" = "$(sha "in/$(basename "$f")")" ] || { echo "corrupt file published: $f"; return 1; }
  done
  [ "$(count_files out-trunc)" -lt "$(count_files in)" ] || { echo "truncated stream yielded every file"; return 1; }
  if "$SARC" extract -p "wrong-password-1" -a - -o out-wrong <t.sarc >/dev/null 2>&1; then
    echo "wrong password extracted"; return 1
  fi
  no_leftovers out-wrong
  echo "truncated stream and wrong password fail with no leftover files"
}

# with_pty CMD...: runs CMD on a pseudo-terminal, so a passphrase prompt reads from it;
# stdin is forwarded to the terminal after a delay so the prompt is waiting.
with_pty() {
  if [ "$(uname)" = "Darwin" ]; then
    script -q /dev/null "$@"
  else
    script -qec "$(printf '%q ' "$@")" /dev/null
  fi
}

perm_bits() {
  if [ "$(uname)" = "Darwin" ]; then stat -f '%Lp' "$1"; else stat -c '%a' "$1"; fi
}

example_key_file() {
  "$SARC" keygen --keyfile -o backup.key 2>/dev/null
  [ "$(wc -c <backup.key | tr -d ' ')" = 32 ] || { echo "key file is not 32 bytes"; return 1; }
  [ "$(perm_bits backup.key)" = 600 ] || { echo "key file mode is $(perm_bits backup.key), want 600"; return 1; }
  if "$SARC" keygen --keyfile -o backup.key 2>/dev/null; then echo "keygen overwrote a key file"; return 1; fi
  head -c 4096 /dev/urandom >usb.key
  "$SARC" archive -k backup.key -k usb.key -o - in/* 2>/dev/null >k.sarc
  nonempty k.sarc
  "$SARC" extract -k backup.key -a - -o out-key <k.sarc >/dev/null && same_files in out-key
  "$SARC" extract -k usb.key -a k.sarc -o out-usb >/dev/null && same_files in out-usb
  local err
  if err="$("$SARC" extract -p "$PASS" -a k.sarc -o out-pw 2>&1)"; then echo "password opened a key file archive"; return 1; fi
  echo "$err" | grep -q "accepts: key file" || { echo "unhelpful error: $err"; return 1; }
  no_leftovers out-pw
  echo "keygen --keyfile (32 bytes, 0600), generated and user-supplied key files open it; password refused"
}

example_key_file_and_password() {
  "$SARC" keygen --keyfile -o device.key 2>/dev/null
  "$SARC" archive -k device.key -p "$PASS" -o both.sarc in/* >/dev/null
  "$SARC" extract -k device.key -p "$PASS" -a both.sarc -o out-both >/dev/null && same_files in out-both
  local err
  if err="$("$SARC" extract -k device.key -a both.sarc -o out-key-only 2>&1)"; then echo "key file alone opened it"; return 1; fi
  echo "$err" | grep -q "accepts: key file + password" || { echo "unhelpful error: $err"; return 1; }
  if "$SARC" extract -p "$PASS" -a both.sarc -o out-pw-only >/dev/null 2>&1; then echo "password alone opened it"; return 1; fi
  no_leftovers out-key-only
  no_leftovers out-pw-only
  echo "--key with --password needs both; either alone is refused"
}

example_ssh_keys() {
  ssh-keygen -q -t ed25519 -N "" -C e2e -f id_ed25519
  ssh-keygen -q -t rsa -b 3072 -N "" -C e2e -f id_rsa
  ssh-keygen -q -t ed25519 -N "ssh-passphrase-1" -C e2e -f id_locked
  ssh-keygen -q -t ed25519 -N "" -C e2e -f id_other
  "$SARC" archive -r "$(cat id_ed25519.pub)" -r id_rsa.pub -i id_locked -o - in/* 2>/dev/null >ssh.sarc
  nonempty ssh.sarc
  "$SARC" extract -i id_ed25519 -a - -o out-ed <ssh.sarc >/dev/null && same_files in out-ed
  "$SARC" extract -i id_rsa -a ssh.sarc -o out-rsa >/dev/null && same_files in out-rsa
  if "$SARC" extract -i id_other -a ssh.sarc -o out-other >/dev/null 2>&1; then echo "unrelated SSH key opened it"; return 1; fi
  no_leftovers out-other
  if ! command -v script >/dev/null; then
    echo "ed25519 and RSA keys open it; unrelated key refused (passphrase prompt skipped: no script)"; return 0
  fi
  (sleep 2; echo "ssh-passphrase-1") | with_pty "$SARC" extract -i id_locked -a ssh.sarc -o out-locked >/dev/null 2>&1 || true
  same_files in out-locked
  (sleep 2; echo "wrong-passphrase") | with_pty "$SARC" extract -i id_locked -a ssh.sarc -o out-wrong >wrong.log 2>&1 || true
  grep -q "identity could not be used" wrong.log || { echo "wrong passphrase not reported: $(tr -d '\r' <wrong.log | tail -n 1)"; return 1; }
  no_leftovers out-wrong
  echo "ed25519, RSA, and passphrase-protected keys (prompted on the terminal) open it; wrong passphrase and unrelated key refused"
}

example_hardware_token_plugin() {
  if [ ! -x "$AGE_DIR/age-plugin-sarctest" ]; then
    echo "skipped: age-plugin-sarctest not built into $AGE_DIR"; return 0
  fi
  export PATH="$AGE_DIR:$PATH"
  age-plugin-sarctest -generate >token.id
  local recipient
  recipient="$(grep -o 'age1sarctest1[0-9a-z]*' token.id)"
  "$SARC" archive -r "$recipient" -o - in/* 2>plugin.log >token.sarc
  nonempty token.sarc
  [ "$(head -c 4 token.sarc)" = "SARC" ] || { echo "plugin output corrupted the archive stream"; return 1; }
  grep -q "sarctest token wrapping" plugin.log || { echo "plugin message missing from stderr"; return 1; }
  "$SARC" extract -i token.id -a - -o out-token <token.sarc 2>plugin.log >/dev/null && same_files in out-token
  grep -q "touch your sarctest token" plugin.log || { echo "plugin prompt missing from stderr"; return 1; }
  # The same identity works with the age CLI, so the plugin speaks the standard protocol.
  [ "$(echo "token interop" | age -r "$recipient" | age -d -i token.id 2>/dev/null)" = "token interop" ]
  echo "plugin recipient (as age1yubikey1...) via stdout; plugin prompts on stderr; age CLI uses the same token"
}

example_constant_memory() {
  head -c "$((BIG_MB * 1048576))" /dev/urandom >big.bin
  local want rss
  want="$(sha big.bin)"
  "$SARC" archive -p "$PASS" -o big.sarc big.bin >/dev/null
  rm -f big.bin
  max_rss_mb rss.txt sh -c "\"$SARC\" extract -p \"$PASS\" -a - -o out-big <big.sarc" || { echo "streaming extract failed"; return 1; }
  rss="$(cat rss.txt)"
  [ "$(sha out-big/big.bin)" = "$want" ] || { echo "extracted ${BIG_MB} MB file differs"; return 1; }
  rm -rf out-big big.sarc
  [ "$rss" -lt "$MAX_RSS_MB" ] || { echo "peak RSS ${rss} MB for a ${BIG_MB} MB stream exceeds ${MAX_RSS_MB} MB"; return 1; }
  echo "extract of a ${BIG_MB} MB stream peaked at ${rss} MB RSS (limit ${MAX_RSS_MB} MB)"
}

example_refuses_terminal() {
  if [ "$(uname)" = "Darwin" ] || ! command -v script >/dev/null; then
    echo "skipped: needs util-linux script for a pseudo-terminal"; return 0
  fi
  local out
  out="$(script -qec "\"$SARC\" archive -p \"$PASS\" -o - in/main.go" /dev/null 2>&1 || true)"
  echo "$out" | grep -q "refusing to write an archive to a terminal" || { echo "binary output reached a terminal: $out"; return 1; }
  echo "archive -o - refuses to write binary to a terminal"
}

run_example "Pipe roundtrip" example_pipe_roundtrip
run_example "HTTP download into extract" example_http_download
run_example "Multi-recipient with age keys" example_multi_recipient_age
run_example "Solid mode through a pipe" example_solid_pipe
run_example "Verify from stdin" example_verify_stdin
run_example "Truncated stream and wrong password" example_truncated_and_wrong_password
run_example "Key file" example_key_file
run_example "Key file and password" example_key_file_and_password
run_example "SSH keys" example_ssh_keys
run_example "Hardware token plugin" example_hardware_token_plugin
run_example "Constant memory streaming extract" example_constant_memory
run_example "Refuse terminal output" example_refuses_terminal

{
  echo "## Live examples ($(uname -s))"
  echo
  echo "| Example | Result | Detail |"
  echo "|---|---|---|"
  printf '%s\n' "${results[@]}"
} >>"$REPORT"

if [ "$failures" -gt 0 ]; then
  echo "$failures example(s) failed" >&2
  exit 1
fi
echo "all examples passed"
