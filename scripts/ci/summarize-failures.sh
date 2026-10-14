#!/usr/bin/env bash
# Turns a failed `attome-release --check` log into GitHub annotations that a
# reader of the public checks API can act on without the raw log:
#   1. the failing test targets (cargo's "rerun pass" lines),
#   2. compile and lint errors with their locations,
#   3. every panic with the message lines that follow it,
#   4. rustfmt diffs.
# GitHub keeps at most 10 error annotations per step and truncates long ones,
# so the summary is split into chunks of 120 lines, at most 9 annotations.
set -u
log="${1:-release-check.log}"
clean=$(mktemp)
sed -e 's/\x1b\[[0-9;]*m//g' "$log" > "$clean"

{
  echo "== failing targets"
  grep -E 'rerun pass' "$clean" | sed -E 's/.*rerun pass `(.*)`/\1/' | sort -u
  echo "== compile and lint errors"
  grep -E -A1 '^error(\[E[0-9]+\])?: ' "$clean" | grep -vE '^--$|could not compile|aborting due to|test failed, to rerun' | head -200
  echo "== panics"
  grep -E -A3 'panicked at' "$clean" | grep -vE '^--$|^note: run with|^stack backtrace' | head -400
  echo "== format"
  grep -E '^Diff in' "$clean" | head -50
} > failures.txt

total=$(wc -l < failures.txt)
chunk=120
part=1
start=1
while [ "$start" -le "$total" ] && [ "$part" -le 9 ]; do
  body=$(sed -n "${start},$((start + chunk - 1))p" failures.txt | sed -e 's/%/%25/g' | awk '{printf "%s%%0A", $0}')
  echo "::error title=release check failures ${part}::${body}"
  start=$((start + chunk))
  part=$((part + 1))
done
rm -f "$clean"
