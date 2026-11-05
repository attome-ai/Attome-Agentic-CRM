# Performance history

One `attome-perf/v1` record per release, written by `attome perf record --release <v>` after the
release gate's load-test matrix (`attome release --check --slo-evidence`) and `cargo bench`. Each holds
the machine it ran on, every SLO class's p95 per run and every criterion benchmark's mean.

`attome perf compare` (and the gate step `perf_compare`, with `--perf`) compares the newest record
with the previous release's on the same machine: a class whose median p95 grew past its
`regression_threshold_pct` in `observability/slo-catalogue.json` (10% when unset) fails. Records
from different machines are never compared.

## Reading a failure and updating a record

`attome perf compare` names each class that grew past its threshold with both p95 values. By
default it compares the newest record with the newest earlier one from the same `machine` (the
hardware fingerprint); two records named with `--base` and `--current` from different machines are
not compared and the command exits 2, so a new machine starts its own line of history. A real regression is fixed in code; if the slower number is accepted (a
feature that costs time on purpose), the release's record stands and becomes the next release's
reference, and the commit says why. Records are never edited by hand; a bad run is re-run with
`attome perf record` and the new file replaces it before the release is tagged.

