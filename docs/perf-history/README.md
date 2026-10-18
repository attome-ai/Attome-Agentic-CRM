# Performance history

One `attome-perf/v1` record per release, written by `attome perf record --release <v>` after the
release gate's load-test matrix (`attome release --check --slo-evidence`) and `cargo bench`. Each holds
the machine it ran on, every SLO class's p95 per run and every criterion benchmark's mean.

`attome perf compare` (and the gate step `perf_compare`, with `--perf`) compares the newest record
with the previous release's on the same machine: a class whose median p95 grew past its
`regression_threshold_pct` in `observability/slo-catalogue.json` (10% when unset) fails. Records
from different machines are never compared.
