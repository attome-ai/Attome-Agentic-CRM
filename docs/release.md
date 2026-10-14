# Cutting a release

A release is tagged only from a commit that passed the release gate on **both Windows and Linux**
(V2-D471, roadmap AC4). The gate is one command; its report is the evidence.

## 1. Run the gate on each operating system

On a Windows machine and on a Linux machine (a real one: a Linux run inside WSL on the Windows
machine does not count as either), at the same commit:

```sh
cargo run -p attome-release --target-dir target/gate -- --check --web
```

The steps are format, clippy, tests, the API contract, the waivers (every `deny.toml`,
`web/audit-waivers.yaml` and `.trivyignore.yaml` entry owned and in date), `cargo deny check`
(install `cargo-deny`), dependency intake (a crate or production npm package added since the
previous tag needs an entry in `docs/dependencies/intake.json`: reason, licence, maintenance, and
`windows_native: true` for a crate), the production npm licences, a CycloneDX SBOM from `Cargo.lock`, the SLO outputs (`attome slo generate
--check`, see [slo.md](slo.md)) and the Prometheus rules (`promtool check rules` and `promtool test
rules`; install Prometheus's `promtool`, or point `ATTOME_PROMTOOL` at it), the install time
(`attome init` into the empty database `ATTOME_INSTALL_DATABASE_URL` names, under ten minutes; not
measured when it is unset), plus the web app with
`--web` and, with `--reproducible`, two release builds whose `attome` binaries must hash the same
(`target/release-gate/repro.json`).

Each run writes `target/release-gate/gate-<os>.json`: the commit, the OS, the toolchain and every
step's outcome. CI does the same on every push and keeps the report as the `release-gate-<os>`
artifact of the run.

A failing step that must not block this release can be overridden only by a named person with a
reason of at least 20 characters; the step still runs and the report keeps its failure:

```sh
cargo run -p attome-release --target-dir target/gate -- --check --override tests="flaky mirror, tracked in issue 42" --by "Name"
```

`format` and `clippy` can never be overridden.

## 2. Bring the reports together

Copy the other machine's report (or the CI artifact) onto the machine that will tag, then:

```sh
cargo run -p attome-release -- import-report path/to/gate-linux.json
```

It refuses a report made from another commit.

## 3. Name breaking changes

If the API changed incompatibly since the previous tag, `CHANGELOG.md`'s `[Unreleased]` section
names every changed path under `### Breaking`; the gate's contract step refuses the release
otherwise. Move `[Unreleased]` under the new version's heading in the same commit as the version
bump.

## 4. Tag

```sh
cargo run -p attome-release -- tag 2.0.0
```

It refuses unless the tracked tree is clean, `v2.0.0` does not exist yet, `[Unreleased]` in
`CHANGELOG.md` says something, and `gate-windows.json` and `gate-linux.json` are both present, both
from this commit and both green (exit 3 names what is missing). Then it sets `[workspace.package]
version` in `Cargo.toml`, moves `[Unreleased]` under `## [2.0.0] - <date>`, adds the release to
`docs/releases/stability.json`, commits `release: v2.0.0` and creates the annotated tag `v2.0.0`.
It never pushes: push the branch and the tag yourself once you are satisfied.

Pushing the tag starts `.github/workflows/release.yml`, which builds the web app and the `attome`
binary for Linux and Windows, packs each with the web app as `attome-<os>-x86_64.(tar.gz|zip)` plus
a `.sha256` file, and attaches them to the GitHub release of the tag. `scripts/install.sh` and
`scripts/install.ps1` download the latest of these, or the one `--version`/`-Version` names.

## 5. After the release

The stability ledger records what happened to each release:

```sh
cargo run -p attome-release -- stability add-defect 2.0.0 '#123'   # a defect that escaped into it
cargo run -p attome-release -- stability rollback 2.0.0              # it was rolled back
```
