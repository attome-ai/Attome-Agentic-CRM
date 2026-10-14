# Security policy

## Reporting a vulnerability

Please report security problems **privately** by email to **security@attome.com**. Do not open a public
issue, discussion or pull request for a security problem.

Include what you found, how to reproduce it, the version or commit, and its impact as you understand it.
We aim to acknowledge a report within three working days and will keep you informed while we fix it.
Please give us reasonable time to release a fix before you disclose the problem publicly; we will credit
you in the release notes unless you prefer otherwise.

## Supported versions

Attome has no release yet. Until the first release, fixes go into the `main` branch only.

Once there are releases, the supported ones are each long-term-support release and the latest
release, as `docs/releases/stability.json` lists them.

## Advisory sweep

With every patch release, and at least monthly, the maintainers run `attome release advisories`,
which checks every supported release against the Rust and npm advisory databases and writes
`target/advisories/<date>.json`. A finding that affects a supported release is fixed within:

- **critical**: 7 days;
- **high**: 30 days;
- **moderate**: the next patch release.
