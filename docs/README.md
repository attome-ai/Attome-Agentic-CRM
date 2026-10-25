# Documentation

## Guides

- [Install](content/install.md): Linux, Windows, PostgreSQL in Docker, and the first steps after.
- [Admin](content/admin.md): people and access, settings, health, records and compliance.
- [Builder](content/builder.md): entities and fields, model objects, rules and flows, packs.
- [Developer](content/developer.md): the API, and building from source.
- [Extension](content/extension.md): packs, agents, integrations, web forms, branding.
- [Partners](content/partners/README.md): the partner programme, its tiers and the implementation methodology.
- [Trust centre](content/trust/README.md): certifications and reports, and who operates each security control per hosting profile.
- [Upgrade](content/upgrade.md): upgrading and rolling back.
- [Learning paths](content/learn/README.md): four paths with exercises and answer checks on a local Solo install.

## Reference

- [Architecture](architecture.md)
- [Agents](agents.md): what agents may do, their tools, delegation and safety.
- [Identity brokers](identity-brokers.md): signing in with a SAML-only identity provider through Entra ID, Okta, AD FS or Keycloak over OpenID Connect.
- [Hijri calendar](hijri.md): Umm al-Qura dates, corrections, grouping, autonumbers and holidays.
- [Duplicate rules](duplicates.md): comparators, what saving a duplicate does, scans, merges and undo.
- [Data lineage](lineage.md): the graph of what uses what, impact before a field change, hand-documented links and the OpenLineage export.
- [Data quality](data-quality.md): dimensions, measure-only rules, targets, issues and their owners, fixes and alerts.
- [Scanning](scanning.md): scannable fields, GS1 codes, finding records by code, scan actions and the deep-link rule.
- [Offline use](offline.md): offline profiles, what a device gets and never gets, remote wipe and the device view.
- [Deal teams and splits](deal-teams.md): team members, revenue and overlay splits, won deals and leavers.
- [Opportunity lines](opportunity-lines.md): lines and the product picker, pricing order, the deal's amount, schedules, quote sync, undo and the feature flags.
- [Procurement](procurement.md): requisitions, orders, receipts, vendor bills, budget checks and scorecards.
- [Invoicing](invoicing.md): drafts, issue and numbering, notes, the invoice document, statements, ageing and write-offs.
- [Workforce](workforce.md): planning groups, staffing, schedule builds, self-service, swaps and intraday offers.
- [Rule language functions](rule-language.md): language versions and the functions V2 adds.
- [Data layer](data-layer.md): pools, statement classes, retry, locks, query tags, read-your-writes and the censuses.
- [Caching](caching.md): adding a cache with a CacheSpec and TieredCache, partitions, sensitivity, failure, dependencies, warm start, quotas and purging.
- [Metadata versions](metadata-versions.md): how a publish reaches every node, the version header, readiness, pins and rollback.
- [Background jobs](jobs.md): registering a job type, schedules and batch jobs with checkpoints, progress and cancel.
- [Slow statements](slow-queries.md): turning on pg_stat_statements and auto_explain, reading query tags and plans.
- [Backup](backup.md), [Versions and support](versions-and-support.md), [API versions](api-versions.md), [API workflows (Arazzo)](api/arazzo/), [Model servers](model-servers.md)
- [Release](release.md), [Release signing](release-signing.md), [SLOs](slo.md), [Testing](testing.md), [Build machine](build-machine.md)
- `evidence/`: dated measurements (latency, memory, AI quality) that releases are checked against.

## Building the documentation site

```sh
node scripts/docs-build.mjs        # target/docs-site/<version>/en and /ar, with the API reference
node --test scripts/docs-build.test.mjs
```

The site is static HTML, one folder per version (from `Cargo.toml`, or `--version`), in English and
Arabic (right to left). An Arabic page is the same path under `docs/ar/`; until it exists the Arabic
site shows the English page with a note. The API reference is generated from `openapi.json`.
`--out <dir>` keeps several versions side by side; `versions.json` lists them.
