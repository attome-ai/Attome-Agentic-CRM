# Documentation

## Guides

- [Install](content/install.md): Linux, Windows, PostgreSQL in Docker, and the first steps after.
- [Admin](content/admin.md): people and access, settings, health, records and compliance.
- [Builder](content/builder.md): entities and fields, model objects, rules and flows, packs.
- [Developer](content/developer.md): the API, and building from source.
- [Extension](content/extension.md): packs, agents, integrations, web forms, branding.
- [Upgrade](content/upgrade.md): upgrading and rolling back.

## Reference

- [Architecture](architecture.md)
- [Agents](agents.md): what agents may do, their tools, delegation and safety.
- [Hijri calendar](hijri.md): Umm al-Qura dates, corrections, grouping, autonumbers and holidays.
- [Duplicate rules](duplicates.md): comparators, what saving a duplicate does, scans, merges and undo.
- [Scanning](scanning.md): scannable fields, GS1 codes, finding records by code, scan actions and the deep-link rule.
- [Deal teams and splits](deal-teams.md): team members, revenue and overlay splits, won deals and leavers.
- [Procurement](procurement.md): requisitions, orders, receipts, vendor bills, budget checks and scorecards.
- [Invoicing](invoicing.md): drafts, issue and numbering, notes, the invoice document, statements, ageing and write-offs.
- [Rule language functions](rule-language.md): language versions and the functions V2 adds.
- [Data layer](data-layer.md): pools, statement classes, retry, locks, query tags, read-your-writes and the censuses.
- [Slow statements](slow-queries.md): turning on pg_stat_statements and auto_explain, reading query tags and plans.
- [Backup](backup.md), [Versions and support](versions-and-support.md), [API versions](api-versions.md), [API workflows (Arazzo)](api/arazzo/), [Model servers](model-servers.md)
- [Release](release.md), [SLOs](slo.md), [Testing](testing.md), [Build machine](build-machine.md)
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
