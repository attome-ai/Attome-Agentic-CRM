# Versions and support

## Version numbers

Attome uses semantic versions, `MAJOR.MINOR.PATCH`:

- **PATCH** (`1.4.2` to `1.4.3`): fixes and security patches only. No migration needs a decision
  and no API changes shape. Safe to apply as soon as it is out.
- **MINOR** (`1.4` to `1.5`): new features, new metadata kinds, new API routes and the migrations
  they need. A breaking change to `/api/v1` can ship in a minor release; it is named under
  `### Breaking` in `CHANGELOG.md` and in the release notes, and the release gate refuses a
  release that breaks the API without saying so.
- **MAJOR** (`1.x` to `2.0`): a change to how a deployment is installed, upgraded or hosted, or the
  end of a supported platform (an operating system, a PostgreSQL major version).

Until `1.0`, every `0.x` minor may change anything; the changelog says what.

## Cadence

- A minor release about every eight weeks.
- Patch releases when they are needed, security fixes first.
- Each release is cut by `attome release` only when the release gate passed on both Windows and
  Linux, and ships a SHA-256 for every file.

## Support window

- Each minor release is supported for **12 months** from its release date: it receives security
  patches and fixes for data loss or data exposure.
- The two newest minor releases also receive ordinary bug fixes.
- An upgrade from any supported minor to the newest one is tested before each release; skipping
  minor releases is supported within the window.

## Security patches

- A reported vulnerability is acknowledged within 3 working days.
- Critical and high severity issues are fixed in every supported minor release, as a patch
  release, as soon as the fix is ready; medium and low ones in the next scheduled release.
- Each security release names what was fixed in its notes, without exploit detail, once a fix is
  available.
- Customers hosted by Attome or a partner are patched by their host within the time their
  agreement states.

## Platforms

Attome runs on Windows and Linux (x86-64), with PostgreSQL 18 (pgvector for vector search). A
platform's support ends only in a major release, announced at least 6 months ahead.

The HTTP API has its own dated versions, pinning and a 24-month support window: see
[api-versions.md](api-versions.md).
