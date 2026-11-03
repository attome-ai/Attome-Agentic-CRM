# Packages

A package (T8-T1) is an `attome-bundle/v1` bundle with a manifest saying who published it, under
which namespace, at which version, what it needs and how it installs, signed with the publisher's
Ed25519 key (`attome-package/v1`). The `attome package` command (T8-T4) builds, publishes and
installs them.

## Build

A package folder holds `package.json`, the manifest, and `bundle.json`, the bundle:

```json
{ "id": "com.example.fleet", "publisher": "Example Co", "namespace": "exf",
  "version": "1.2.0", "depends": [{ "id": "com.attome.sales", "version": ">=1.0.0" }],
  "platform": ">=0.1.0", "contents": ["entities", "views"], "mode": "managed" }
```

```sh
attome package keygen --out publisher.key        # once; prints the public key
attome package build ./fleet --key publisher.key # writes com.example.fleet-1.2.0.attome-package.json
```

The key file is the publisher's secret: keep it out of the repository and off shared machines.
Targets trust the publisher by the printed public key. `keygen` never overwrites a key file.

## Publish

```sh
attome package publish com.example.fleet-1.2.0.attome-package.json --to ./catalogue
```

A catalogue is a folder: `<id>/<version>.attome-package.json` for each version and `index.json`
(`attome-package-catalogue/v1`) listing them. Only a signed package is published, and a published
version never changes: publish a new version instead. Share the folder however suits you (a file
share, a repository, a static web server).

## Install

```sh
attome package install com.example.fleet --from ./catalogue \
  --trust "Example Co=<public key>" --target prod
attome package install com.example.fleet@1.2.0 --from ./catalogue --trust-file trusted.json \
  --target prod --yes --confirm-target prod
```

`install` takes a package file, or `<id>` (the newest version) or `<id>@<version>` from a
catalogue. It checks the signature against the publishers you trust (`--trust`, repeatable, or a
`--trust-file` of `{"<publisher>": "<public key>"}`), checks that every entity the package adds,
and every attribute it adds to an entity it does not own, carries its namespace, and shows the
target's plan: what it creates, updates and leaves unchanged. With `--yes` (and
`--confirm-target` on a production target) it applies that plan through
`POST /api/v1/admin/metadata/import`, under that route's permission, two-person approval gate and
audit. `--json` prints the versioned result.

A deployment can also check packages itself. List the publishers it trusts in the setting
`packages.trusted_publishers` (`[{"publisher": "Example Co", "key": "<public key>"}]`; empty, the
default, trusts none), then `POST /api/v1/admin/packages/preview` with `{"package": <the package
document>}`. It checks the signature against those publishers, the manifest and the namespace, plans
the bundle against live metadata and answers the install preview: new and changed objects, the
permissions the package requests, its effects on records already there (records it writes, fields
it adds to existing entities, field changes), what it removes and what is blocked, with the
persisted plan. Installing is applying that plan (`POST /api/v1/admin/metadata/import?mode=apply`
with its `plan_id`). Administrators only.

## Managed packages

A package whose manifest says `"mode": "managed"` keeps its objects. Once its plan applies, its own
entities (those named with its namespace) are locked: the admin metadata routes refuse changing or
removing them or their fields (`409 metadata_locked`). An entity the manifest lists in
`"extension_points"` is add-only instead: customers may add their own fields to it, but not change
or remove the package's (`409 metadata_add_only`). The fields a package adds to entities it does not
own are locked one by one. A newer version of the package changes them through its own apply. An
unmanaged package locks nothing: its objects become the deployment's own.

A package's bundle is always a selection: installing or upgrading it never retires an object it
does not carry.

## Upgrade, drift and uninstall

`POST /api/v1/admin/packages/upgrade` takes a newer version of an installed managed package, pushed
as `{"package": <document>}` or pulled from `{"url": "https://…"}` (a public host, at most 32 MB).
It is checked like an install (signature, manifest, the installed version's namespace, a higher
version), then merged three ways: the installed version, the new one, and the deployment's live
metadata. A property only the customer changed (a label, a field type, required, sensitive, the
lookup target, the options, the length) keeps the customer's value (`kept`); a property both
changed differently is a conflict (`conflicts`, each with the installed, customer and package
values). While there are conflicts nothing is planned; send `"accept_package": true` to take the
package's value for each. Objects the new version drops stay in place, no longer the package's
(`removed`). Upgrading is applying the returned plan; the apply replaces the old version's locks.

`GET /api/v1/admin/packages/{id}/drift` names every managed property that differs live from what
the installed version set, and every object of it gone: changes made around the package, through a
bundle, a changeset or by hand. Fields customers add on extension points are their own, not drift.

`POST /api/v1/admin/packages/{id}/uninstall` with `{"data": …}` lifts the package's locks and marks
it uninstalled:

| `data` | what happens |
|---|---|
| `keep` | its objects and records stay, as the deployment's own |
| `export` | as `delete`, once `exports` lists a completed record export (`POST /api/v1/{entity}/export`) of every entity the package owns |
| `delete` | its entities, their views and queries, and the fields it added to other entities are retired through a metadata plan, queued like any apply (approval-gated where the deployment requires it) |

The uninstall writes a Configuration audit event. Every route here is for administrators only.

## Catalogue

Each deployment keeps a private catalogue of signed package versions (S13-T1).
`POST /api/v1/admin/packages/catalogue` adds one for review: pushed as `{"package": <document>}`
(signed by a trusted publisher), or taken from a partner catalogue as
`{"partner": "<name>", "package_id": "…", "version": "…"}`. A version already there is a conflict.
Each entry shows what the package asks of the deployment (its mode, contents, the entities it
brings or extends with their field counts, its roles and dependencies) and its review status.
`POST /api/v1/admin/packages/catalogue/{id}/review` with `{"decision": "approved" | "rejected",
"note": …}` reviews a pending version; the administrator who added it cannot. Only an approved
version installs: `POST /api/v1/admin/packages/catalogue/{id}/install` answers the same preview and
persisted plan as `packages/preview`, and installing is applying that plan.
`GET /api/v1/admin/packages/catalogue` lists the catalogue, newest first.

Partner catalogues are set in `packages.partner_catalogues`
(`[{"name", "url", "publisher", "key"}]`): an `https://` URL serving an index
`{"format": "attome-catalogue/v1", "packages": [<package>, …]}` and the Ed25519 key the partner's
packages are signed with. Configuring one trusts that key for its publisher.
`GET /api/v1/admin/packages/partner-catalogues/{name}` fetches the index and lists each package
with what it asks and whether it verifies against the partner's key. Adding and reviewing write a
Configuration audit event. Every route is for administrators only.
