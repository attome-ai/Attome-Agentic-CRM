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
