# Release signing

`attome-release tag <version>` signs each operating system's gate report
(`target/release-gate/gate-<os>.json`) with the release key and verifies the
signature before it tags (roadmap AC4-T9, D-673). A missing key, a key inside
the repository, a failed signature or a failed verification refuses the tag
with exit 3. Signing uses cosign 2.x and never contacts a transparency log, so
signing and verifying work offline.

## The key pair

The release key is made once, on the release machine, outside the repository:

```sh
mkdir ~/attome-release-key && cd ~/attome-release-key
cosign generate-key-pair          # asks for a password; writes cosign.key and cosign.pub
```

- `cosign.key` is the private key. It never enters the repository, an image or
  a backup of the working tree. Keep it offline, with two custodians, and write
  down the recovery procedure (who holds the copies, where the password is).
- `cosign.pub` is committed as `deploy/cosign.pub` and printed in each
  release's notes.

## Tagging

```sh
export COSIGN_KEY=~/attome-release-key/cosign.key   # PowerShell: $env:COSIGN_KEY = "..."
attome-release tag 1.4.0                            # cosign asks for the key's password
```

Each report gets a `.sig` beside it: `target/release-gate/gate-windows.json.sig`
and `gate-linux.json.sig`. Anyone can check one offline:

```sh
cosign verify-blob --insecure-ignore-tlog=true --key deploy/cosign.pub \
  --signature gate-windows.json.sig gate-windows.json
```

`Verified OK` means the report is the one the release machine signed.

## A lost or leaked key

Make a new key pair as above, commit the new `deploy/cosign.pub`, and say in
the next release's notes that the old key is revoked and from which version
the new one signs.
