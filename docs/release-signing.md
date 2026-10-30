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

## The release manifest

Each release also ships a signed manifest (`attome-release-manifest/v1`, AB8-T1;
`schemas/attome-release-manifest-v1.schema.json`): the versions it upgrades from, whether the
upgrade pauses writes and for how long, the features it removes and how to check for them, the
contract SQL it runs later, the digest of every artifact and the impact per module in English and
Arabic. It is signed with an Ed25519 release key (a 32-byte seed, kept like `cosign.key`), and the
binary trusts the public keys in `crates/apps/attome/src/release_keys.rs`: two slots, the current
key and the next, so the key can rotate. The slots hold placeholders whose private halves were
never kept; put the real public keys there before the first release that ships a manifest.
`attome_ops::release_manifest::verify_manifest` refuses an unsigned or altered manifest and one
signed by a key not listed.

## A lost or leaked key

Make a new key pair as above, commit the new `deploy/cosign.pub`, and say in
the next release's notes that the old key is revoked and from which version
the new one signs.
