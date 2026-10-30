# Secrets in the configuration

A secret never goes into `config.json` itself. The file names it with a placeholder,
`"password": "${DATABASE_PASSWORD}"`, and the server fills the placeholder when it starts. A
production configuration with a secret typed into the file does not start.

## Where a placeholder's value comes from

In this order, the first that answers wins:

1. **A key unwrapped by your key service**, when `NAME_KMS` and `ATTOME_KMS` are set (see
   "Customer-held master keys" below).
2. **A cloud secret store**, when `ATTOME_SECRET_SOURCE` is set (below).
3. **The environment variable** of the same name, `DATABASE_PASSWORD`.
4. **A file** named by `DATABASE_PASSWORD_FILE`: its contents, trimmed (the Docker and Kubernetes
   secret-file convention).

A placeholder nothing answers stops the start, naming the placeholder and where it is used.

## Cloud secret stores

The store is read **once**, before the configuration loads, by `attome serve`, `attome worker`,
`attome migrate` and `attome preflight`. Nothing refreshes it afterwards: a rotated secret takes
a restart. The whole read must finish within 10 seconds; if it fails, the start stops with a
message naming the store and the step, never a secret's value. Only the secrets whose names begin
with the prefix are read (at most 500).

| Variable | Meaning |
|---|---|
| `ATTOME_SECRET_SOURCE` | `aws` or `azure`; unset reads no store |
| `ATTOME_SECRET_SOURCE_PREFIX` | The name prefix of Attome's secrets, such as `attome/` |

### AWS Secrets Manager

| Variable | Meaning |
|---|---|
| `ATTOME_SECRET_SOURCE_REGION` | The region, else `AWS_REGION` |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | An access key allowed `secretsmanager:BatchGetSecretValue`, `ListSecrets` and `GetSecretValue` on the prefix |
| `AWS_SESSION_TOKEN` | With temporary credentials |

The secret `attome/DATABASE_PASSWORD` answers `${DATABASE_PASSWORD}`. Only text secrets
(`SecretString`) are read. Credentials come from these variables only; instance and container
roles are not read.

### Azure Key Vault

| Variable | Meaning |
|---|---|
| `ATTOME_SECRET_SOURCE_VAULT_URL` | The vault, `https://<name>.vault.azure.net` |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | A service principal allowed to list and get secrets |

Vault names allow letters, digits and `-` only, so each `-` after the prefix reads as `_`: under
the prefix `attome-`, the secret `attome-DATABASE-PASSWORD` answers `${DATABASE_PASSWORD}`.
Disabled secrets are skipped.

Both stores are built into the release binary (cargo features `aws-secrets` and
`azure-keyvault`, on by default); neither adds a native dependency.

## Customer-held master keys

A key you keep in your own key service (AWS KMS, Azure Key Vault, Google Cloud KMS, or an HSM)
reaches Attome wrapped, so the plain key is never written to a file or a variable. Wrap the exact
text the placeholder would hold (a 64-hex key, say) with your key, put the ciphertext in base64 in
`NAME_KMS` (in the environment or the secret store), and set `ATTOME_KMS`:

```text
ATTOME_KMS=aws
AWS_REGION=me-central-1
JWT_SECRET_KMS=AQICAHh...   # aws kms encrypt --plaintext fileb://jwt.hex, base64
```

At start, `attome serve`, `attome worker`, `attome migrate` and `attome preflight` unwrap every
`*_KMS` value once, and `${JWT_SECRET}` answers the unwrapped key ahead of the secret store and the
environment. The keys are held only while the configuration loads; a rotated key takes a restart.

Until then the node is **sealed**: it does not start when the key service cannot be reached within
15 seconds or refuses a value, when a value is not base64 or does not unwrap to text, when a
`*_KMS` value is set without `ATTOME_KMS`, or when `ATTOME_KMS` is set with nothing to unwrap. The
message names the service, the step and the placeholder, never a key. Losing the key in your key
service means losing what it protects: keep the key's own backup or escrow in the key service.

| `ATTOME_KMS` | Unwraps with | Settings |
|---|---|---|
| `aws` | `Decrypt` (symmetric key) | `ATTOME_KMS_REGION` or `AWS_REGION`; `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN` (allowed `kms:Decrypt`); optional `ATTOME_KMS_KEY_ID` pins the key |
| `azure` | `unwrapkey`, RSA-OAEP-256 | `ATTOME_KMS_KEY_URL`, `https://<vault>.vault.azure.net/keys/<name>/<version>`; `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` (allowed `unwrapKey`) |
| `gcp` | `decrypt` (symmetric key) | `ATTOME_KMS_KEY_NAME`, `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`; `GOOGLE_OAUTH_ACCESS_TOKEN`, or `GOOGLE_APPLICATION_CREDENTIALS` naming a service account key file (role `cloudkms.cryptoKeyDecrypter`) |
| `hsm` | PKCS#11 `C_Decrypt`, RSA-OAEP with SHA-256 | `ATTOME_HSM_MODULE` (the vendor's PKCS#11 library, a DLL on Windows), `ATTOME_HSM_SLOT` (default the first slot with a token), `ATTOME_HSM_PIN`, `ATTOME_HSM_KEY_LABEL` (the RSA private key's label) |

Google's metadata server is not used: Attome's outbound calls never reach a metadata address.
AWS, Azure and Google are built into the release binary (cargo features `aws-secrets`,
`azure-keyvault` and `gcp-kms`, on by default). The HSM needs a binary built with the `hsm`
feature; it loads the vendor's library at start and adds no build-time native dependency.

## Key rings

A secret that signs or encrypts (the session key, the MFA and S2S encryption keys, the API-key
pepper and the others `attome secrets` lists) can hold several keys at once, so a rotation never
breaks what the old key made. In the environment it is one string:

```text
JWT_SECRET=ring:k2=<new key>;k1=<old key>
```

The first key is the active one: it signs and encrypts from the next start. The others are only
read, so a session or a stored value made with them keeps working until it is moved onto the new
key. Every key needs an id and a value, and ids are unique. A plain value (no `ring:`) is a ring of
one key.

## Rotating a secret

1. `attome secrets rotate JWT_SECRET --env-file .env` writes a new active key in front of the
   current one (`ring:<new id>=<new>;<old id>=<old>`), after copying the file to `.env.bak`. With a
   cloud store or a secret file, put the same ring into the store or the file yourself.
2. Restart every server and worker, so they all sign and encrypt with the new key.
3. Move stored data onto the new key:
   `attome secrets rewrap <domain> --api-key <key>` (`POST /api/v1/admin/security/rewrap/{domain}`,
   for example `mfa`, `s2s` or `erasure`). When rewraps need approval, a second administrator
   approves the request first.
4. Once the rewrap has finished and old sessions have expired, drop the old key from the ring and
   restart again.

`attome secrets generate --env-file .env` fills the secrets the platform makes itself (encryption
keys, peppers, the application roles' passwords) where they are missing; it never invents a
provider's credential and never changes a value already there. No command prints a secret.

## The inventory

Each start records every secret that is set, with its key ids, never a value or anything derived
from one. `GET /api/v1/admin/secrets` lists them with the age of each active key; a new active key
id is a rotation. A daily job reminds administrators of a secret whose active key is older than
`security.secret_max_age_days` (365 by default, `0` turns the reminder off).

## A secret typed into the file

On the `production` profile, a secret written into `config.json` as a value, not a `${NAME}`
placeholder, stops the start and names the path. Move it into the environment, a secret file or the
cloud store.
