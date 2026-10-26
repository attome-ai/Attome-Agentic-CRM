# Secrets in the configuration

A secret never goes into `config.json` itself. The file names it with a placeholder,
`"password": "${DATABASE_PASSWORD}"`, and the server fills the placeholder when it starts. A
production configuration with a secret typed into the file does not start.

## Where a placeholder's value comes from

In this order, the first that answers wins:

1. **A cloud secret store**, when `ATTOME_SECRET_SOURCE` is set (below).
2. **The environment variable** of the same name, `DATABASE_PASSWORD`.
3. **A file** named by `DATABASE_PASSWORD_FILE`: its contents, trimmed (the Docker and Kubernetes
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
