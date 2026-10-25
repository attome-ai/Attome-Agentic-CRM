# File storage

Attachments, exports, report output, generated documents and brand assets live in object storage.
`storage.backend` chooses where; every backend goes through the same `object_store` client, so
nothing else changes with it.

| `storage.backend` | Where files go | Settings |
|---|---|---|
| `s3` (default) | An S3-compatible bucket: AWS S3, RustFS, MinIO | `storage.s3_endpoint`, `s3_public_endpoint`, `s3_region`, `s3_access_key`, `s3_secret_key`, `s3_bucket`, `s3_verify_ssl` |
| `local` | A folder on this machine | `storage.local.path`, `storage.local.url_signing_key`, `storage.local.public_base_url` |
| `azure` | An Azure Blob Storage container | `storage.azure.account`, `container`, `access_key`, `endpoint` |
| `gcs` | A Google Cloud Storage bucket | `storage.gcs.bucket`, `storage.gcs.service_account_key` |

Only the chosen backend's settings are read; the others may be left out. Boot refuses a backend
whose settings are missing. Secrets (`s3_secret_key`, `local.url_signing_key`, `azure.access_key`,
`gcs.service_account_key`) come from the environment in production (`${VAR}` or `VAR_FILE`).

## How browsers reach the files

Browsers upload and download files directly, with short-lived signed links the server hands out
after checking the caller's permission on that file:

- **S3, Azure and GCS** sign their own URLs (SigV4, a shared access signature, a V4 signature),
  and the browser talks to the bucket. The bucket must accept the browser's origin (CORS).
- **Local disk** has no address of its own, so the links point at the server:
  `/api/v1/storage/local?key=…&expires=…&signature=…`. The signature is an HMAC-SHA256 under
  `storage.local.url_signing_key` over the method, the file's key and the expiry, so a download
  link does not open an upload, and a changed key or expiry is refused. An expired or altered
  link is a 404. Downloads are always sent as attachments, never shown in the browser.

A signed link is a bearer credential until it expires: anyone holding it can use it. Configure any
proxy in front of the server or the bucket **not to log query strings** on these paths.

## Local disk

```json
"storage": {
  "backend": "local",
  "local": {
    "path": "C:\\ProgramData\\Attome\\files",
    "url_signing_key": "${ATTOME_STORAGE_LINK_KEY}",
    "public_base_url": ""
  }
}
```

- `path` is created at boot when it does not exist. Back it up with the database
  (`docs/backup.md` copies files on every backend).
- `url_signing_key` is at least 32 bytes (`openssl rand -hex 32`). Every process of the
  deployment (the server and a separate worker) needs the same value, so a link one makes is
  accepted by the other. Changing it invalidates links already handed out, which expire within
  minutes anyway.
- `public_base_url` is the address browsers reach the server at (`https://crm.example.com`).
  Empty hands out links relative to the server, which is right when the web app and the API share
  an origin. Production requires `https://` here.
- One node only: other servers cannot see the folder. Use a bucket for more than one node.
- An upload through the server is bounded by `app.max_body_size_bytes` and the request timeout,
  as every request is. Raise `app.max_body_size_bytes` to at least `storage.max_upload_size_bytes`
  for uploads that large.

## Azure Blob Storage

```json
"storage": {
  "backend": "azure",
  "azure": {
    "account": "attomefiles",
    "container": "attome",
    "access_key": "${AZURE_STORAGE_KEY}",
    "endpoint": ""
  }
}
```

Use the storage account's shared key: links are signed with it. `endpoint` is empty for the public
Azure cloud, or names an Azurite emulator or a sovereign cloud endpoint.

## Google Cloud Storage

```json
"storage": {
  "backend": "gcs",
  "gcs": {
    "bucket": "attome-files",
    "service_account_key": "${GCS_SERVICE_ACCOUNT_JSON}"
  }
}
```

`service_account_key` is the JSON key document Google issues for the service account; links are
signed with its private key. A sovereign deployment (`deployment.sovereign`) refuses `gcs` and the
public Azure cloud, as it refuses AWS S3.

## Timeouts and retries

Every cloud backend uses the same bounds: 10 s to connect, 30 s per attempt, at most 10 retries
within 180 s. Local disk has no network to wait on.

## Encryption at rest

S3, Azure and GCS encrypt what they store themselves; turn that on in the bucket or account.
Local disk does not, so the server can encrypt files before they reach it:

```json
"storage": {
  "backend": "local",
  "encryption_key": "${ATTOME_STORAGE_ENCRYPTION_KEY}"
}
```

- `storage.encryption_key` is a key ring like the other `*_encryption_key` settings: one 64-hex-char
  key (`openssl rand -hex 32`), or `{"keys": {"k1": "…", "k2": "…"}, "active_key_id": "k2"}`. Set,
  every file written to local disk is encrypted; empty, none is.
- Each file gets its own random AES-256-GCM key, sealed under the ring's active key and kept in the
  file's first 334 bytes. The file is encrypted in 1 MiB pieces, so a download or a byte range reads
  only the pieces it needs and never holds the whole file in memory. A file that was altered, cut
  short or given another file's header does not open.
- **Rotation:** add a new key, make it active, and keep the old one in the ring. New files use the
  new key; old files still name the old one and keep opening. Removing a key from the ring makes the
  files sealed under it unreadable.
- Files written before encryption was turned on read back as they are; they stay unencrypted until
  they are written again (or copied with `attome storage migrate` to an encrypting target).
- `storage.encrypt_client_side: true` encrypts on S3, Azure and GCS too. Signed download links then
  hand out ciphertext, so use it only when downloads go through the server.
- A listing of the store reports stored sizes (with the header and the 16 bytes per piece); a file's
  own size is the plaintext size.

## Moving to another backend

`attome storage migrate` copies every file from the current backend to a new one:

```
attome storage migrate --from config.json --to config.new.json [--state storage-migrate.state]
```

`config.new.json` is a copy of the deployment's config with the new `storage` section. The command:

1. lists every file of the source and copies 100 at a time, 8 at once;
2. reads each copy back from the target and checks its size and SHA-256 against the source;
3. appends each verified file to the state file, so running it again after a stop continues where
   it left off and copies only files that are new or failed;
4. refuses a target outside `deployment.data_region` (an S3 bucket in another region, or Azure or
   GCS, which name no region to check);
5. never deletes a source file.

Each side's encryption applies: an encrypted local folder is read as plaintext, and a target with
`encryption_key` set encrypts what it receives. To switch over: run it while the server runs, stop
the server, run it once more to copy what arrived meanwhile, put the new `storage` section in the
deployment's config and start the server. Delete the old files only after checking the new backend.
