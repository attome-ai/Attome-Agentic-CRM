# The drill host

`attome drill agent` runs on a **drill host**: a machine that is not a production node, holds a recent
copy of the backups and can start the server binary. It asks the deployment which recovery drills are
due, checks it is ready, runs each, and uploads the signed evidence. The deployment never runs a drill
itself.

```text
attome drill agent --deployment-url https://crm.example --api-key-file ops-drill.key --config drill-agent.json [--once]
```

`--once` polls once and exits (a test, or a manual run); without it the agent polls every 10 minutes.
Exit codes: 0 all uploaded, 3 a drill or an upload failed, 4 readiness failed.

## `drill-agent.json`

```json
{
  "signing_key": "drill-signing.key",
  "out": "evidence",
  "restore": {
    "server_binary": "/opt/attome/attome",
    "expected_digest": "<sha256 of that binary>",
    "api_key_file": "restore-read.key",
    "archive": "latest",
    "port": 7999,
    "config": "/etc/attome/config.json"
  }
}
```

| Field | Meaning |
|---|---|
| `signing_key` | The drill signing key (`attome drill keygen --out <dir>`); a relative path is read next to this file |
| `out` | Where evidence is written |
| `restore.server_binary`, `restore.expected_digest` | The binary the restore drill boots, and its SHA-256 (provenance) |
| `restore.api_key_file` | A read-only key of the deployment, for the drill's sample reads |
| `restore.archive`, `restore.port`, `restore.config` | `latest` or an archive name; the drill's port (default 7999); the configuration the restore reads |

The file names key files; it never holds a key. Keep the key files readable by the service account only.
The JSON format is used because the command-line tool carries no TOML reader.

The key of `--api-key-file` needs only `ops.drill.run`. A due kind with no parameters here (v2 runs
`restore` drills from the agent) is reported and stays due.

## What a poll does

1. `GET /api/v1/ops/drills/due`. Nothing due: done.
2. `attome drill readiness`. When it fails, a signed `Restore` evidence with the check `readiness` failed
   and `overall_ok` false is uploaded, so the failure shows on the deployment's drill page, and nothing
   else runs.
3. Each due kind runs, and its evidence is uploaded to `POST /api/v1/ops/drills/evidence`, up to five
   tries with waits of 2, 4, 8 and 16 seconds.

## Install

**Windows** (an administrator prompt; `attome.exe` and the files under `C:\attome-drill`):

```text
sc.exe create AttomeDrillAgent binPath= "C:\attome-drill\attome.exe drill agent --deployment-url https://crm.example --api-key-file C:\attome-drill\ops-drill.key --config C:\attome-drill\drill-agent.json" start= delayed-auto obj= ".\attome-drill" password= "<the account's password>"
sc.exe description AttomeDrillAgent "Attome recovery drill agent"
sc.exe start AttomeDrillAgent
```

Warning: the API key is a file on this host, and Windows has no built-in secret store for a service.
Give `ops-drill.key` and `drill-signing.key` an ACL for the service account only
(`icacls <file> /inheritance:r /grant:r attome-drill:R`), and never put a key in the service's command
line or in `drill-agent.json`.

**Linux** (`/etc/systemd/system/attome-drill-agent.service`):

```ini
[Unit]
Description=Attome recovery drill agent
After=network-online.target

[Service]
User=attome-drill
ExecStart=/opt/attome/attome drill agent --deployment-url https://crm.example --api-key-file /etc/attome-drill/ops-drill.key --config /etc/attome-drill/drill-agent.json
Restart=on-failure
RestartSec=60
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/attome-drill

[Install]
WantedBy=multi-user.target
```

```text
sudo install -d -o attome-drill -m 0700 /etc/attome-drill /var/lib/attome-drill
sudo systemctl enable --now attome-drill-agent
```

Never run the agent on a production node: a restore drill restores the newest backup into a throwaway
database on the host's own PostgreSQL server and starts the server binary against it.
