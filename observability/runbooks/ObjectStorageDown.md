# ObjectStorageDown

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

The file store ({{storage}}) fails its probe for 2 minutes. Uploads, downloads and reads of stored files fail; the capability gate refuses object-storage routes.

## Checks

1. Check the store's health (RustFS or MinIO) and its logs.
2. Check connectivity from {{node}} to the endpoint.
3. Read `{{api_base}}/health/dependencies` (administrator API key).

## Fix

Restart or repair the store; the gate reopens on its own once the probe passes.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
