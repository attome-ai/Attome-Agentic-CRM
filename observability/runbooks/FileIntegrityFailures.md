# FileIntegrityFailures

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

The weekly file sample (one in a hundred stored files, at most 1,000) read back a file from the file store ({{storage}}) whose size or SHA-256 no longer matches what was recorded at upload, or found no file at its key. The file the user downloads is no longer the file they uploaded.

## Checks

1. Search the logs on {{node}} for `file integrity:`; each finding names the file version id and its storage key.
2. Read `file_integrity_failures_total` by `kind`: `mismatch` (changed contents) or `missing` (gone).
3. Check the store for recent restores, lifecycle rules or manual deletions on those keys, and the store's own health.

## Fix

Restore each named object from the latest backup of the file store; nothing is changed or deleted automatically. If many files are affected, stop and treat it as storage corruption or tampering before restoring.

## Escalation

Escalate to the platform on-call, and to security if tampering cannot be ruled out. This deployment's alert recipients: {{alert_emails}}.
