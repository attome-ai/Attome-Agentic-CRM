# StoragePresignFailures

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

Signing presigned URLs is failing; each failure is a 500 on an upload or download route.

## Checks

1. Check the S3 credentials for {{storage}} (a rotation applies on restart).
2. Check the configured expiry range and the object key being signed.

## Fix

Correct the credentials or the expiry and restart.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
