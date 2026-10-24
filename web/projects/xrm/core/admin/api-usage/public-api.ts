// S10-T1 — the API usage screen (`/xrm/admin/api-usage`): requests per key
// and per route, and each key's own quota. Its own secondary entry point so
// the `@attome/xrm/core/admin` barrel does not carry it (D-314); the service
// and wire types live in `@attome/xrm/core/admin/data`.
export { ApiUsageComponent, parseQuota } from './api-usage.component';
