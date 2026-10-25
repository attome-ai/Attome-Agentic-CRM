-- S8-T4: calls by API version and route, per API key and S2S client, by
-- day. Filled by the nightly usage rollup from a Redis buffer the
-- api_version layer counts into; read by GET /api/v1/admin/api-versions/usage.
-- Counts only, never a payload. caller_id has no foreign key: a deleted key
-- or client keeps its history.
CREATE TABLE IF NOT EXISTS api_version_usage (
    usage_date     date    NOT NULL,
    caller_kind    text    NOT NULL CHECK (caller_kind IN ('api_key', 's2s_client')),
    caller_id      uuid    NOT NULL,
    api_version    text    NOT NULL,
    route_template text    NOT NULL,
    deprecated     boolean NOT NULL DEFAULT false,
    request_count  bigint  NOT NULL DEFAULT 0,
    PRIMARY KEY (usage_date, caller_kind, caller_id, api_version, route_template)
);

CREATE INDEX IF NOT EXISTS api_version_usage_deprecated_idx
    ON api_version_usage (usage_date) WHERE deprecated;

GRANT SELECT, INSERT, UPDATE, DELETE ON api_version_usage TO attome_runtime;
GRANT SELECT ON api_version_usage TO attome_readonly;
