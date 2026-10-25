-- S2-T16: the builder's OpenAPI overlay (OpenAPI Overlay 1.0 actions that
-- set a summary, description or example on a path or operation), applied to
-- the deployment document GET /api/v1/openapi/deployment.json when it is
-- served. One row at most; written only through
-- PUT /api/v1/admin/openapi/overlay.
CREATE TABLE IF NOT EXISTS openapi_overlay (
    id          uuid        PRIMARY KEY,
    overlay     jsonb       NOT NULL CHECK (jsonb_typeof(overlay) = 'object'),
    row_version bigint      NOT NULL DEFAULT 1,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  uuid
);

CREATE UNIQUE INDEX IF NOT EXISTS openapi_overlay_one_row ON openapi_overlay ((true));

GRANT SELECT, INSERT, UPDATE, DELETE ON openapi_overlay TO attome_runtime;
GRANT SELECT ON openapi_overlay TO attome_readonly;
