-- L4-T1: the data catalog. One row per asset (entity, attribute, option set,
-- view, saved query, report, dashboard, metric, flow, agent tool), filled
-- when the asset is published, with its Arabic and English name and
-- description, domain, label and a search vector; and the requests people
-- make for access to an asset.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS catalog_asset (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    kind text NOT NULL CHECK (kind IN ('entity', 'attribute', 'option_set', 'view', 'saved_query',
        'report', 'dashboard', 'metric', 'flow', 'agent_tool')),
    ref text NOT NULL,
    parent_ref text,
    name_en text,
    name_ar text,
    description_en text,
    description_ar text,
    description_status text NOT NULL DEFAULT 'missing'
        CHECK (description_status IN ('missing', 'draft', 'reviewed')),
    domain_ref uuid,
    label text,
    search tsvector,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, ref)
);
CREATE INDEX IF NOT EXISTS catalog_asset_search_idx ON catalog_asset USING gin (search);
CREATE INDEX IF NOT EXISTS catalog_asset_kind_domain_idx ON catalog_asset (kind, domain_ref);

CREATE TABLE IF NOT EXISTS catalog_access_request (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    asset_id uuid NOT NULL REFERENCES catalog_asset (id) ON DELETE CASCADE,
    requester_id uuid NOT NULL,
    reason text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'granted', 'refused', 'withdrawn')),
    decided_by uuid,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS catalog_access_request_asset_idx ON catalog_access_request (asset_id, status);

GRANT SELECT, INSERT, UPDATE, DELETE ON catalog_asset, catalog_access_request TO attome_runtime;
GRANT SELECT ON catalog_asset, catalog_access_request TO attome_readonly;
