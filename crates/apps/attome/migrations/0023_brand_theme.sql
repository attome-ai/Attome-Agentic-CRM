-- B13-T1: brand themes and their assets. A theme belongs to a scope (the
-- deployment, an app, a business unit, a domain or a portal); each save is a
-- new version, and at most one version per scope is published.
CREATE TABLE IF NOT EXISTS theme (
    id uuid PRIMARY KEY,
    scope_kind text NOT NULL CHECK (scope_kind IN ('deployment', 'app', 'unit', 'domain', 'portal')),
    scope_ref text NOT NULL DEFAULT '',
    version integer NOT NULL,
    status text NOT NULL CHECK (status IN ('draft', 'published', 'retired')),
    tokens jsonb NOT NULL,
    contrast_report jsonb,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    UNIQUE (scope_kind, scope_ref, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS theme_one_published ON theme (scope_kind, scope_ref) WHERE status = 'published';

CREATE TABLE IF NOT EXISTS brand_asset (
    id uuid PRIMARY KEY,
    theme_id uuid NOT NULL REFERENCES theme(id),
    kind text NOT NULL CHECK (kind IN ('logo', 'logo_dark', 'favicon', 'font_arabic', 'font_latin', 'guidelines_pdf')),
    storage_key text NOT NULL,
    content_type text NOT NULL,
    byte_size bigint NOT NULL,
    sha256 text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON theme, brand_asset TO attome_runtime;
GRANT SELECT ON theme, brand_asset TO attome_readonly;
