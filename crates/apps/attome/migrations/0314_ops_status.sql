-- AB11-T1: the status page's data. Components (each named after the
-- capability probe that decides its state; `records` is the database, so it
-- names none), incidents and their append-only updates (a correction is a
-- new update naming the one it corrects), maintenance windows, and status
-- subscribers. A subscriber is an address, not a CRM record, so its consent
-- is kept on its own row rather than in the record consent ledger (0093);
-- its unsubscribe token is stored only as a hash.
CREATE TABLE IF NOT EXISTS ops_status_component (
    key text PRIMARY KEY,
    name_en text NOT NULL,
    name_ar text NOT NULL,
    capability text,
    public boolean NOT NULL DEFAULT true,
    sort integer NOT NULL DEFAULT 0
);

INSERT INTO ops_status_component (key, name_en, name_ar, capability, sort) VALUES
    ('sign_in', 'Sign-in', 'تسجيل الدخول', 'cache', 10),
    ('records', 'Records', 'السجلات', NULL, 20),
    ('search', 'Search', 'البحث', 'search_index', 30),
    ('email', 'Email', 'البريد الإلكتروني', 'email', 40),
    ('ai', 'AI assistant', 'المساعد الذكي', 'ai_model', 50),
    ('portal', 'Portal', 'البوابة', NULL, 60),
    ('integrations', 'Integrations', 'التكاملات', 'connectors', 70)
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS ops_incident (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    title_en text NOT NULL,
    title_ar text,
    audience text NOT NULL DEFAULT 'internal' CHECK (audience IN ('internal', 'public')),
    state text NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft', 'investigating', 'identified', 'monitoring', 'resolved')),
    components text[] NOT NULL DEFAULT '{}',
    impact text NOT NULL DEFAULT 'degraded' CHECK (impact IN ('degraded', 'partial', 'major')),
    started_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    published_at timestamptz,
    created_by uuid,
    auto_created boolean NOT NULL DEFAULT false,
    row_version bigint NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS ops_incident_open_idx
    ON ops_incident (started_at DESC) WHERE resolved_at IS NULL;

CREATE TABLE IF NOT EXISTS ops_incident_update (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    incident_id uuid NOT NULL REFERENCES ops_incident (id),
    stage text NOT NULL
        CHECK (stage IN ('investigating', 'identified', 'monitoring', 'resolved', 'note')),
    body_en text NOT NULL,
    body_ar text,
    corrects_update_id uuid REFERENCES ops_incident_update (id),
    published_by uuid,
    published_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ops_incident_update_incident_idx
    ON ops_incident_update (incident_id, published_at);

CREATE OR REPLACE FUNCTION ops_incident_update_keep() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ops_incident_update is append-only; publish a correction instead';
END;
$$;

DROP TRIGGER IF EXISTS ops_incident_update_keep ON ops_incident_update;
CREATE TRIGGER ops_incident_update_keep BEFORE UPDATE OR DELETE ON ops_incident_update
    FOR EACH ROW EXECUTE FUNCTION ops_incident_update_keep();

CREATE TABLE IF NOT EXISTS ops_maintenance (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    title_en text NOT NULL,
    title_ar text,
    components text[] NOT NULL DEFAULT '{}',
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    audience text NOT NULL DEFAULT 'internal' CHECK (audience IN ('internal', 'public')),
    created_by uuid,
    cancelled_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    CHECK (ends_at > starts_at)
);

CREATE INDEX IF NOT EXISTS ops_maintenance_window_idx
    ON ops_maintenance (starts_at) WHERE cancelled_at IS NULL;

CREATE TABLE IF NOT EXISTS ops_status_subscriber (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    channel text NOT NULL CHECK (channel IN ('email', 'webhook', 'sms', 'whatsapp')),
    address text NOT NULL,
    components text[] NOT NULL DEFAULT '{}',
    audience text NOT NULL DEFAULT 'public' CHECK (audience IN ('internal', 'public')),
    consent_at timestamptz NOT NULL,
    consent_source text,
    unsubscribe_token_hash text NOT NULL,
    confirmed_at timestamptz,
    removed_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS ops_status_subscriber_address_key
    ON ops_status_subscriber (channel, lower(address)) WHERE removed_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ops_status_subscriber_token_key
    ON ops_status_subscriber (unsubscribe_token_hash);

GRANT SELECT ON ops_status_component TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON ops_incident, ops_maintenance, ops_status_subscriber
    TO attome_runtime;
GRANT SELECT, INSERT ON ops_incident_update TO attome_runtime;
GRANT SELECT ON ops_status_component, ops_incident, ops_incident_update, ops_maintenance,
    ops_status_subscriber TO attome_readonly;
