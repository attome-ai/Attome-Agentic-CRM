-- Z12-T3: calendar v2. Inheritance and an Arabic name on calendars, holiday
-- rules (fixed or Hijri, some needing a moon sighting), seasons, content
-- versions, user and team assignments, sighting confirmations and feeds.
ALTER TABLE calendar
    ADD COLUMN IF NOT EXISTS parent_calendar_id uuid REFERENCES calendar (id),
    ADD COLUMN IF NOT EXISTS country_code text,
    ADD COLUMN IF NOT EXISTS name_ar text,
    ADD COLUMN IF NOT EXISTS current_version integer NOT NULL DEFAULT 1;

ALTER TABLE calendar_holiday
    ADD COLUMN IF NOT EXISTS name_ar text,
    ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'manual'
        CHECK (source IN ('manual', 'feed', 'pack'));

CREATE TABLE IF NOT EXISTS calendar_holiday_rule (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    calendar_id uuid NOT NULL REFERENCES calendar (id) ON DELETE CASCADE,
    name text NOT NULL,
    name_ar text,
    rule jsonb NOT NULL,
    needs_sighting boolean NOT NULL DEFAULT false,
    is_active boolean NOT NULL DEFAULT true,
    row_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid
);

CREATE TABLE IF NOT EXISTS calendar_season (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    calendar_id uuid NOT NULL REFERENCES calendar (id) ON DELETE CASCADE,
    name text NOT NULL,
    name_ar text,
    definition jsonb NOT NULL,
    is_active boolean NOT NULL DEFAULT true,
    row_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid
);

CREATE TABLE IF NOT EXISTS calendar_version (
    calendar_id uuid NOT NULL REFERENCES calendar (id) ON DELETE CASCADE,
    version integer NOT NULL,
    canonical text NOT NULL,
    content_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (calendar_id, version)
);

CREATE TABLE IF NOT EXISTS calendar_assignment (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    subject_type text NOT NULL CHECK (subject_type IN ('user', 'team')),
    subject_id uuid NOT NULL,
    calendar_id uuid NOT NULL REFERENCES calendar (id) ON DELETE CASCADE,
    row_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (subject_type, subject_id)
);

CREATE TABLE IF NOT EXISTS calendar_sighting (
    rule_id uuid NOT NULL REFERENCES calendar_holiday_rule (id) ON DELETE CASCADE,
    hijri_year integer NOT NULL,
    confirmed_start date NOT NULL,
    confirmed_by uuid NOT NULL,
    confirmed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, hijri_year)
);

CREATE TABLE IF NOT EXISTS calendar_feed (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    calendar_id uuid NOT NULL REFERENCES calendar (id) ON DELETE CASCADE,
    url text NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    etag text,
    last_fetched_at timestamptz,
    last_error text,
    row_version bigint NOT NULL DEFAULT 0
);

-- Version 1 of every existing calendar, with an empty hash that the loader
-- recomputes on first load.
INSERT INTO calendar_version (calendar_id, version, canonical, content_hash)
SELECT id, 1, '', '' FROM calendar
ON CONFLICT (calendar_id, version) DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON calendar_holiday_rule, calendar_season, calendar_version,
    calendar_assignment, calendar_sighting, calendar_feed TO attome_runtime;
GRANT SELECT ON calendar_holiday_rule, calendar_season, calendar_version, calendar_assignment,
    calendar_sighting, calendar_feed TO attome_readonly;
