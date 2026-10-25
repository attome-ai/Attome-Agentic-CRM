-- Z12-T6: holiday rules and seasons are written through the admin API and
-- changesets like holidays, so they carry the layer that owns them (D-785)
-- and one live row per name within a calendar.
ALTER TABLE calendar_holiday_rule
    ADD COLUMN IF NOT EXISTS owner_layer text NOT NULL DEFAULT 'project'
        CHECK (owner_layer IN ('platform', 'product', 'project', 'customer'));
ALTER TABLE calendar_season
    ADD COLUMN IF NOT EXISTS owner_layer text NOT NULL DEFAULT 'project'
        CHECK (owner_layer IN ('platform', 'product', 'project', 'customer'));

CREATE UNIQUE INDEX IF NOT EXISTS calendar_holiday_rule_name_uq
    ON calendar_holiday_rule (calendar_id, name) WHERE is_active;
CREATE UNIQUE INDEX IF NOT EXISTS calendar_season_name_uq
    ON calendar_season (calendar_id, name) WHERE is_active;
