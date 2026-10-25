-- A1-T1: a six-value sensitivity label on attributes and entities, beside
-- data_classification (kept for now: expand step). Existing attributes are
-- mapped from their classification and left unconfirmed, so a builder
-- confirms each; writing the label through the admin API confirms it.
ALTER TABLE attribute_info
    ADD COLUMN IF NOT EXISTS sensitivity varchar(20) NOT NULL DEFAULT 'internal'
        CHECK (sensitivity IN ('public', 'internal', 'personal', 'financial', 'health', 'secret')),
    ADD COLUMN IF NOT EXISTS sensitivity_confirmed boolean NOT NULL DEFAULT false;

ALTER TABLE entity_info
    ADD COLUMN IF NOT EXISTS sensitivity varchar(20) NOT NULL DEFAULT 'internal'
        CHECK (sensitivity IN ('public', 'internal', 'personal', 'financial', 'health', 'secret')),
    ADD COLUMN IF NOT EXISTS sensitivity_confirmed boolean NOT NULL DEFAULT false;

UPDATE attribute_info
   SET sensitivity = CASE data_classification
                         WHEN 'personal' THEN 'personal'
                         WHEN 'sensitive_special_category' THEN 'health'
                         ELSE 'internal'
                     END
 WHERE NOT sensitivity_confirmed;
