-- E11-T1: a content space has a kind. A `marketing` space holds landing
-- pages (it starts with the landing templates and its form blocks name a
-- marketing form); every existing space is `standard`. A constant default
-- is metadata-only; the CHECK is added NOT VALID and validated separately.
SET LOCAL lock_timeout = '5s';

ALTER TABLE content_space ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'standard';
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'ck_content_space_kind'
           AND conrelid = 'content_space'::regclass
    ) THEN
        ALTER TABLE content_space
            ADD CONSTRAINT ck_content_space_kind
            CHECK (kind = ANY (ARRAY['standard', 'marketing'])) NOT VALID;
    END IF;
END
$$;
ALTER TABLE content_space VALIDATE CONSTRAINT ck_content_space_kind;
