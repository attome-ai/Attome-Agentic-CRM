-- K5-T4: linked translations. A translation is its own page (its own URL,
-- draft, versions and audience) that names the page it translates and the
-- source version it was last brought up to date with; it is stale while the
-- source has a newer published version. One translation per language.
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS language text;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS translation_of uuid;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS translated_from_version integer;
ALTER TABLE content_page DROP CONSTRAINT IF EXISTS content_page_translation_of_fkey;
ALTER TABLE content_page ADD CONSTRAINT content_page_translation_of_fkey
    FOREIGN KEY (translation_of) REFERENCES content_page (id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_content_page_translation_language
    ON content_page (translation_of, language)
    WHERE is_deleted = false AND translation_of IS NOT NULL;
