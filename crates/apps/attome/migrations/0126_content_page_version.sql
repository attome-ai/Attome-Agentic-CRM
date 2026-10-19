-- K5-T1: every publish of a content page keeps a numbered version (its
-- title, SEO text and published blocks), so an editor can compare two
-- versions and restore an old one; restoring publishes a new version that
-- names the one it came from. A space may require approval before a page
-- in it is published (Z10's approval engine).
CREATE TABLE IF NOT EXISTS content_page_version (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    page_id         uuid        NOT NULL,
    version_number  integer     NOT NULL CHECK (version_number >= 1),
    title           text        NOT NULL,
    blocks          jsonb       NOT NULL,
    seo_title       text,
    seo_description text,
    published_by    uuid        NOT NULL,
    published_at    timestamptz NOT NULL DEFAULT now(),
    restored_from   integer,
    CONSTRAINT content_page_version_number_unique UNIQUE (page_id, version_number)
);

ALTER TABLE content_space ADD COLUMN IF NOT EXISTS require_approval boolean NOT NULL DEFAULT false;

GRANT SELECT, INSERT, UPDATE, DELETE ON content_page_version TO attome_runtime;
GRANT SELECT ON content_page_version TO attome_readonly;
