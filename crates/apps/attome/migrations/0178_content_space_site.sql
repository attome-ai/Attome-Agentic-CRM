-- E12-T2: a content space is a site. Its own domain (served by host), a
-- site title, a theme (CSS custom properties), a menu (ordered links), and
-- the path under which its pages are its blog (listed in its RSS feed).
SET LOCAL lock_timeout = '5s';

ALTER TABLE content_space ADD COLUMN IF NOT EXISTS domain text;
ALTER TABLE content_space ADD COLUMN IF NOT EXISTS site_title text;
ALTER TABLE content_space ADD COLUMN IF NOT EXISTS theme jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE content_space ADD COLUMN IF NOT EXISTS menu jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE content_space ADD COLUMN IF NOT EXISTS blog_path text;

-- One live space per domain.
CREATE UNIQUE INDEX IF NOT EXISTS content_space_domain_uq
    ON content_space (lower(domain)) WHERE domain IS NOT NULL AND is_deleted = FALSE;
