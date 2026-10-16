-- K6-T1: website source settings on a crawl target, and the change-tracking
-- facts the polite recrawl (K6-T2) keeps per page. Every column has a
-- default, so existing targets and pages read as before.
ALTER TABLE webcrawl_target
    ADD COLUMN IF NOT EXISTS include_patterns text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS exclude_patterns text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS languages text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS audience text NOT NULL DEFAULT 'internal'
        CHECK (audience IN ('internal', 'partner', 'customer')),
    ADD COLUMN IF NOT EXISTS import_mode text NOT NULL DEFAULT 'review'
        CHECK (import_mode IN ('review', 'automatic')),
    ADD COLUMN IF NOT EXISTS schedule text NOT NULL DEFAULT 'manual'
        CHECK (schedule IN ('manual', 'daily', 'weekly')),
    ADD COLUMN IF NOT EXISTS sitemap_url text,
    ADD COLUMN IF NOT EXISTS watch_only boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS allow_host text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS credential_ref text;

ALTER TABLE webcrawl_page
    ADD COLUMN IF NOT EXISTS etag text,
    ADD COLUMN IF NOT EXISTS last_modified text,
    ADD COLUMN IF NOT EXISTS content_hash text,
    ADD COLUMN IF NOT EXISTS missing_count integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS alias_of uuid REFERENCES webcrawl_page (id),
    ADD COLUMN IF NOT EXISTS language text;
