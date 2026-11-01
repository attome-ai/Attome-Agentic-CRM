-- K6-T5: the text-block hashes a source's last crawl saw on most of its
-- pages (a repeated related-links panel, a newsletter box). The next crawl
-- leaves them out of each page's main content.
SET LOCAL lock_timeout = '5s';

ALTER TABLE webcrawl_target
    ADD COLUMN IF NOT EXISTS repeated_blocks bigint[] NOT NULL DEFAULT '{}';
