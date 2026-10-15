-- E13-T3: search-engine settings and evidence for content pages: canonical
-- URL, noindex/nofollow, Open Graph fields and the audit score on the page;
-- the audit's findings; topic clusters around a pillar page; daily search
-- statistics per page and engine; and per site the robots.txt body and the
-- built sitemap parts (site_key is the site's host name, as E12 uses it).
SET LOCAL lock_timeout = '5s';

ALTER TABLE content_page ADD COLUMN IF NOT EXISTS seo_canonical_url text;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS seo_noindex boolean NOT NULL DEFAULT false;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS seo_nofollow boolean NOT NULL DEFAULT false;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS og_title text;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS og_description text;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS og_image_ref uuid;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS seo_score smallint;
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS seo_audited_at timestamptz;

CREATE TABLE IF NOT EXISTS content_seo_finding (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    page_ref uuid NOT NULL REFERENCES content_page (id),
    rule text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('info', 'warning', 'error')),
    block_ref text,
    detail jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS content_seo_finding_page_idx ON content_seo_finding (page_ref);

CREATE TABLE IF NOT EXISTS content_seo_topic (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL,
    language text NOT NULL,
    pillar_page_ref uuid REFERENCES content_page (id),
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS content_seo_topic_page (
    topic_ref uuid NOT NULL REFERENCES content_seo_topic (id) ON DELETE CASCADE,
    page_ref uuid NOT NULL REFERENCES content_page (id),
    PRIMARY KEY (topic_ref, page_ref)
);

CREATE TABLE IF NOT EXISTS content_search_stat (
    page_ref uuid NOT NULL,
    stat_date date NOT NULL,
    source text NOT NULL CHECK (source IN ('google', 'bing')),
    impressions integer NOT NULL,
    clicks integer NOT NULL,
    avg_position real,
    top_queries jsonb NOT NULL DEFAULT '[]',
    PRIMARY KEY (page_ref, stat_date, source)
);

CREATE TABLE IF NOT EXISTS content_site_robots (
    site_key text PRIMARY KEY,
    body text NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    updated_by uuid,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS content_sitemap (
    site_key text NOT NULL,
    lang text NOT NULL,
    part integer NOT NULL,
    xml text NOT NULL,
    built_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_key, lang, part)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON content_seo_finding, content_seo_topic,
    content_seo_topic_page, content_search_stat, content_site_robots, content_sitemap
    TO attome_runtime;
GRANT SELECT ON content_seo_finding, content_seo_topic, content_seo_topic_page,
    content_search_stat, content_site_robots, content_sitemap TO attome_readonly;
