-- E13-T5: when a page's url_path changes, its old path keeps working. A
-- redirect names the page, not a path, so a page moved twice still answers
-- at both old paths with its current one. url_path is unique among live
-- pages (uq_xrm_content_page_url_path), so the old path alone is the key; a
-- page that later takes that path releases the redirect.
CREATE TABLE IF NOT EXISTS content_page_redirect (
    old_path   text        PRIMARY KEY,
    page_id    uuid        NOT NULL REFERENCES content_page (id),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS content_page_redirect_page_idx ON content_page_redirect (page_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON content_page_redirect TO attome_runtime;
GRANT SELECT ON content_page_redirect TO attome_readonly;
