-- K5-T2: who may read a published page. `public` pages are served to anyone
-- (the public view and delivery routes); `internal` pages only to signed-in
-- people, and the public routes answer them with the same 404 as a page
-- that does not exist.
ALTER TABLE content_page ADD COLUMN IF NOT EXISTS audience text NOT NULL DEFAULT 'public';
ALTER TABLE content_page DROP CONSTRAINT IF EXISTS content_page_audience_check;
ALTER TABLE content_page ADD CONSTRAINT content_page_audience_check
    CHECK (audience = ANY (ARRAY['public', 'internal']));
