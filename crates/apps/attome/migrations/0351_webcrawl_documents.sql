-- K6-T6: a crawled page of status 'document' is a linked PDF, Word or Excel
-- file. Its own job fetches it into an attome_document (document_ref) through
-- the upload pipeline (document_session_id: the scan, then the text), and
-- keeps the file's ETag for the next conditional fetch.
SET LOCAL lock_timeout = '5s';

ALTER TABLE webcrawl_page
    ADD COLUMN IF NOT EXISTS document_ref uuid,
    ADD COLUMN IF NOT EXISTS document_session_id uuid,
    ADD COLUMN IF NOT EXISTS document_etag text,
    ADD COLUMN IF NOT EXISTS document_fetched_at timestamptz;
