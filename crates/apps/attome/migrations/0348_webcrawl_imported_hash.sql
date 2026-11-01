-- K6-T4: the text hash a crawled page had when it was last imported into its
-- knowledge item. A recrawl that brings a different hash leaves the item
-- out of date: the next import or post-crawl sync updates it as a new
-- version (or flags it for review). Pages imported before this column
-- take their current hash, so the first sync does not rewrite them all.
SET LOCAL lock_timeout = '5s';

ALTER TABLE webcrawl_page
    ADD COLUMN IF NOT EXISTS imported_content_hash text;

UPDATE webcrawl_page
   SET imported_content_hash = content_hash
 WHERE imported_data_item_ref IS NOT NULL
   AND imported_content_hash IS NULL;
