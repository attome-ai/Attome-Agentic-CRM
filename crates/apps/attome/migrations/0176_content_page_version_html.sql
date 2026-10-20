-- E12-T1: each published page version keeps its server-rendered HTML,
-- rendered once in the publish transaction, so serving a page does no
-- work. A version published before this has none.
SET LOCAL lock_timeout = '5s';

ALTER TABLE content_page_version ADD COLUMN IF NOT EXISTS html text;
