-- The text-search configuration the search engine indexes with. It is
-- `simple`-based and deliberately unstemmed: the platform stems in Rust, so
-- index-time and query-time stemming are one implementation, and a second
-- stemmer underneath would silently disagree with it. v1 created it in its
-- migration 0106; the v2 baseline did not carry it over.

DO $cfg$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_ts_config WHERE cfgname = 'attome_search') THEN
        CREATE TEXT SEARCH CONFIGURATION attome_search (COPY = simple);
    END IF;
END
$cfg$;

COMMENT ON TEXT SEARCH CONFIGURATION attome_search IS
  'simple-based, deliberately unstemmed; the platform stems in Rust so index-time and query-time stemming are one implementation';
