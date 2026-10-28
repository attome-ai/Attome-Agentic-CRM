-- B15-T1: geocoding answers by normalised address
-- (attome_integration::connector::adapters::geocode), so an address is asked
-- of the provider once. An address the provider does not know is kept with
-- no point. Holds no record data: only address text and coordinates.
CREATE TABLE IF NOT EXISTS geocode_cache (
    address_key text PRIMARY KEY,
    lat double precision,
    lng double precision,
    cached_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((lat IS NULL) = (lng IS NULL))
);

GRANT SELECT, INSERT, UPDATE ON geocode_cache TO attome_runtime;
GRANT SELECT ON geocode_cache TO attome_readonly;
