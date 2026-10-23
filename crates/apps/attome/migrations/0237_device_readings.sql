-- I7-T1: device readings: the latest value per asset and meter, hourly
-- summaries, the readings already counted, and the device rules that fired.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS device_latest_reading (
    asset_id uuid NOT NULL,
    meter text NOT NULL,
    reading double precision NOT NULL,
    unit text,
    read_at timestamptz NOT NULL,
    reading_id uuid NOT NULL,
    PRIMARY KEY (asset_id, meter)
);

CREATE TABLE IF NOT EXISTS device_hourly_summary (
    asset_id uuid NOT NULL,
    meter text NOT NULL,
    hour timestamptz NOT NULL,
    readings bigint NOT NULL,
    min_reading double precision NOT NULL,
    max_reading double precision NOT NULL,
    sum_reading double precision NOT NULL,
    last_reading double precision NOT NULL,
    last_read_at timestamptz NOT NULL,
    PRIMARY KEY (asset_id, meter, hour)
);

-- A reading is counted into its hour once, however often the feed replays it.
CREATE TABLE IF NOT EXISTS device_reading_counted (
    reading_id uuid PRIMARY KEY,
    counted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS device_reading_counted_at ON device_reading_counted (counted_at);

CREATE TABLE IF NOT EXISTS device_rule_fire (
    rule_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    reading_id uuid NOT NULL,
    read_at timestamptz NOT NULL,
    fired_at timestamptz NOT NULL DEFAULT now(),
    target_entity text NOT NULL,
    target_id uuid,
    PRIMARY KEY (rule_id, reading_id)
);
CREATE INDEX IF NOT EXISTS device_rule_fire_last ON device_rule_fire (rule_id, asset_id, read_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON device_latest_reading, device_hourly_summary,
    device_reading_counted, device_rule_fire TO attome_runtime;
GRANT SELECT ON device_latest_reading, device_hourly_summary, device_reading_counted,
    device_rule_fire TO attome_readonly;
