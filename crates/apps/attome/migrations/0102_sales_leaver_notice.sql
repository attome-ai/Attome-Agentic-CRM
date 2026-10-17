-- D7-T6: one row per disabled account reported to its managers for the open
-- deals it still owns, keyed by the account's auth_epoch (every disable moves
-- it on), so each disable is reported once. Holds no business data.

CREATE TABLE IF NOT EXISTS sales_leaver_notice (
    user_ref uuid NOT NULL,
    auth_epoch integer NOT NULL,
    open_deals bigint NOT NULL,
    notified_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_ref, auth_epoch)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON sales_leaver_notice TO attome_runtime;
GRANT SELECT ON sales_leaver_notice TO attome_readonly;
