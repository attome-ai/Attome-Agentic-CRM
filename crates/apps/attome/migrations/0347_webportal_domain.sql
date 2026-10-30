-- G12-T3: a web portal served on its own domain. The domain is kept
-- normalised (lower case, no port, no trailing dot) and names one portal;
-- a request whose host is the domain opens that portal, and with ACME on
-- the server orders the domain's certificate at boot. One row per portal.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS webportal_domain (
    webportal_id uuid PRIMARY KEY,
    domain text NOT NULL UNIQUE,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON webportal_domain TO attome_runtime;
