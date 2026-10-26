-- S11-T5: on a deployment without Redis (Solo) the S2S nonces and OAuth
-- assertion ids live here instead of in process memory, so a restart does not
-- forget them and reopen the replay window. A row lives as long as the
-- timestamp window allows a replay (`expires_at`); an expired row may be
-- claimed again and is swept in small batches.
CREATE TABLE IF NOT EXISTS s2s_nonce (
    client_id text NOT NULL,
    nonce text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (client_id, nonce)
);

CREATE INDEX IF NOT EXISTS s2s_nonce_expires_idx ON s2s_nonce (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON s2s_nonce TO attome_runtime;
