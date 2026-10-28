-- Q1-T10: the provider and OIDC session (`sid`) a federated sign-in came
-- from, kept on every row of the refresh family (a rotation copies them).
-- Sign-out sends the person to that provider's end-session endpoint, and a
-- provider's back-channel logout finds the families to end by `sid`.
ALTER TABLE refresh_token ADD COLUMN IF NOT EXISTS oidc_provider text;
ALTER TABLE refresh_token ADD COLUMN IF NOT EXISTS oidc_sid text;

CREATE INDEX IF NOT EXISTS refresh_token_oidc_sid_idx
    ON refresh_token (oidc_provider, oidc_sid)
    WHERE oidc_sid IS NOT NULL;
