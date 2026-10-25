-- AJ3-T1: identity checks against a national register (Yakeen). Only the
-- outcome is kept: which record was checked, the ID's kind and last four
-- digits, whether the register matched, and the consent the person gave
-- before the check. The register's own data is never stored here.
CREATE TABLE IF NOT EXISTS identity_verification (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    subject_entity text NOT NULL,
    subject_id uuid NOT NULL,
    provider text NOT NULL,
    id_kind text NOT NULL CHECK (id_kind IN ('citizen', 'resident')),
    id_last4 text NOT NULL CHECK (id_last4 ~ '^[0-9]{4}$'),
    outcome text NOT NULL CHECK (outcome IN ('matched', 'not_matched', 'not_found')),
    provider_reference text,
    consent_text_version text NOT NULL,
    consent_given_at timestamptz NOT NULL,
    consent_source text NOT NULL,
    requested_by uuid,
    verified_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS identity_verification_subject_idx
    ON identity_verification (subject_entity, subject_id, verified_at DESC);

-- The record of checks is append-only for the application.
GRANT SELECT, INSERT ON identity_verification TO attome_runtime;
GRANT SELECT ON identity_verification TO attome_readonly;
