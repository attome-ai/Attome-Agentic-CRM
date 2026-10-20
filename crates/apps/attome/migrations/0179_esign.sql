-- K4-T1: electronic signatures. An envelope carries documents (each with
-- the SHA-256 of its file when sent) and signers in signing order; every
-- step is an append-only event chained by hash; a completed envelope keeps
-- its completion certificate and the certificate's hash.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS esign_envelope (
    id               uuid        PRIMARY KEY DEFAULT uuidv7(),
    title            text        NOT NULL,
    status           text        NOT NULL DEFAULT 'draft'
                     CHECK (status IN ('draft', 'sent', 'completed', 'declined', 'voided')),
    created_by       uuid        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz,
    completed_at     timestamptz,
    certificate      jsonb,
    certificate_hash text,
    row_version      bigint      NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS esign_envelope_creator_idx ON esign_envelope (created_by, created_at DESC);

CREATE TABLE IF NOT EXISTS esign_document (
    id          uuid    PRIMARY KEY DEFAULT uuidv7(),
    envelope_id uuid    NOT NULL REFERENCES esign_envelope (id) ON DELETE CASCADE,
    document_id uuid    NOT NULL,
    name        text    NOT NULL,
    file_key    text    NOT NULL,
    sha256      text    NOT NULL,
    position    integer NOT NULL
);
CREATE INDEX IF NOT EXISTS esign_document_envelope_idx ON esign_document (envelope_id);

CREATE TABLE IF NOT EXISTS esign_signer (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    envelope_id    uuid        NOT NULL REFERENCES esign_envelope (id) ON DELETE CASCADE,
    name           text        NOT NULL,
    email          text        NOT NULL,
    role           text        NOT NULL DEFAULT 'signer',
    sign_order     integer     NOT NULL DEFAULT 1,
    status         text        NOT NULL DEFAULT 'waiting'
                   CHECK (status IN ('waiting', 'notified', 'signed', 'declined')),
    typed_name     text,
    signed_at      timestamptz,
    ip             text,
    user_agent     text,
    decline_reason text
);
CREATE INDEX IF NOT EXISTS esign_signer_envelope_idx ON esign_signer (envelope_id, sign_order);

CREATE TABLE IF NOT EXISTS esign_event (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    envelope_id uuid        NOT NULL REFERENCES esign_envelope (id) ON DELETE CASCADE,
    seq         integer     NOT NULL,
    signer_id   uuid,
    kind        text        NOT NULL,
    at          timestamptz NOT NULL,
    ip          text,
    detail      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   text        NOT NULL,
    hash        text        NOT NULL,
    UNIQUE (envelope_id, seq)
);

GRANT SELECT, INSERT, UPDATE ON esign_envelope, esign_signer TO attome_runtime;
GRANT SELECT, INSERT ON esign_document TO attome_runtime;
-- Append-only: events are added and never changed.
GRANT SELECT, INSERT ON esign_event TO attome_runtime;
GRANT SELECT ON esign_envelope, esign_document, esign_signer, esign_event TO attome_readonly;
