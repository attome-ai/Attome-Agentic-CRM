-- The email ledger (attome-email): one delivery row per message sent through
-- `attome_email::send`, and the suppression list that send checks before every
-- SMTP attempt.
--
-- Rendered bodies are deliberately not stored: verification, reset and
-- invitation emails carry live single-use token links, so a resend mints a
-- fresh token instead of replaying content.
--
-- `user_ref`, `created_by` and `dispatch_ref` are opaque ids, not foreign keys:
-- attome-email is a foundation crate and knows nothing of the tables that
-- produce mail.
--
-- Status 'unknown' is terminal: an SMTP send that timed out after the relay
-- may already have taken the message. Retrying would deliver it twice and
-- 'failed' would hide it, so it waits for an operator and is never retried.

CREATE TABLE IF NOT EXISTS email_delivery (
    id           UUID PRIMARY KEY DEFAULT uuidv7(),
    kind         TEXT NOT NULL CHECK (kind IN ('email_verification', 'password_reset', 'invitation', 'generic')),
    recipient    TEXT NOT NULL,
    subject      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'queued',
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT,
    user_ref     UUID,
    created_by   UUID,
    dispatch_ref UUID,
    sent_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    row_version  BIGINT NOT NULL DEFAULT 0,
    is_deleted   BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT email_delivery_status_check
        CHECK (status IN ('queued', 'sent', 'failed', 'suppressed', 'unknown'))
);

CREATE INDEX IF NOT EXISTS idx_email_delivery_recipient ON email_delivery (recipient, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_delivery_status ON email_delivery (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_delivery_dispatch_ref
    ON email_delivery (dispatch_ref)
    WHERE dispatch_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS email_suppression (
    id          UUID PRIMARY KEY DEFAULT uuidv7(),
    email       TEXT NOT NULL,
    reason      TEXT NOT NULL CHECK (reason IN ('hard_bounce', 'complaint', 'admin_manual')),
    detail      TEXT,
    created_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    row_version BIGINT NOT NULL DEFAULT 0,
    is_deleted  BOOLEAN NOT NULL DEFAULT FALSE
);

-- Partial unique: an address lifted from suppression can be suppressed again
-- without colliding with its own soft-deleted history.
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_suppression_email_active
    ON email_suppression (email) WHERE is_deleted = FALSE;
