-- AG2-T3: e-invoicing's two infrastructure tables (ZATCA first).
--
-- einvoice_device: one EGS unit (an invoicing device): its signing key
-- (encrypted under einvoice.key_encryption_key), its certificate signing
-- request, the compliance and production CSIDs ZATCA issued (secrets
-- encrypted the same way) and its hash chain (last counter value and last
-- invoice hash). A document is chained under a row lock on its device.
-- einvoice_document: the stamped document for one invoice, its place in its
-- device's chain (unique per device and counter value), and what ZATCA said.

CREATE TABLE IF NOT EXISTS einvoice_device (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE,
    environment text NOT NULL
        CHECK (environment IN ('sandbox', 'simulation', 'production')),
    status text NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'compliance', 'active', 'failed', 'retired')),
    egs_serial text NOT NULL,
    invoice_types text NOT NULL DEFAULT '1100',
    private_key_encrypted text NOT NULL,
    csr text NOT NULL,
    compliance_request_id text,
    compliance_token text,
    compliance_secret_encrypted text,
    production_token text,
    production_secret_encrypted text,
    certificate text,
    cert_issuer text,
    cert_serial text,
    cert_ca_signature bytea,
    last_icv bigint NOT NULL DEFAULT 0,
    last_hash text NOT NULL
        DEFAULT 'NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==',
    last_error text,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    row_version bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS einvoice_document (
    id uuid PRIMARY KEY,
    invoice_ref uuid NOT NULL UNIQUE,
    device_ref uuid NOT NULL REFERENCES einvoice_device (id),
    profile text NOT NULL CHECK (profile IN ('standard', 'simplified')),
    icv bigint NOT NULL,
    document_uuid uuid NOT NULL,
    invoice_hash text NOT NULL,
    xml text NOT NULL,
    qr text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'cleared', 'reported', 'rejected', 'failed')),
    validation jsonb,
    cleared_xml text,
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (device_ref, icv)
);

CREATE INDEX IF NOT EXISTS einvoice_document_due_idx
    ON einvoice_document (next_attempt_at)
    WHERE status = 'pending';

GRANT SELECT, INSERT, UPDATE ON einvoice_device TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON einvoice_document TO attome_runtime;
GRANT SELECT ON einvoice_document TO attome_readonly;
