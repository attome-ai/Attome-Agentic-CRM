-- Q15-T1: a field-security grant may show a field masked instead of in
-- full. `mask_format` NULL is today's behaviour (read in full when
-- can_read); a format means the holder sees only the masked form, produced
-- by the server, and cannot change the field.
SET LOCAL lock_timeout = '5s';

-- A nullable column with no default is metadata-only (no table rewrite).
ALTER TABLE field_security_profile_field
    ADD COLUMN IF NOT EXISTS mask_format text
        CHECK (mask_format IN ('last4', 'email', 'phone', 'full'));
