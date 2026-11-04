-- Q15-T3: a field-security grant may carry a read condition: a rule
-- expression (Z11-T16) over the record's own fields. Its holder sees the
-- field in full only on records that meet it; elsewhere the field stays
-- hidden, or masked when another grant masks it. NULL is today's behaviour.
SET LOCAL lock_timeout = '5s';

-- A nullable column with no default is metadata-only (no table rewrite).
ALTER TABLE field_security_profile_field
    ADD COLUMN IF NOT EXISTS read_condition text;
