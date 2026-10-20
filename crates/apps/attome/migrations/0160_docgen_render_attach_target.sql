-- W1-T6: a render may attach its document to another record than the one it
-- renders from (a contract's draft lands on a new contract_version). All
-- three are set together or not at all; without them the template's own
-- attach_to_field applies to the rendered record, as before.
ALTER TABLE docgen_render ADD COLUMN IF NOT EXISTS attach_entity text;
ALTER TABLE docgen_render ADD COLUMN IF NOT EXISTS attach_record_id uuid;
ALTER TABLE docgen_render ADD COLUMN IF NOT EXISTS attach_field text;
