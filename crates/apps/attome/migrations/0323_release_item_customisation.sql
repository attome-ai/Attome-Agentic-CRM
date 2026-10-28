-- Y11-T12: a release report item for a customisation a platform or app
-- release affects: the item it was made on is retired, deleted or renamed.
-- Information only (Dismiss); the customisation is never moved.
ALTER TABLE release_report_item DROP CONSTRAINT IF EXISTS ck_core_release_item_kind;
ALTER TABLE release_report_item ADD CONSTRAINT ck_core_release_item_kind CHECK (kind = ANY (ARRAY[
    'conflict'::text, 'conversion_nulled'::text, 'field_deleted'::text,
    'customer_object_adjusted'::text, 'customer_object_removed'::text,
    'breaking_api_change'::text, 'choice_removed_in_use'::text, 'required_empty'::text,
    'customisation_affected'::text
]));
