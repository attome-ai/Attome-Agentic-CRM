-- E8-T9: erasing a person removes their journey rows (attome_core::erasure_hook,
-- the marketing engine's JourneyErasure), in the erasure's transaction. Only
-- that hook deletes from these tables; everything else only adds to them.
GRANT DELETE ON marketing_journey_enrolment, marketing_journey_block, marketing_message_log
    TO attome_runtime;
