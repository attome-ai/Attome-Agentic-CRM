-- The three change logs draw their ids from sequences 0006 created as the
-- bootstrap role, so the migrator's default privileges never reached them:
-- the runtime role could not insert a label, metadata or setting change
-- (a platform changeset that sets labels failed boot with "permission
-- denied for sequence metadata_label_change_log_id_seq").
GRANT USAGE, SELECT ON SEQUENCE
    metadata_change_log_id_seq,
    metadata_label_change_log_id_seq,
    setting_change_log_id_seq
TO attome_runtime;
