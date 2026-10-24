-- Z6-T6: where a clean image's thumbnail is stored (beside the original),
-- and the lookup the download route makes by the original's key.
ALTER TABLE upload_session ADD COLUMN IF NOT EXISTS thumbnail_key text;
CREATE INDEX IF NOT EXISTS upload_session_final_key_thumb_idx ON upload_session (final_key)
    WHERE thumbnail_key IS NOT NULL AND status = 'clean' AND is_deleted = false;
