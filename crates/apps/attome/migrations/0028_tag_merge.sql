-- B4-T3: merging one shared tag into another, with undo, and the expiry
-- sweep. A merged tag keeps its row, pointing at the tag it went into; each
-- link the merge moved remembers the tag it came from, so undo moves exactly
-- those back.
ALTER TABLE tag ADD COLUMN IF NOT EXISTS merged_into uuid REFERENCES tag(id);
ALTER TABLE tag_link ADD COLUMN IF NOT EXISTS merged_from uuid;
CREATE INDEX IF NOT EXISTS tag_link_expiring ON tag_link (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS tag_link_merged_from ON tag_link (tag_id, merged_from) WHERE merged_from IS NOT NULL;
