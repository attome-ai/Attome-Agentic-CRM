-- G6-T3: each time a person inserts a reply template on a record, so the
-- reply suggestions can rank by what was used on similar cases and how often.
CREATE TABLE IF NOT EXISTS reply_template_use (
    id uuid DEFAULT uuidv7() NOT NULL PRIMARY KEY,
    template_id text NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    used_by uuid NOT NULL,
    used_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reply_template_use_record
    ON reply_template_use (entity_logicalname, record_id);
CREATE INDEX IF NOT EXISTS idx_reply_template_use_recent
    ON reply_template_use (used_at, template_id);
