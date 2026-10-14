-- B9-T1: what each user opened lately, and the lists of things they keep at
-- hand. A list belongs to one user (a folder of their own) or is shared with
-- one team; an item is a record, a view or a page. The engine keeps the last
-- 200 recent rows per user.
CREATE TABLE IF NOT EXISTS user_recent (
    user_id uuid NOT NULL,
    entity text NOT NULL CHECK (char_length(entity) BETWEEN 1 AND 63),
    record_id uuid NOT NULL,
    opened_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, entity, record_id)
);
CREATE INDEX IF NOT EXISTS user_recent_by_user ON user_recent (user_id, opened_at DESC);

CREATE TABLE IF NOT EXISTS favourite_list (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    owner_user uuid,
    team_id uuid,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((owner_user IS NULL) <> (team_id IS NULL))
);
CREATE INDEX IF NOT EXISTS favourite_list_by_owner ON favourite_list (owner_user) WHERE owner_user IS NOT NULL;
CREATE INDEX IF NOT EXISTS favourite_list_by_team ON favourite_list (team_id) WHERE team_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS favourite_item (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    list_id uuid NOT NULL REFERENCES favourite_list(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('record', 'view', 'page')),
    entity text CHECK (entity IS NULL OR char_length(entity) BETWEEN 1 AND 63),
    ref text NOT NULL CHECK (char_length(ref) BETWEEN 1 AND 500),
    label text CHECK (label IS NULL OR char_length(label) <= 200),
    position integer NOT NULL,
    pinned boolean NOT NULL DEFAULT false,
    CHECK (kind <> 'record' OR entity IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS favourite_item_by_list ON favourite_item (list_id, position);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_recent, favourite_list, favourite_item TO attome_runtime;
