-- B4-T1/T2: tags on any record. A tag is shared (everyone who can read the
-- record sees it) or personal (only its owner sees it). A shared tag may sit
-- in a group whose policy says who may create tags in it. Names match
-- through `normalize_ar` (diacritics, letter forms, digits and case folded),
-- so one tag is never created twice in two spellings.
CREATE TABLE IF NOT EXISTS tag_group (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    colour text CHECK (colour IS NULL OR colour ~ '^#[0-9a-fA-F]{6}$'),
    create_policy text NOT NULL DEFAULT 'anyone'
        CHECK (create_policy IN ('anyone', 'privilege', 'nobody')),
    create_privilege text CHECK (create_privilege IS NULL OR char_length(create_privilege) <= 200),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (create_policy <> 'privilege' OR create_privilege IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS tag_group_name_uq ON tag_group (normalize_ar(name));

CREATE TABLE IF NOT EXISTS tag (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    group_id uuid REFERENCES tag_group(id),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    normalized_name text GENERATED ALWAYS AS (normalize_ar(name)) STORED,
    colour text CHECK (colour IS NULL OR colour ~ '^#[0-9a-fA-F]{6}$'),
    owner_user uuid,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (owner_user IS NULL OR group_id IS NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS tag_shared_uq ON tag (normalized_name) WHERE owner_user IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS tag_personal_uq ON tag (owner_user, normalized_name) WHERE owner_user IS NOT NULL;

CREATE TABLE IF NOT EXISTS tag_link (
    tag_id uuid NOT NULL REFERENCES tag(id) ON DELETE CASCADE,
    entity text NOT NULL CHECK (char_length(entity) BETWEEN 1 AND 63),
    record_id uuid NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    PRIMARY KEY (tag_id, entity, record_id)
);
CREATE INDEX IF NOT EXISTS tag_link_by_record ON tag_link (entity, record_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON tag_group, tag, tag_link TO attome_runtime;
GRANT SELECT ON tag_group, tag, tag_link TO attome_readonly;
