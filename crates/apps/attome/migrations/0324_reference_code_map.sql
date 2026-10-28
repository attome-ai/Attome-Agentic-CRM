-- L1-T8: reference-data code mappings, versioned. A source system's code in
-- one of its code lists maps to the value this deployment stores. An edit
-- inserts the next version and never updates a row, so every earlier mapping
-- is kept; the newest version already in effect (valid_from <= now()) is the
-- one imports use. A version with a null value retires the code.
CREATE TABLE IF NOT EXISTS reference_code_map (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    source_system text NOT NULL,
    code_list text NOT NULL,
    code text NOT NULL,
    value text,
    version integer NOT NULL CHECK (version >= 1),
    valid_from timestamptz NOT NULL DEFAULT now(),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT reference_code_map_version_uq UNIQUE (source_system, code_list, code, version)
);

GRANT SELECT, INSERT ON reference_code_map TO attome_runtime;
GRANT SELECT ON reference_code_map TO attome_readonly;
