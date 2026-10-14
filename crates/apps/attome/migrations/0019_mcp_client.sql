-- N13-T1: outside MCP servers an administrator lets agents use, and the tools
-- imported from them. A tool arrives disabled at the strictest tier; an
-- administrator reviews its (untrusted) description, sets its tier and
-- enables it.
CREATE TABLE IF NOT EXISTS mcp_server (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    url text NOT NULL CHECK (char_length(url) BETWEEN 1 AND 2000),
    credential_encrypted text,
    allow_external boolean NOT NULL DEFAULT false,
    is_active boolean NOT NULL DEFAULT true,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    tools_imported_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS mcp_server_name_uq ON mcp_server (name) WHERE is_active;

CREATE TABLE IF NOT EXISTS mcp_server_tool (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    server_ref uuid NOT NULL REFERENCES mcp_server(id),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description text CHECK (description IS NULL OR char_length(description) <= 4000),
    input_schema jsonb,
    risk text NOT NULL DEFAULT 'consequential' CHECK (risk IN ('read', 'reversible', 'consequential')),
    is_enabled boolean NOT NULL DEFAULT false,
    imported_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (server_ref, name)
);
GRANT SELECT, INSERT, UPDATE ON mcp_server, mcp_server_tool TO attome_runtime;
