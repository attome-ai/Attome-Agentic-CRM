-- AD6-T2: each published metadata version's documentation, in English and
-- Arabic, written by the job its publish enqueues.
CREATE TABLE IF NOT EXISTS metadata_version_doc (
    version bigint NOT NULL REFERENCES metadata_published_version (version),
    lang text NOT NULL CHECK (lang IN ('en', 'ar')),
    markdown text NOT NULL,
    generated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (version, lang)
);

GRANT SELECT, INSERT, UPDATE ON metadata_version_doc TO attome_runtime;
GRANT SELECT ON metadata_version_doc TO attome_readonly;
