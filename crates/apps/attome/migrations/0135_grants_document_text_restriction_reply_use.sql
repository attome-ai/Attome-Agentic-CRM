-- Grants for the tables 0132 (document_text), 0133 (processing_restriction)
-- and 0134 (reply_template_use) created, in the shape every table migration
-- states them; the schema's default privileges already cover a table the
-- migrator creates, so this changes nothing there and keeps the rule visible.
GRANT SELECT, INSERT, UPDATE, DELETE ON document_text TO attome_runtime;
GRANT SELECT ON document_text TO attome_readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON processing_restriction TO attome_runtime;
GRANT SELECT ON processing_restriction TO attome_readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON reply_template_use TO attome_runtime;
GRANT SELECT ON reply_template_use TO attome_readonly;
