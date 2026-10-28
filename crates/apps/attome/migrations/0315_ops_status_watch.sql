-- AB11-T4: since when a status component has been down, kept by the
-- status watch job (attome_ops::status_watch) so "down for three minutes"
-- survives a restart and does not depend on which node ran the last tick.
ALTER TABLE ops_status_component ADD COLUMN IF NOT EXISTS degraded_since timestamptz;

GRANT UPDATE (degraded_since) ON ops_status_component TO attome_runtime;
