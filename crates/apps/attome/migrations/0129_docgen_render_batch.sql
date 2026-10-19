-- K3-T3: renders started together for many records share a batch id, so
-- the batch's progress (pending, running, completed, failed, attached) can
-- be read in one place.
ALTER TABLE docgen_render ADD COLUMN IF NOT EXISTS batch_id uuid;

CREATE INDEX IF NOT EXISTS docgen_render_batch_idx ON docgen_render (batch_id)
    WHERE batch_id IS NOT NULL;
