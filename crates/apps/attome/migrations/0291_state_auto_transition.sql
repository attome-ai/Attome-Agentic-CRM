-- M8-T3: a transition may happen by itself. `auto_condition` is an
-- attome-rules condition over the record's fields; when it holds for a
-- record in the transition's from_state, the transition is applied (after
-- each write and by a daily sweep). NULL is a transition people make.
SET LOCAL lock_timeout = '5s';

-- A nullable column with no default is metadata-only (no table rewrite).
ALTER TABLE state_transition ADD COLUMN IF NOT EXISTS auto_condition text;
