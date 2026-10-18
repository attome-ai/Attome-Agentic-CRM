-- S1-T10: a server-to-server client granted can_act_as_user may name a user
-- in the signed x-attome-act-as header; the request then runs as that user
-- and the access log keeps both identities.
ALTER TABLE s2s_client ADD COLUMN IF NOT EXISTS can_act_as_user boolean NOT NULL DEFAULT false;
ALTER TABLE s2s_access_log ADD COLUMN IF NOT EXISTS acted_as_user_id uuid;
