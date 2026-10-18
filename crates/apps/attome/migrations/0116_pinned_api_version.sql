-- S8-T1: the API version an API key or S2S client is answered at when it
-- sends no Attome-Version header. Existing and new rows take the current
-- version; a later version's migration moves the default forward, leaving
-- existing pins where they are.
ALTER TABLE api_key ADD COLUMN IF NOT EXISTS pinned_api_version text NOT NULL DEFAULT '2026-10';
ALTER TABLE s2s_client ADD COLUMN IF NOT EXISTS pinned_api_version text NOT NULL DEFAULT '2026-10';
