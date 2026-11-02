-- E14-T11: an erasure finds a person's web sessions by lead as well as by
-- contact, and their events by session, without scanning every month.
CREATE INDEX IF NOT EXISTS marketing_web_session_lead_idx ON marketing_web_session (lead_ref);
CREATE INDEX IF NOT EXISTS marketing_web_event_session_idx ON marketing_web_event (session_id);
