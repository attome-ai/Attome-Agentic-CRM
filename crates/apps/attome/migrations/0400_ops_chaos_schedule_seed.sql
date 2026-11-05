-- AB9-T4: the chaos drill's schedule, proposed like the restore drill's
-- (0267): monthly and off until an administrator turns it on. The drill
-- agent runs `attome drill chaos suite` when it is due.
INSERT INTO ops_drill_schedule (id, kind, cadence, enabled)
VALUES ('0192f5a0-0000-7000-8000-00000000ab94', 'chaos', 'monthly', false)
ON CONFLICT DO NOTHING;
