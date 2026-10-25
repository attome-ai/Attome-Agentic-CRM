-- AB3-T1: the recovery point and time each deployment profile promises per
-- disaster scenario, and the kind of drill evidence that proves it. Seeded
-- from the internal targets; operators change the numbers through the API.
CREATE TABLE IF NOT EXISTS ops_recovery_target (
    id uuid PRIMARY KEY,
    profile text NOT NULL CHECK (profile IN ('solo', 'team', 'ha', 'scale')),
    scenario text NOT NULL CHECK (scenario IN ('node_loss', 'site_loss', 'corruption', 'ransomware', 'bad_change')),
    rpo_seconds integer NOT NULL CHECK (rpo_seconds >= 0),
    rto_seconds integer NOT NULL CHECK (rto_seconds >= 0),
    evidence_kind text NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    updated_by uuid,
    updated_at timestamptz,
    UNIQUE (profile, scenario)
);

INSERT INTO ops_recovery_target (id, profile, scenario, rpo_seconds, rto_seconds, evidence_kind)
SELECT uuidv7(), p.profile, s.scenario,
       CASE
           WHEN s.scenario = 'node_loss' AND p.profile IN ('ha', 'scale') THEN 0
           WHEN s.scenario = 'ransomware' THEN 3600
           ELSE 300
       END,
       CASE
           WHEN s.scenario = 'node_loss' AND p.profile IN ('ha', 'scale') THEN 30
           WHEN s.scenario IN ('ransomware', 'site_loss') THEN 14400
           ELSE 3600
       END,
       CASE
           WHEN s.scenario = 'node_loss' AND p.profile IN ('ha', 'scale') THEN 'failover'
           WHEN s.scenario = 'node_loss' THEN 'restore'
           ELSE 'recovery'
       END
  FROM (VALUES ('solo'), ('team'), ('ha'), ('scale')) AS p (profile)
 CROSS JOIN (VALUES ('node_loss'), ('site_loss'), ('corruption'), ('ransomware'), ('bad_change')) AS s (scenario)
ON CONFLICT (profile, scenario) DO NOTHING;

GRANT SELECT, UPDATE ON ops_recovery_target TO attome_runtime;
GRANT SELECT ON ops_recovery_target TO attome_readonly;
