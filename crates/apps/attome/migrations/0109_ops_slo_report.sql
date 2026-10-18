-- AA13-T9: the monthly SLO report, one row per calendar month (UTC),
-- written once by the SloMonthlyReport job (ON CONFLICT DO NOTHING on
-- period_start) from the built-in metrics store.

CREATE TABLE IF NOT EXISTS ops_slo_report (
    id uuid PRIMARY KEY,
    period_start date NOT NULL UNIQUE,
    report jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT ON ops_slo_report TO attome_runtime;
GRANT SELECT ON ops_slo_report TO attome_readonly;
