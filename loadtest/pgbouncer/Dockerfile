# P1.8d step 5 — pgbouncer for the loadtest-only P1.12 exercise.
#
# NOT the same base image as ../../pgbouncer/Dockerfile (the real deployment
# recipe, `debian:bookworm-slim` + apt) — found by actually running this
# exercise that bookworm's apt package is pgbouncer 1.18.0, which lacks
# protocol-level prepared-statement support under transaction pooling (added
# in 1.21). Two workarounds (database.disable_statement_cache=true,
# server_reset_query_always=1) were tried first and neither fully closed the
# gap ("prepared statement already exists"/"does not exist" under real
# concurrent load, see document/LOADTEST-2026-07-21.md and DECISIONS.md).
# Switching to a maintained image that ships a current pgbouncer (>= 1.21)
# is the real fix — this pins the specific digest tested, not `:latest`,
# for reproducibility. The real recipe still uses bookworm's apt package
# (1.18) and needs the equivalent decision made deliberately, not copied
# here silently — see pgbouncer.ini's own comments and DECISIONS.md.
FROM edoburu/pgbouncer@sha256:4c1ca296ef525f108f5d3552cc337c0c09587cf8dae7f0067fd93349e47dc1cd

COPY pgbouncer.ini /etc/pgbouncer/pgbouncer.ini
COPY userlist.txt /etc/pgbouncer/userlist.txt

EXPOSE 6432
