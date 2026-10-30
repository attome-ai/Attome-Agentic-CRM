-- P2-T1 (V2-D1416): the role an author's SQL report runs as. It logs in
-- never, owns nothing and holds no privilege on any schema or table: during
-- a run (`attome_report::secured_sql`) it is granted SELECT on that run's
-- temporary views only, each one the author's own rows and readable columns
-- of one entity, and the transaction is rolled back. A schema-qualified
-- name, a function that reads a table by name or a second statement then
-- fails on privileges, not on a list of forbidden words.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'attome_user_sql') THEN
        CREATE ROLE attome_user_sql WITH NOLOGIN NOINHERIT;
    END IF;
END
$$;

-- The application's connections switch to it with SET LOCAL ROLE.
GRANT attome_user_sql TO attome_runtime;
DO $$
BEGIN
    IF current_user <> 'attome_user_sql'
       AND NOT pg_has_role(current_user, 'attome_user_sql', 'MEMBER') THEN
        EXECUTE format('GRANT attome_user_sql TO %I', current_user);
    END IF;
END
$$;
