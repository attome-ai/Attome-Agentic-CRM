-- AH3-T2: an agent principal (identity plan Phase 1). The agent is an
-- account (`principal_kind` 2) with a person who sponsors it; it acts within
-- the intersection of its own grants and its sponsor's, never more (AG-2).
-- `lifecycle_state` pauses, suspends or revokes it with a reason;
-- `entity_scope` narrows it to listed entities; `policy_ref` names its AI
-- policy. An agent session records the agent it runs as and the chain of
-- principals it acts for.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS agent_principal (
    user_ref             uuid PRIMARY KEY REFERENCES user_account (id),
    sponsor_user_ref     uuid NOT NULL,
    persona_ref          uuid,
    lifecycle_state      text NOT NULL DEFAULT 'active'
        CHECK (lifecycle_state IN ('active', 'paused', 'suspended', 'revoked')),
    state_reason         text,
    policy_ref           uuid,
    entity_scope         text[],
    external_account_ref uuid,
    created_at           timestamptz NOT NULL DEFAULT now(),
    created_by           uuid NOT NULL,
    revoked_at           timestamptz,
    row_version          bigint NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS agent_principal_sponsor ON agent_principal (sponsor_user_ref);

ALTER TABLE agent_session
    ADD COLUMN IF NOT EXISTS agent_principal_ref uuid,
    ADD COLUMN IF NOT EXISTS actor_chain uuid[];

GRANT SELECT, INSERT, UPDATE ON agent_principal TO attome_runtime;
GRANT SELECT ON agent_principal TO attome_readonly;
