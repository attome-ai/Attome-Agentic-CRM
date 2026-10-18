-- F5-T7: payment gateway webhook events, each applied once.
--
-- billing_gateway_event: one event a gateway's webhook reported, after its
-- signature verified: the gateway's own event key (unique per gateway
-- system, so a redelivered event is stored once), the decoded event, when it
-- was applied to its payment, and why the last attempt failed. The apply job
-- picks unapplied rows under SKIP LOCKED and stops retrying a row after
-- `attempts` reaches its limit.

CREATE TABLE IF NOT EXISTS billing_gateway_event (
    id uuid PRIMARY KEY,
    gateway_system_id uuid NOT NULL,
    event_key text NOT NULL,
    payload jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    applied_at timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    error text,
    CONSTRAINT billing_gateway_event_once UNIQUE (gateway_system_id, event_key)
);

CREATE INDEX IF NOT EXISTS billing_gateway_event_unapplied
    ON billing_gateway_event (received_at)
    WHERE applied_at IS NULL;
