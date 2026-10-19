-- D20-T2: bookings made through public booking links. A row is the claim
-- on a team member's time (checked for overlap under an advisory lock on
-- the member) and points at the meeting activity created for it; the
-- cursor keeps each page's round robin.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS booking (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    page_id uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'booked' CHECK (status IN ('booked', 'cancelled')),
    activity_id uuid,
    name text NOT NULL,
    email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (ends_at > starts_at)
);
CREATE INDEX IF NOT EXISTS booking_user_time_idx
    ON booking (user_id, starts_at) WHERE status = 'booked';

CREATE TABLE IF NOT EXISTS booking_assign_cursor (
    page_id uuid PRIMARY KEY,
    last_user_id uuid,
    updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON booking, booking_assign_cursor TO attome_runtime;
GRANT SELECT ON booking, booking_assign_cursor TO attome_readonly;
