-- K4-T2: the PAdES-sealed copy of each PDF in a completed envelope. The
-- original file is kept as it was signed; the sealed copy's key and SHA-256
-- sit beside it, or the reason it could not be sealed (not a PDF, encrypted).
SET LOCAL lock_timeout = '5s';

ALTER TABLE esign_document ADD COLUMN IF NOT EXISTS sealed_key    text;
ALTER TABLE esign_document ADD COLUMN IF NOT EXISTS sealed_sha256 text;
ALTER TABLE esign_document ADD COLUMN IF NOT EXISTS sealed_at     timestamptz;
ALTER TABLE esign_document ADD COLUMN IF NOT EXISTS seal_error    text;
