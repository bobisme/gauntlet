-- A request key binds one normalized input to one run for the life of the
-- engagement. The row is written in the same transaction as the run, before
-- the caller may cross its first effect boundary.
CREATE TABLE request_keys (
    key TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    binding TEXT NOT NULL,
    command TEXT NOT NULL,
    input TEXT NOT NULL CHECK (json_valid(input) AND json_type(input) = 'object'),
    input_digest TEXT NOT NULL,
    run_id TEXT NOT NULL,
    receipt_revision INTEGER NOT NULL CHECK (receipt_revision > 0),
    lead_id TEXT,
    lead_revision INTEGER,
    engagement_revision INTEGER NOT NULL CHECK (engagement_revision >= 0),
    FOREIGN KEY (engagement_id, run_id) REFERENCES runs (engagement_id, id)
) STRICT;
