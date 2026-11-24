-- One current observation per named check and engagement. Raw native output
-- and adapter configuration are never written here.
CREATE TABLE recorded_checks (
    engagement_id TEXT NOT NULL REFERENCES engagements,
    stage TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    code TEXT,
    native_exit INTEGER,
    wrapper_exit INTEGER,
    run_id TEXT,
    CHECK (code IS NOT NULL
        OR (COALESCE(native_exit, 0) = 0 AND COALESCE(wrapper_exit, 0) = 0)),
    PRIMARY KEY (engagement_id, stage),
    FOREIGN KEY (engagement_id, run_id) REFERENCES runs (engagement_id, id)
) STRICT;
