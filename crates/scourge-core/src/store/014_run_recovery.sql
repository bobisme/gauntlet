-- Recovery identity is minted by the request boundary and enriched only with
-- the capture handle issued for that exact run.  It contains no caller verdict
-- or inferred dispatch outcome.
CREATE TABLE run_recovery (
    run_id TEXT PRIMARY KEY REFERENCES runs,
    request_key TEXT NOT NULL UNIQUE REFERENCES request_keys (key),
    input_digest TEXT NOT NULL,
    capture_handle TEXT
) STRICT;

-- Existing accepted requests already have the service-issued run/key/input
-- binding.  They predate durable capture-handle retention, so that field is
-- intentionally unknown rather than reconstructed.
INSERT INTO run_recovery (run_id, request_key, input_digest)
SELECT run_id, key, input_digest FROM request_keys;

CREATE TRIGGER run_recovery_no_delete
BEFORE DELETE ON run_recovery
BEGIN
    SELECT RAISE(ABORT, 'run recovery identity is immutable');
END;

CREATE TRIGGER run_recovery_monotonic
BEFORE UPDATE ON run_recovery
WHEN NEW.run_id<>OLD.run_id
  OR NEW.request_key<>OLD.request_key
  OR NEW.input_digest<>OLD.input_digest
  OR OLD.capture_handle IS NOT NULL
  OR NEW.capture_handle IS NULL
BEGIN
    SELECT RAISE(ABORT, 'run recovery identity is immutable');
END;
