-- One run holds at most one request key for the life of the engagement, and a
-- stored key-to-run association cannot be duplicated by another key.
CREATE UNIQUE INDEX request_key_runs ON request_keys (run_id);

-- Scope lookups go through the key primary key; this lane creates no index
-- that no statement uses. Older stores of this lane may still hold it.
DROP INDEX IF EXISTS request_key_scopes;
