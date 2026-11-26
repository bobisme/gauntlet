-- A production-only, run-bound copy of Teapot's durable `requests lookup`
-- refusal. The exact native bytes are bounded and hashed by the Rust writer;
-- recovery trusts neither an exit code nor a caller-created `not-sent` word.
CREATE TABLE run_pre_dispatch_refusals (
    receipt_digest TEXT PRIMARY KEY CHECK (length(receipt_digest) = 64),
    reference TEXT NOT NULL UNIQUE CHECK (
        length(reference) = 72 AND substr(reference, 1, 8) = 'scourge:'
    ),
    run_id TEXT NOT NULL REFERENCES runs,
    request_key TEXT NOT NULL REFERENCES request_keys (key),
    step_number TEXT NOT NULL,
    step TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    action_index INTEGER NOT NULL CHECK (action_index = 1),
    argv_digest TEXT NOT NULL CHECK (length(argv_digest) = 64),
    instrument_digest TEXT NOT NULL CHECK (length(instrument_digest) = 64),
    target_digest TEXT NOT NULL CHECK (length(target_digest) = 64),
    lookup_digest TEXT NOT NULL CHECK (length(lookup_digest) = 64),
    source_commit TEXT NOT NULL CHECK (
        source_commit = '6e66dca22026db00cfadb4e07a6950165b160c14'
    ),
    binary_digest TEXT NOT NULL CHECK (
        binary_digest = 'c03bd1dfb40cdcbba7ab97b5f5ab16cb00a8f5ed33c7c59c6ab59a980326abae'
    ),
    engine_instance TEXT NOT NULL CHECK (length(engine_instance) > 0),
    project_id TEXT NOT NULL CHECK (length(project_id) > 0),
    reason TEXT NOT NULL CHECK (reason = 'out-of-scope'),
    capture_handle TEXT NOT NULL CHECK (length(capture_handle) > 0),
    attachment_key TEXT NOT NULL CHECK (length(attachment_key) > 0),
    attachment_position INTEGER NOT NULL CHECK (attachment_position > 0),
    attachment_request_digest TEXT NOT NULL CHECK (length(attachment_request_digest) = 64),
    artifact_id TEXT NOT NULL CHECK (length(artifact_id) > 0),
    artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64),
    authority_original BLOB NOT NULL CHECK (
        length(authority_original) > 0 AND length(authority_original) <= 131072
    ),
    UNIQUE (run_id, step_number),
    FOREIGN KEY (run_id, step_number) REFERENCES run_steps (run_id, number)
) STRICT;

CREATE TRIGGER run_pre_dispatch_refusal_no_update
BEFORE UPDATE ON run_pre_dispatch_refusals
BEGIN
    SELECT RAISE(ABORT, 'pre-dispatch refusal evidence is immutable');
END;

CREATE TRIGGER run_pre_dispatch_refusal_no_delete
BEFORE DELETE ON run_pre_dispatch_refusals
BEGIN
    SELECT RAISE(ABORT, 'pre-dispatch refusal evidence is immutable');
END;

CREATE TRIGGER run_pre_dispatch_refusal_exact_binding
BEFORE INSERT ON run_pre_dispatch_refusals
WHEN NOT EXISTS (
    SELECT 1
      FROM runs r
      JOIN request_keys q
        ON q.key = NEW.request_key
       AND q.run_id = NEW.run_id
       AND q.engagement_id = r.engagement_id
      JOIN run_recovery rr
        ON rr.run_id = NEW.run_id
       AND rr.request_key = NEW.request_key
       AND rr.trusted_evidence = 1
       AND rr.capture_handle = NEW.capture_handle
      JOIN run_steps s
        ON s.run_id = NEW.run_id
       AND s.number = NEW.step_number
     WHERE r.id = NEW.run_id
       AND r.request_key = NEW.request_key
       AND s.step = NEW.step
       AND s.request_digest = NEW.request_digest
       AND s.instrument_reference = 'refusal:' || NEW.receipt_digest
       AND s.effects = 'unknown'
       AND s.flow_refs = '[]'
)
BEGIN
    SELECT RAISE(ABORT, 'pre-dispatch refusal binding mismatch');
END;
