-- Publication receipts are part of the write-ahead state. This column binds
-- Investigation's durable receipt to the intent when the chain transaction
-- completes or supersedes the candidate.
ALTER TABLE publication_intents ADD COLUMN artifact_id TEXT;

-- Version-12 verifier writers atomically retain the exact canonical record
-- and ordered Investigation inputs needed to retry the same idempotent write.
-- Legacy intents predate this source and remain distinguishable; migration
-- must not invent bytes for them.
ALTER TABLE publication_intents ADD COLUMN candidate_required INTEGER NOT NULL DEFAULT 0
    CHECK (candidate_required IN (0, 1));

CREATE TABLE publication_candidates (
    intent_id TEXT PRIMARY KEY REFERENCES publication_intents (id),
    record_bytes BLOB NOT NULL
        CHECK (length(record_bytes) BETWEEN 1 AND 67108864),
    inputs TEXT NOT NULL
        CHECK (length(inputs) BETWEEN 1 AND 524288 AND json_type(inputs) = 'array')
) STRICT;

-- Older linked rows predate the receipt column, but the verification index
-- already held the exact artifact identity.  Reconstruct only that receipt;
-- no record bytes or verdict are copied into coordination state.
UPDATE publication_intents
SET artifact_id = (
    SELECT v.artifact_id FROM verifications v WHERE v.intent_id = publication_intents.id
)
WHERE state = 'complete';

-- Version 11 admitted more than one live intent for a run.  Refuse to guess
-- through inconsistent completed rows, and require durable intent audit order
-- before choosing among pending-only duplicates.  A linked verification is
-- authoritative; otherwise the last admitted intent survives.  Superseded
-- legacy rows deliberately keep a NULL receipt because migration must never
-- invent an Investigation artifact identity.
CREATE TABLE publication_migration_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;
INSERT INTO publication_migration_guard
SELECT CASE WHEN
    NOT EXISTS (
        SELECT 1
        FROM publication_intents i
        WHERE i.state = 'complete'
          AND NOT EXISTS (
              SELECT 1 FROM verifications v
              WHERE v.intent_id = i.id
                AND v.engagement_id = i.engagement_id
                AND v.run_id = i.run_id
                AND v.record_id = i.record_id
                AND v.record_digest = i.record_digest
                AND v.artifact_id = i.artifact_id
          )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM publication_intents i
        WHERE i.state = 'pending'
          AND NOT EXISTS (
              SELECT 1 FROM publication_intents completed
              WHERE completed.run_id = i.run_id
                AND completed.state = 'complete'
          )
          AND 1 < (
              SELECT COUNT(*) FROM publication_intents live
              WHERE live.run_id = i.run_id
                AND live.state IN ('pending', 'complete')
          )
          AND 1 <> (
              SELECT COUNT(*) FROM audit_events a
              WHERE a.operation = 'publication.intent'
                AND a.subject = i.id
          )
    )
THEN 1 ELSE 0 END;
DROP TABLE publication_migration_guard;

UPDATE publication_intents AS legacy
SET state = 'superseded'
WHERE legacy.state = 'pending'
  AND (
      EXISTS (
          SELECT 1 FROM publication_intents completed
          WHERE completed.run_id = legacy.run_id
            AND completed.state = 'complete'
      )
      OR (
          NOT EXISTS (
              SELECT 1 FROM publication_intents completed
              WHERE completed.run_id = legacy.run_id
                AND completed.state = 'complete'
          )
          AND (
              SELECT a.revision FROM audit_events a
              WHERE a.operation = 'publication.intent'
                AND a.subject = legacy.id
          ) < (
              SELECT MAX(a.revision)
              FROM publication_intents pending
              JOIN audit_events a
                ON a.operation = 'publication.intent'
               AND a.subject = pending.id
              WHERE pending.run_id = legacy.run_id
                AND pending.state = 'pending'
          )
      )
  );

CREATE UNIQUE INDEX publication_one_live_run
ON publication_intents (run_id)
WHERE state IN ('pending', 'complete');

CREATE UNIQUE INDEX publication_artifact_receipt
ON publication_intents (artifact_id)
WHERE artifact_id IS NOT NULL;

-- New intent rows are always the verifier's pending, receipt-free write-ahead
-- declaration against the checkpoint that exists at insertion time.
CREATE TRIGGER publication_intent_insert
BEFORE INSERT ON publication_intents
WHEN NEW.state <> 'pending'
  OR NEW.artifact_id IS NOT NULL
  OR NEW.candidate_required <> 1
  OR NOT EXISTS (
      SELECT 1 FROM engagements e
      WHERE e.id = NEW.engagement_id
        AND e.head_sequence = NEW.expected_sequence
        AND e.head_digest IS NEW.expected_digest
  )
BEGIN
    SELECT RAISE(ABORT, 'invalid publication intent');
END;

-- Identity and predecessor fields never change. Runtime mutation binds an
-- acknowledged artifact while terminally completing or superseding intent.
-- Receipt-free superseded rows exist only when this migration retires a v11
-- duplicate; the trigger prevents new callers from constructing one.
CREATE TRIGGER publication_intent_transition
BEFORE UPDATE ON publication_intents
WHEN OLD.id <> NEW.id
  OR OLD.engagement_id <> NEW.engagement_id
  OR OLD.run_id <> NEW.run_id
  OR OLD.record_id <> NEW.record_id
  OR OLD.record_digest <> NEW.record_digest
  OR OLD.expected_sequence <> NEW.expected_sequence
  OR OLD.expected_digest IS NOT NEW.expected_digest
  OR OLD.candidate_required <> NEW.candidate_required
  OR OLD.state <> 'pending'
  OR NEW.state NOT IN ('complete', 'superseded')
  OR OLD.artifact_id IS NOT NULL
  OR NEW.artifact_id IS NULL
  OR (NEW.state = 'complete' AND NOT EXISTS (
      SELECT 1 FROM verifications v
      WHERE v.intent_id = NEW.id
        AND v.engagement_id = NEW.engagement_id
        AND v.run_id = NEW.run_id
        AND v.record_id = NEW.record_id
        AND v.record_digest = NEW.record_digest
        AND v.artifact_id = NEW.artifact_id
  ))
  OR (NEW.state = 'superseded' AND EXISTS (
      SELECT 1 FROM verifications v WHERE v.intent_id = NEW.id
  ))
BEGIN
    SELECT RAISE(ABORT, 'invalid publication transition');
END;

-- Staging is write-once and belongs only to a new verifier-owned intent. The
-- application checks the canonical bytes, digest, frozen record binding and
-- ordered typed Artifact inputs before either row is inserted.
CREATE TRIGGER publication_candidate_insert
BEFORE INSERT ON publication_candidates
WHEN NOT EXISTS (
    SELECT 1 FROM publication_intents i
    WHERE i.id = NEW.intent_id
      AND i.state = 'pending'
      AND i.artifact_id IS NULL
      AND i.candidate_required = 1
)
BEGIN
    SELECT RAISE(ABORT, 'invalid publication candidate');
END;

CREATE TRIGGER publication_candidate_no_update
BEFORE UPDATE ON publication_candidates
BEGIN
    SELECT RAISE(ABORT, 'publication candidates are immutable');
END;

CREATE TRIGGER publication_candidate_no_delete
BEFORE DELETE ON publication_candidates
BEGIN
    SELECT RAISE(ABORT, 'publication candidates are immutable');
END;

CREATE TRIGGER publication_intent_no_delete
BEFORE DELETE ON publication_intents
BEGIN
    SELECT RAISE(ABORT, 'publication intents are immutable');
END;

-- A chain row can be inserted only while its matching intent is pending and
-- still names the current predecessor.  The application additionally checks
-- the exact canonical record bytes and artifact digest before this statement.
CREATE TRIGGER verification_insert
BEFORE INSERT ON verifications
WHEN NOT EXISTS (
    SELECT 1
    FROM publication_intents i
    JOIN engagements e ON e.id = i.engagement_id
    WHERE i.id = NEW.intent_id
      AND i.state = 'pending'
      AND i.artifact_id IS NULL
      AND i.engagement_id = NEW.engagement_id
      AND i.run_id = NEW.run_id
      AND i.record_id = NEW.record_id
      AND i.record_digest = NEW.record_digest
      AND i.expected_sequence + 1 = NEW.sequence
      AND e.head_sequence = i.expected_sequence
      AND e.head_digest IS i.expected_digest
)
BEGIN
    SELECT RAISE(ABORT, 'invalid verification publication');
END;

CREATE TRIGGER verification_no_update
BEFORE UPDATE ON verifications
BEGIN
    SELECT RAISE(ABORT, 'verification index is immutable');
END;

CREATE TRIGGER verification_no_delete
BEFORE DELETE ON verifications
BEGIN
    SELECT RAISE(ABORT, 'verification index is immutable');
END;
