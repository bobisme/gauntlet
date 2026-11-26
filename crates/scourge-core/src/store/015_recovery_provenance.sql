-- Rows enrolled before this schema cannot prove that their step outcomes came
-- from the production adapter writer: the old public recovery writer could
-- enrich the same run.step lane.  Only a capture validated and persisted by
-- the post-v14 production path crosses this immutable trust boundary.
ALTER TABLE run_recovery
ADD COLUMN trusted_evidence INTEGER NOT NULL DEFAULT 0
CHECK (trusted_evidence IN (0, 1));

-- Legacy handles remain retained for audit, but do not become trusted merely
-- because they existed at upgrade.  Only trusted owners participate in this
-- uniqueness constraint; the production transition separately refuses a
-- handle already named by any legacy or trusted row.
CREATE UNIQUE INDEX run_recovery_trusted_capture_owner
ON run_recovery (capture_handle)
WHERE trusted_evidence=1;

CREATE TRIGGER run_recovery_trusted_insert
BEFORE INSERT ON run_recovery
WHEN NEW.trusted_evidence<>0
BEGIN
    SELECT RAISE(ABORT, 'run recovery provenance must start untrusted');
END;

CREATE TRIGGER run_recovery_trust_boundary
BEFORE UPDATE OF trusted_evidence ON run_recovery
WHEN NEW.trusted_evidence<>OLD.trusted_evidence
 AND NOT (
     OLD.trusted_evidence=0
     AND NEW.trusted_evidence=1
     AND OLD.capture_handle IS NULL
     AND NEW.capture_handle IS NOT NULL
 )
BEGIN
    SELECT RAISE(ABORT, 'run recovery provenance is immutable');
END;
