-- Remember every keyed run that predates durable conflict ownership.  Its
-- exact pass/session/resource set cannot be reconstructed from a pre-v10
-- store, so unresolved legacy runs receive a conservative global barrier. The
-- marker remains after terminal release so compatible terminal read-modify
-- writes can be distinguished from a new keyed run that skipped preflight.
CREATE TABLE legacy_keyed_runs (
    run_id TEXT PRIMARY KEY REFERENCES runs
) STRICT;
INSERT INTO legacy_keyed_runs (run_id)
    SELECT run_id FROM request_keys;

-- Conflict ownership is durable run state, not merely process-local mutual
-- exclusion. A verifier process may die after dispatch while the instrument
-- job continues, so closing its flock descriptors must not release these
-- claims. `legacy` rows are conservative barriers for pre-v10 keyed runs;
-- `exact` rows bind the complete derived set used by current admission.
CREATE TABLE run_conflict_sets (
    run_id TEXT PRIMARY KEY REFERENCES runs,
    set_digest TEXT NOT NULL,
    claim_kind TEXT NOT NULL CHECK (claim_kind IN ('exact', 'legacy'))
) STRICT;
CREATE TABLE run_conflicts (
    conflict_key TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES run_conflict_sets (run_id)
) STRICT;
CREATE INDEX run_conflicts_by_run ON run_conflicts (run_id);

-- A stop is durable admission state, not merely an audit label. Ordinary
-- manifest amendments leave this fence in place; only the explicit resume
-- transition removes it. The revision link makes a torn or invented stop
-- impossible to interpret as authority.
CREATE TABLE engagement_stops (
    engagement_id TEXT PRIMARY KEY REFERENCES engagements (id),
    stopped_revision INTEGER NOT NULL,
    FOREIGN KEY (engagement_id, stopped_revision)
        REFERENCES engagement_revisions (engagement_id, revision)
) STRICT;

-- A declared run with no step is definitionally pre-start and can safely be
-- resumed into exact keys (or install a conservative barrier transactionally
-- with its first legacy step). A resolved terminal run likewise owes no future
-- target effect. Every other legacy keyed run blocks new exact admission until
-- it is reconciled terminally.
INSERT INTO run_conflict_sets (run_id, set_digest, claim_kind)
    SELECT l.run_id, 'legacy', 'legacy'
    FROM legacy_keyed_runs l
    JOIN runs r ON r.id = l.run_id
    WHERE NOT (
        r.state = 'declared'
        AND NOT EXISTS (SELECT 1 FROM run_steps s WHERE s.run_id = r.id)
    )
      AND NOT (
        r.state = 'finalized'
        AND r.effects <> 'unknown'
        AND r.cleanup NOT IN ('partial', 'failed', 'unknown')
        AND NOT EXISTS (
            SELECT 1 FROM run_steps s
            WHERE s.run_id = r.id
              AND (s.effects IS NULL OR s.effects = 'unknown')
        )
    );
