CREATE TABLE store_revision (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;
INSERT INTO store_revision VALUES (1, 0);

CREATE TABLE audit_events (
    revision INTEGER PRIMARY KEY CHECK (revision > 0),
    operation TEXT NOT NULL,
    subject TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

-- Each engagement owns exactly one checkpoint, including its empty checkpoint.
CREATE TABLE engagements (
    id TEXT PRIMARY KEY,
    head_sequence INTEGER NOT NULL DEFAULT 0,
    head_digest TEXT,
    CHECK ((head_sequence = 0 AND head_digest IS NULL)
        OR (head_sequence > 0 AND head_digest IS NOT NULL)),
    FOREIGN KEY (id, head_sequence, head_digest)
        REFERENCES verifications (engagement_id, sequence, record_digest)
) STRICT;
CREATE TABLE engagement_revisions (
    engagement_id TEXT NOT NULL REFERENCES engagements,
    revision INTEGER NOT NULL CHECK (revision > 0),
    manifest_artifact_id TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    pass_digest TEXT NOT NULL,
    PRIMARY KEY (engagement_id, revision)
) STRICT;
CREATE TABLE leads (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements,
    UNIQUE (engagement_id, id)
) STRICT;
CREATE TABLE lead_revisions (
    lead_id TEXT NOT NULL REFERENCES leads,
    revision INTEGER NOT NULL CHECK (revision > 0),
    text TEXT NOT NULL,
    class TEXT,
    slots TEXT NOT NULL CHECK (json_type(slots) = 'object'),
    proposed_policy TEXT CHECK (json_valid(proposed_policy)),
    PRIMARY KEY (lead_id, revision)
) STRICT;
CREATE TABLE lead_events (
    id INTEGER PRIMARY KEY,
    lead_id TEXT NOT NULL,
    lead_revision INTEGER NOT NULL,
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_refs TEXT NOT NULL CHECK (json_type(evidence_refs) = 'array'),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (lead_id, lead_revision) REFERENCES lead_revisions
) STRICT;
CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements,
    request_key TEXT NOT NULL,
    experiment_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    flags TEXT NOT NULL CHECK (json_type(flags) = 'array'),
    effects TEXT NOT NULL,
    oracle_result TEXT,
    reproduction TEXT NOT NULL,
    cleanup TEXT NOT NULL,
    UNIQUE (engagement_id, id)
) STRICT;
CREATE TABLE run_steps (
    run_id TEXT NOT NULL REFERENCES runs,
    number TEXT NOT NULL,
    step TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    flow_id_floor TEXT,
    instrument_reference TEXT,
    effects TEXT,
    flow_refs TEXT NOT NULL CHECK (json_type(flow_refs) = 'array'),
    PRIMARY KEY (run_id, number)
) STRICT;
CREATE TABLE publication_intents (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    expected_sequence INTEGER NOT NULL,
    expected_digest TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'superseded')),
    CHECK ((expected_sequence = 0 AND expected_digest IS NULL)
        OR (expected_sequence > 0 AND expected_digest IS NOT NULL)),
    FOREIGN KEY (engagement_id, run_id) REFERENCES runs (engagement_id, id),
    UNIQUE (id, engagement_id, run_id, record_id, record_digest)
) STRICT;
CREATE TABLE verifications (
    record_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    run_id TEXT NOT NULL UNIQUE,
    lead_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    intent_id TEXT NOT NULL UNIQUE,
    UNIQUE (engagement_id, sequence),
    UNIQUE (engagement_id, sequence, record_digest),
    FOREIGN KEY (engagement_id, lead_id) REFERENCES leads (engagement_id, id),
    FOREIGN KEY (intent_id, engagement_id, run_id, record_id, record_digest)
        REFERENCES publication_intents (id, engagement_id, run_id, record_id, record_digest)
) STRICT;
