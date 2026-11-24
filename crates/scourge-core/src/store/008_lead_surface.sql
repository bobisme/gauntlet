ALTER TABLE lead_revisions ADD COLUMN property TEXT;
ALTER TABLE lead_revisions ADD COLUMN origin TEXT NOT NULL DEFAULT 'local'
    CHECK (origin IN ('local', 'teapot'));
ALTER TABLE lead_revisions ADD COLUMN source_ref TEXT;
ALTER TABLE lead_revisions ADD COLUMN endpoint TEXT;
ALTER TABLE lead_revisions ADD COLUMN flow_ids TEXT NOT NULL DEFAULT '[]'
    CHECK (json_type(flow_ids) = 'array');
ALTER TABLE lead_revisions ADD COLUMN producer_confidence TEXT;

CREATE TABLE lead_imports (
    engagement_id TEXT NOT NULL REFERENCES engagements,
    source_ref TEXT NOT NULL,
    lead_id TEXT NOT NULL REFERENCES leads,
    PRIMARY KEY (engagement_id, source_ref),
    UNIQUE (engagement_id, lead_id)
) STRICT;
