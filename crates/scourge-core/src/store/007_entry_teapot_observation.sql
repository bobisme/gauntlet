-- An inventory read is local, scoped and independently dated.
CREATE TABLE teapot_entry_observations (
    engagement_id TEXT NOT NULL REFERENCES engagements,
    route_digest TEXT NOT NULL,
    observation TEXT NOT NULL CHECK (length(observation) <= 512 AND json_type(observation) = 'object'),
    PRIMARY KEY (engagement_id, route_digest)
) STRICT;
