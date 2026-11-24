-- Raw programmatic stores can remain unbound. An operator-created workspace
-- registers its UUID before publishing its coordination file to readers.
CREATE TABLE store_workspace (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    workspace_id TEXT NOT NULL
) STRICT;
