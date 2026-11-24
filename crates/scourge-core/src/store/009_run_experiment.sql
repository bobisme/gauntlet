-- The run is declared before any external call. Once the frozen experiment is
-- retained, this nullable pointer binds that pre-existing row to its evidence
-- artifact without duplicating the digest already stored on the run.
ALTER TABLE runs ADD COLUMN experiment_artifact_id TEXT;
CREATE UNIQUE INDEX run_experiment_artifacts
    ON runs (experiment_artifact_id)
    WHERE experiment_artifact_id IS NOT NULL;
