-- The verified staging marker binds to the exact local Investigation case.
-- Existing candidates keep NULL and are only eligible for historical reads.
ALTER TABLE publication_candidates
ADD COLUMN evidence_case_id TEXT CHECK (evidence_case_id IS NULL OR length(evidence_case_id) > 0);
