-- Per-object cleanup authority and outcomes. A target-derived name or
-- request alone never grants authority: only an established plant response
-- may have an object_id and cleanup intent.
CREATE TABLE run_cleanup (
    run_id TEXT NOT NULL REFERENCES runs,
    round TEXT NOT NULL,
    object TEXT NOT NULL CHECK (object IN ('primary', 'control')),
    plant_step TEXT NOT NULL,
    plant_request_digest TEXT NOT NULL,
    object_id TEXT,
    ownership TEXT NOT NULL CHECK (ownership IN ('pending', 'established', 'not_created', 'unknown')),
    cleanup_step TEXT,
    cleanup_request_digest TEXT,
    flow_id_floor TEXT,
    instrument_reference TEXT,
    effects TEXT,
    response_status TEXT,
    flow_refs TEXT NOT NULL CHECK (json_type(flow_refs) = 'array'),
    outcome TEXT NOT NULL CHECK (outcome IN ('owed', 'in_flight', 'not_required', 'complete', 'failed', 'unknown')),
    PRIMARY KEY (run_id, round, object),
    CHECK (response_status IS NULL OR
           (length(response_status) = 3 AND response_status NOT GLOB '*[^0-9]*' AND
            CAST(response_status AS INTEGER) BETWEEN 100 AND 599)),
    CHECK (effects IS NOT 'observed' OR
           (instrument_reference IS NOT NULL AND instrument_reference LIKE 'flow:%' AND
            length(instrument_reference) > 5 AND
            substr(instrument_reference, 6) NOT GLOB '*[^0-9]*')),
    CHECK ((ownership = 'established') = (object_id IS NOT NULL)),
    CHECK ((cleanup_step IS NULL) = (cleanup_request_digest IS NULL)),
    CHECK (cleanup_step IS NULL OR COALESCE(
           (length(round) > 0 AND round NOT GLOB '*[^0-9]*' AND
            CAST(round AS INTEGER) > 0 AND
            round = CAST(CAST(round AS INTEGER) AS TEXT) AND
            cleanup_step = CAST(CAST(round AS INTEGER) * 12 AS TEXT)), 0)),
    CHECK (ownership = 'established' OR cleanup_step IS NULL),
    CHECK ((ownership IN ('pending', 'unknown') AND outcome = 'owed') OR
           (ownership = 'not_created' AND outcome = 'not_required') OR
           (ownership = 'established' AND outcome IN ('owed', 'in_flight', 'complete', 'failed', 'unknown'))),
    CHECK (COALESCE(
           (outcome IN ('owed', 'not_required') AND instrument_reference IS NULL AND
            effects IS NULL AND response_status IS NULL AND flow_refs = '[]') OR
           (outcome = 'complete' AND instrument_reference IS NOT NULL AND effects = 'observed' AND
            response_status = '204' AND json_array_length(flow_refs) > 0 AND
            json_extract(flow_refs, '$[#-1].step') IN
                (CASE object WHEN 'primary' THEN 'C.primary.request' ELSE 'C.control.request' END,
                 CASE object WHEN 'primary' THEN 'C.primary.retry' ELSE 'C.control.retry' END) AND
            json_type(flow_refs, '$[#-1].flow_id') = 'integer' AND
             json_extract(flow_refs, '$[#-1].completeness') = 'complete' AND
            instrument_reference = 'flow:' || (flow_refs -> '$[#-1].flow_id')) OR
           (outcome = 'failed' AND instrument_reference IS NOT NULL AND effects IN ('none', 'observed') AND
            ((effects = 'none' AND response_status IS NULL) OR
             (effects = 'observed' AND response_status IS NOT NULL AND
              CAST(response_status AS INTEGER) NOT BETWEEN 200 AND 299))) OR
           (outcome = 'in_flight' AND
            (effects IS NULL OR effects IN ('none', 'observed', 'unknown'))) OR
           (outcome = 'unknown' AND effects IN ('unknown', 'observed')),
           0)),
    CHECK (outcome IN ('owed', 'not_required') OR cleanup_step IS NOT NULL),
    CHECK (cleanup_step IS NOT NULL OR
           (flow_id_floor IS NULL AND instrument_reference IS NULL AND effects IS NULL AND
            response_status IS NULL AND flow_refs = '[]'))
) STRICT;

-- Only the pre-dispatch owed intent may precede the frozen C RunStep. Once an
-- action becomes in-flight or terminal, its exact batch boundary must already
-- be durable even when the receipt retained no flow.
CREATE TRIGGER run_cleanup_step_boundary_insert
BEFORE INSERT ON run_cleanup
WHEN NEW.outcome NOT IN ('owed', 'not_required') AND NOT EXISTS (
    SELECT 1 FROM run_steps AS step_row
    WHERE step_row.run_id = NEW.run_id
      AND step_row.number = NEW.cleanup_step
      AND step_row.step = 'round.' || NEW.round || '.C'
)
BEGIN
    SELECT RAISE(ABORT, 'run_cleanup outcome has no durable cleanup step');
END;

CREATE TRIGGER run_cleanup_step_boundary_update
BEFORE UPDATE ON run_cleanup
WHEN NEW.outcome NOT IN ('owed', 'not_required') AND NOT EXISTS (
    SELECT 1 FROM run_steps AS step_row
    WHERE step_row.run_id = NEW.run_id
      AND step_row.number = NEW.cleanup_step
      AND step_row.step = 'round.' || NEW.round || '.C'
)
BEGIN
    SELECT RAISE(ABORT, 'run_cleanup outcome has no durable cleanup step');
END;

-- Every stored flow must decode through the frozen Flow contract. SQLite's
-- JSON extractors otherwise conflate a missing nullable member with JSON null,
-- coerce integers beyond u64, and can retain strings that Rust must reject.
CREATE TRIGGER run_steps_flow_shape_insert
BEFORE INSERT ON run_steps
WHEN scourge_flow_refs_valid(NEW.flow_refs) != 1 OR EXISTS (
    SELECT 1 FROM json_each(NEW.flow_refs) AS flow
    WHERE json_type(flow.value) IS NOT 'object'
       OR (SELECT count(*) FROM json_each(flow.value)) != 5
       OR json_type(flow.value, '$.step') IS NOT 'text'
       OR length(json_extract(flow.value, '$.step')) = 0
       OR instr(json_extract(flow.value, '$.step'), char(0)) != 0
       OR (flow.value -> '$.step') IS NOT
            json_quote(json_extract(flow.value, '$.step'))
       OR (json_type(flow.value, '$.flow_id') IS NOT 'null' AND
           json_type(flow.value, '$.flow_id') IS NOT 'integer')
       OR (json_type(flow.value, '$.flow_id') = 'integer' AND
           ((flow.value -> '$.flow_id') GLOB '*[^0-9]*' OR
            length(flow.value -> '$.flow_id') > 20 OR
            (length(flow.value -> '$.flow_id') = 20 AND
             CAST(flow.value -> '$.flow_id' AS TEXT) >
                 '18446744073709551615' COLLATE BINARY)))
       OR json_type(flow.value, '$.completeness') IS NOT 'text'
       OR json_extract(flow.value, '$.completeness') NOT IN
            ('missing', 'partial', 'complete')
       OR (json_type(flow.value, '$.decoder') IS NOT 'null' AND
           json_type(flow.value, '$.decoder') IS NOT 'object')
       OR (json_type(flow.value, '$.decoder') = 'object' AND
           ((SELECT count(*) FROM json_each(
                json_extract(flow.value, '$.decoder'))) != 2 OR
            json_type(flow.value, '$.decoder.id') IS NOT 'text' OR
            length(json_extract(flow.value, '$.decoder.id')) = 0 OR
            instr(json_extract(flow.value, '$.decoder.id'), char(0)) != 0 OR
            (flow.value -> '$.decoder.id') IS NOT
                json_quote(json_extract(flow.value, '$.decoder.id')) OR
            json_type(flow.value, '$.decoder.version') IS NOT 'text' OR
            length(json_extract(flow.value, '$.decoder.version')) = 0 OR
            instr(json_extract(flow.value, '$.decoder.version'), char(0)) != 0 OR
            (flow.value -> '$.decoder.version') IS NOT
                json_quote(json_extract(flow.value, '$.decoder.version'))))
       OR (json_type(flow.value, '$.original') IS NOT 'null' AND
           json_type(flow.value, '$.original') IS NOT 'object')
       OR (json_type(flow.value, '$.original') = 'object' AND
           ((SELECT count(*) FROM json_each(
                json_extract(flow.value, '$.original'))) != 2 OR
            json_type(flow.value, '$.original.artifact_id') IS NOT 'text' OR
            length(json_extract(flow.value, '$.original.artifact_id')) = 0 OR
            instr(json_extract(flow.value, '$.original.artifact_id'), char(0)) != 0 OR
            (flow.value -> '$.original.artifact_id') IS NOT
                json_quote(json_extract(flow.value, '$.original.artifact_id')) OR
            json_type(flow.value, '$.original.digest') IS NOT 'text' OR
            length(flow.value -> '$.original.digest') != 66 OR
            substr(flow.value -> '$.original.digest', 1, 1) != '"' OR
            substr(flow.value -> '$.original.digest', 66, 1) != '"' OR
            substr(flow.value -> '$.original.digest', 2, 64)
                GLOB '*[^0-9a-f]*'))
)
BEGIN
    SELECT RAISE(ABORT, 'run_steps flow does not decode');
END;

CREATE TRIGGER run_steps_flow_shape_update
BEFORE UPDATE OF flow_refs ON run_steps
WHEN scourge_flow_refs_valid(NEW.flow_refs) != 1 OR EXISTS (
    SELECT 1 FROM json_each(NEW.flow_refs) AS flow
    WHERE json_type(flow.value) IS NOT 'object'
       OR (SELECT count(*) FROM json_each(flow.value)) != 5
       OR json_type(flow.value, '$.step') IS NOT 'text'
       OR length(json_extract(flow.value, '$.step')) = 0
       OR instr(json_extract(flow.value, '$.step'), char(0)) != 0
       OR (flow.value -> '$.step') IS NOT
            json_quote(json_extract(flow.value, '$.step'))
       OR (json_type(flow.value, '$.flow_id') IS NOT 'null' AND
           json_type(flow.value, '$.flow_id') IS NOT 'integer')
       OR (json_type(flow.value, '$.flow_id') = 'integer' AND
           ((flow.value -> '$.flow_id') GLOB '*[^0-9]*' OR
            length(flow.value -> '$.flow_id') > 20 OR
            (length(flow.value -> '$.flow_id') = 20 AND
             CAST(flow.value -> '$.flow_id' AS TEXT) >
                 '18446744073709551615' COLLATE BINARY)))
       OR json_type(flow.value, '$.completeness') IS NOT 'text'
       OR json_extract(flow.value, '$.completeness') NOT IN
            ('missing', 'partial', 'complete')
       OR (json_type(flow.value, '$.decoder') IS NOT 'null' AND
           json_type(flow.value, '$.decoder') IS NOT 'object')
       OR (json_type(flow.value, '$.decoder') = 'object' AND
           ((SELECT count(*) FROM json_each(
                json_extract(flow.value, '$.decoder'))) != 2 OR
            json_type(flow.value, '$.decoder.id') IS NOT 'text' OR
            length(json_extract(flow.value, '$.decoder.id')) = 0 OR
            instr(json_extract(flow.value, '$.decoder.id'), char(0)) != 0 OR
            (flow.value -> '$.decoder.id') IS NOT
                json_quote(json_extract(flow.value, '$.decoder.id')) OR
            json_type(flow.value, '$.decoder.version') IS NOT 'text' OR
            length(json_extract(flow.value, '$.decoder.version')) = 0 OR
            instr(json_extract(flow.value, '$.decoder.version'), char(0)) != 0 OR
            (flow.value -> '$.decoder.version') IS NOT
                json_quote(json_extract(flow.value, '$.decoder.version'))))
       OR (json_type(flow.value, '$.original') IS NOT 'null' AND
           json_type(flow.value, '$.original') IS NOT 'object')
       OR (json_type(flow.value, '$.original') = 'object' AND
           ((SELECT count(*) FROM json_each(
                json_extract(flow.value, '$.original'))) != 2 OR
            json_type(flow.value, '$.original.artifact_id') IS NOT 'text' OR
            length(json_extract(flow.value, '$.original.artifact_id')) = 0 OR
            instr(json_extract(flow.value, '$.original.artifact_id'), char(0)) != 0 OR
            (flow.value -> '$.original.artifact_id') IS NOT
                json_quote(json_extract(flow.value, '$.original.artifact_id')) OR
            json_type(flow.value, '$.original.digest') IS NOT 'text' OR
            length(flow.value -> '$.original.digest') != 66 OR
            substr(flow.value -> '$.original.digest', 1, 1) != '"' OR
            substr(flow.value -> '$.original.digest', 66, 1) != '"' OR
            substr(flow.value -> '$.original.digest', 2, 64)
                GLOB '*[^0-9a-f]*'))
)
BEGIN
    SELECT RAISE(ABORT, 'run_steps flow does not decode');
END;

-- Raw step updates must preserve the same immutable identity, exact prefix,
-- null-original append, and typed original-enrichment contract as put_step.
-- Otherwise a writer could insert before a terminal object's tail, replace or
-- remove prior evidence, or rename the canonical C boundary behind cleanup.
CREATE TRIGGER run_steps_evidence_monotonic
BEFORE UPDATE ON run_steps
WHEN OLD.run_id IS NOT NEW.run_id
  OR OLD.number IS NOT NEW.number
  OR OLD.step IS NOT NEW.step
  OR OLD.request_digest IS NOT NEW.request_digest
  OR OLD.flow_id_floor IS NOT NEW.flow_id_floor
  OR NOT (OLD.instrument_reference IS NULL OR
          OLD.instrument_reference IS NEW.instrument_reference)
  OR NOT COALESCE((OLD.effects IS NEW.effects OR OLD.effects IS NULL OR
                   (OLD.effects = 'unknown' AND NEW.effects IN ('observed', 'none'))), 0)
  OR NOT (
      OLD.flow_refs IS NEW.flow_refs OR
      (json_array_length(OLD.flow_refs) = json_array_length(NEW.flow_refs) AND
       NOT EXISTS (
           SELECT 1
           FROM json_each(OLD.flow_refs) AS old_flow
           JOIN json_each(NEW.flow_refs) AS new_flow ON new_flow.key = old_flow.key
           WHERE json_type(new_flow.value) IS NOT 'object'
              OR (SELECT count(*) FROM json_each(new_flow.value)) != 5
              OR json_extract(old_flow.value, '$.step')
                    IS NOT json_extract(new_flow.value, '$.step')
              OR (old_flow.value -> '$.flow_id')
                    IS NOT (new_flow.value -> '$.flow_id')
              OR json_extract(old_flow.value, '$.completeness')
                    IS NOT json_extract(new_flow.value, '$.completeness')
              OR json_extract(old_flow.value, '$.decoder')
                    IS NOT json_extract(new_flow.value, '$.decoder')
              OR NOT COALESCE((
                  json_extract(old_flow.value, '$.original')
                      IS json_extract(new_flow.value, '$.original') OR
                  (json_type(old_flow.value, '$.original') = 'null' AND
                   json_type(new_flow.value, '$.original') = 'object' AND
                   (SELECT count(*) FROM json_each(
                       json_extract(new_flow.value, '$.original'))) = 2 AND
                   json_type(new_flow.value, '$.original.artifact_id') = 'text' AND
                   length(json_extract(new_flow.value, '$.original.artifact_id')) > 0 AND
                   instr(json_extract(new_flow.value, '$.original.artifact_id'), char(0)) = 0 AND
                   json_type(new_flow.value, '$.original.digest') = 'text' AND
                   length(json_extract(new_flow.value, '$.original.digest')) = 64 AND
                   json_extract(new_flow.value, '$.original.digest')
                       NOT GLOB '*[^0-9a-f]*')
              ), 0)
       )) OR
      (json_array_length(NEW.flow_refs) > json_array_length(OLD.flow_refs) AND
       NOT EXISTS (
           SELECT 1
           FROM json_each(OLD.flow_refs) AS old_flow
           JOIN json_each(NEW.flow_refs) AS new_flow ON new_flow.key = old_flow.key
           WHERE old_flow.value IS NOT new_flow.value
       ) AND
       NOT EXISTS (
           SELECT 1 FROM json_each(NEW.flow_refs) AS new_flow
           WHERE CAST(new_flow.key AS INTEGER) >= json_array_length(OLD.flow_refs)
             AND (json_type(new_flow.value) IS NOT 'object'
               OR (SELECT count(*) FROM json_each(new_flow.value)) != 5
               OR json_type(new_flow.value, '$.step') IS NOT 'text'
               OR length(json_extract(new_flow.value, '$.step')) = 0
               OR instr(json_extract(new_flow.value, '$.step'), char(0)) != 0
               OR (json_type(new_flow.value, '$.flow_id') IS NOT 'null' AND
                   json_type(new_flow.value, '$.flow_id') IS NOT 'integer')
               OR (json_type(new_flow.value, '$.flow_id') = 'integer' AND
                   json_extract(new_flow.value, '$.flow_id') < 0)
               OR (json_type(new_flow.value, '$.flow_id') = 'integer' AND
                   OLD.flow_id_floor IS NOT NULL AND NOT (
                       length(new_flow.value -> '$.flow_id') > length(OLD.flow_id_floor) OR
                       (length(new_flow.value -> '$.flow_id') = length(OLD.flow_id_floor) AND
                        (new_flow.value -> '$.flow_id') > OLD.flow_id_floor)))
               OR json_type(new_flow.value, '$.original') IS NOT 'null'
               OR json_type(new_flow.value, '$.completeness') IS NOT 'text'
               OR json_extract(new_flow.value, '$.completeness') NOT IN
                    ('missing', 'partial', 'complete')
               OR (json_type(new_flow.value, '$.decoder') IS NOT 'null' AND
                   json_type(new_flow.value, '$.decoder') IS NOT 'object')
               OR (OLD.step LIKE 'round.%.C' AND
                   OLD.step = 'round.' ||
                       CAST(CAST(OLD.number AS INTEGER) / 12 AS TEXT) || '.C' AND
                   CAST(OLD.number AS INTEGER) > 0 AND
                   CAST(OLD.number AS INTEGER) % 12 = 0 AND
                   json_extract(new_flow.value, '$.step') NOT IN
                     ('C.primary.request', 'C.primary.redirect',
                      'C.primary.login', 'C.primary.retry',
                      'C.control.request', 'C.control.redirect',
                      'C.control.login', 'C.control.retry')))
       ) AND
       (OLD.effects IS NULL AND
        (json_array_length(OLD.flow_refs) = 0 OR
         (OLD.step LIKE 'round.%.C' AND
          OLD.step = 'round.' ||
              CAST(CAST(OLD.number AS INTEGER) / 12 AS TEXT) || '.C' AND
          CAST(OLD.number AS INTEGER) > 0 AND
          CAST(OLD.number AS INTEGER) % 12 = 0)) OR
        (OLD.effects = 'unknown' AND NEW.effects = 'observed' AND
         json_array_length(OLD.flow_refs) = 0 AND
         json_array_length(NEW.flow_refs) = 1 AND
         json_type(NEW.flow_refs, '$[0].flow_id') = 'integer' AND
         (NEW.instrument_reference IS NULL OR
          NEW.instrument_reference = 'flow:' || (NEW.flow_refs -> '$[0].flow_id')) AND
         (OLD.flow_id_floor IS NULL OR
          length(NEW.flow_refs -> '$[0].flow_id') > length(OLD.flow_id_floor) OR
          (length(NEW.flow_refs -> '$[0].flow_id') = length(OLD.flow_id_floor) AND
           (NEW.flow_refs -> '$[0].flow_id') > OLD.flow_id_floor))))
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'run_steps evidence is not monotonic');
END;

-- put_step uses a validated UPDATE for existing rows. Refuse duplicate INSERT
-- so INSERT OR REPLACE cannot delete and recreate durable step evidence.
CREATE TRIGGER run_steps_no_replace
BEFORE INSERT ON run_steps
WHEN EXISTS (
    SELECT 1 FROM run_steps AS stored
    WHERE stored.run_id = NEW.run_id AND stored.number = NEW.number
)
BEGIN
    SELECT RAISE(ABORT, 'run_steps replacement is forbidden');
END;

CREATE TRIGGER run_steps_cleanup_delete
BEFORE DELETE ON run_steps
WHEN EXISTS (
    SELECT 1 FROM run_cleanup AS cleanup
    WHERE cleanup.run_id = OLD.run_id
      AND cleanup.cleanup_step = OLD.number
      AND OLD.step = 'round.' || cleanup.round || '.C'
)
BEGIN
    SELECT RAISE(ABORT, 'durable cleanup step cannot be deleted');
END;

CREATE TRIGGER run_steps_cleanup_labels_insert
BEFORE INSERT ON run_steps
WHEN NEW.step LIKE 'round.%.C'
 AND NEW.step = 'round.' || CAST(CAST(NEW.number AS INTEGER) / 12 AS TEXT) || '.C'
 AND CAST(NEW.number AS INTEGER) > 0
 AND CAST(NEW.number AS INTEGER) % 12 = 0
 AND EXISTS (
     SELECT 1 FROM json_each(NEW.flow_refs) AS new_flow
     WHERE json_type(new_flow.value) IS NOT 'object'
        OR (SELECT count(*) FROM json_each(new_flow.value)) != 5
        OR json_type(new_flow.value, '$.step') IS NOT 'text'
        OR json_extract(new_flow.value, '$.step') NOT IN
             ('C.primary.request', 'C.primary.redirect',
              'C.primary.login', 'C.primary.retry',
              'C.control.request', 'C.control.redirect',
              'C.control.login', 'C.control.retry')
        OR (json_type(new_flow.value, '$.flow_id') IS NOT 'null' AND
            json_type(new_flow.value, '$.flow_id') IS NOT 'integer')
        OR (json_type(new_flow.value, '$.flow_id') = 'integer' AND
            json_extract(new_flow.value, '$.flow_id') < 0)
        OR json_type(new_flow.value, '$.original') IS NOT 'null'
        OR json_type(new_flow.value, '$.completeness') IS NOT 'text'
        OR json_extract(new_flow.value, '$.completeness') NOT IN
             ('missing', 'partial', 'complete')
        OR (json_type(new_flow.value, '$.decoder') IS NOT 'null' AND
            json_type(new_flow.value, '$.decoder') IS NOT 'object')
 )
BEGIN
    SELECT RAISE(ABORT, 'cleanup step contains an unsupported flow label');
END;

-- C evidence may appear only after that object's in-flight boundary. A
-- terminal object cannot gain a late retry merely because its sibling keeps
-- the batch step open. The one recovery exception binds a previously unknown,
-- flowless action to its exact first retained flow.
CREATE TRIGGER run_steps_cleanup_flow_insert
BEFORE INSERT ON run_steps
WHEN NOT EXISTS (
    SELECT 1 FROM run_steps AS stored
    WHERE stored.run_id = NEW.run_id AND stored.number = NEW.number
) AND EXISTS (
    SELECT 1 FROM json_each(NEW.flow_refs) AS new_flow
    WHERE json_extract(new_flow.value, '$.step') IN
              ('C.primary.request', 'C.primary.redirect',
               'C.primary.login', 'C.primary.retry',
               'C.control.request', 'C.control.redirect',
               'C.control.login', 'C.control.retry')
      AND NOT EXISTS (
          SELECT 1 FROM run_cleanup AS cleanup
          WHERE cleanup.run_id = NEW.run_id
            AND cleanup.cleanup_step = NEW.number
            AND NEW.step = 'round.' || cleanup.round || '.C'
            AND cleanup.outcome = 'in_flight'
            AND ((cleanup.object = 'primary' AND
                  json_extract(new_flow.value, '$.step') IN
                    ('C.primary.request', 'C.primary.redirect',
                     'C.primary.login', 'C.primary.retry')) OR
                 (cleanup.object = 'control' AND
                  json_extract(new_flow.value, '$.step') IN
                    ('C.control.request', 'C.control.redirect',
                     'C.control.login', 'C.control.retry')))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'cleanup flow crossed no in-flight boundary');
END;

CREATE TRIGGER run_steps_cleanup_flow_update
BEFORE UPDATE OF flow_refs ON run_steps
WHEN json_array_length(NEW.flow_refs) > json_array_length(OLD.flow_refs) AND EXISTS (
    SELECT 1 FROM json_each(NEW.flow_refs) AS new_flow
    WHERE CAST(new_flow.key AS INTEGER) >= json_array_length(OLD.flow_refs)
      AND json_extract(new_flow.value, '$.step') IN
              ('C.primary.request', 'C.primary.redirect',
               'C.primary.login', 'C.primary.retry',
               'C.control.request', 'C.control.redirect',
               'C.control.login', 'C.control.retry')
      AND NOT EXISTS (
          SELECT 1 FROM run_cleanup AS cleanup
          WHERE cleanup.run_id = NEW.run_id
            AND cleanup.cleanup_step = NEW.number
            AND NEW.step = 'round.' || cleanup.round || '.C'
            AND ((cleanup.object = 'primary' AND
                  json_extract(new_flow.value, '$.step') IN
                    ('C.primary.request', 'C.primary.redirect',
                     'C.primary.login', 'C.primary.retry')) OR
                 (cleanup.object = 'control' AND
                  json_extract(new_flow.value, '$.step') IN
                    ('C.control.request', 'C.control.redirect',
                     'C.control.login', 'C.control.retry')))
            AND ((cleanup.outcome = 'in_flight' AND
                  (json_type(new_flow.value, '$.flow_id') = 'null' OR
                   cleanup.flow_id_floor IS NULL OR
                   length(new_flow.value -> '$.flow_id') > length(cleanup.flow_id_floor) OR
                   (length(new_flow.value -> '$.flow_id') = length(cleanup.flow_id_floor) AND
                    (new_flow.value -> '$.flow_id') > cleanup.flow_id_floor))) OR
                 (cleanup.outcome = 'unknown' AND cleanup.flow_refs = '[]' AND
                  cleanup.effects IN ('unknown', 'observed') AND
                  OLD.effects = 'unknown' AND NEW.effects = 'observed' AND
                  json_array_length(NEW.flow_refs) = json_array_length(OLD.flow_refs) + 1 AND
                  json_type(new_flow.value, '$.original') = 'null' AND
                  json_type(new_flow.value, '$.flow_id') = 'integer' AND
                  (cleanup.flow_id_floor IS NULL OR
                   length(new_flow.value -> '$.flow_id') > length(cleanup.flow_id_floor) OR
                   (length(new_flow.value -> '$.flow_id') = length(cleanup.flow_id_floor) AND
                    (new_flow.value -> '$.flow_id') > cleanup.flow_id_floor)) AND
                  cleanup.instrument_reference =
                      'flow:' || (new_flow.value -> '$.flow_id')))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'cleanup flow crossed no recoverable object boundary');
END;

-- Recovery is append-only: an interrupted row may gain exact evidence, but
-- direct SQL cannot erase or rewrite evidence that was already durable.
CREATE TRIGGER run_cleanup_monotonic
BEFORE UPDATE ON run_cleanup
WHEN OLD.run_id IS NOT NEW.run_id
  OR OLD.round IS NOT NEW.round
  OR OLD.object IS NOT NEW.object
  OR OLD.plant_step != NEW.plant_step
  OR OLD.plant_request_digest != NEW.plant_request_digest
  OR NOT (OLD.object_id IS NULL OR OLD.object_id IS NEW.object_id)
  OR NOT (OLD.ownership = NEW.ownership OR
          (OLD.ownership IN ('pending', 'unknown') AND
           NEW.ownership IN ('established', 'not_created', 'unknown')))
  OR NOT (OLD.cleanup_step IS NULL OR OLD.cleanup_step IS NEW.cleanup_step)
  OR NOT (OLD.cleanup_request_digest IS NULL OR
          OLD.cleanup_request_digest IS NEW.cleanup_request_digest)
  OR NOT (OLD.flow_id_floor IS NULL OR OLD.flow_id_floor IS NEW.flow_id_floor)
  OR NOT (OLD.instrument_reference IS NULL OR
          OLD.instrument_reference IS NEW.instrument_reference)
  OR NOT COALESCE((OLD.effects IS NEW.effects OR
                   (OLD.outcome = 'in_flight' AND OLD.effects IS NULL) OR
                   (OLD.effects = 'unknown' AND NEW.effects = 'observed')), 0)
  OR NOT (OLD.response_status IS NULL OR OLD.response_status IS NEW.response_status)
  OR NOT (OLD.flow_refs = '[]' OR OLD.flow_refs IS NEW.flow_refs OR
          (json_array_length(OLD.flow_refs) = json_array_length(NEW.flow_refs) AND
           NOT EXISTS (
               SELECT 1
               FROM json_each(OLD.flow_refs) AS old_flow
               JOIN json_each(NEW.flow_refs) AS new_flow ON new_flow.key = old_flow.key
               WHERE json_extract(old_flow.value, '$.step')
                         IS NOT json_extract(new_flow.value, '$.step')
                  OR json_extract(old_flow.value, '$.flow_id')
                         IS NOT json_extract(new_flow.value, '$.flow_id')
                  OR json_extract(old_flow.value, '$.completeness')
                         IS NOT json_extract(new_flow.value, '$.completeness')
                  OR json_extract(old_flow.value, '$.decoder')
                         IS NOT json_extract(new_flow.value, '$.decoder')
                  OR NOT (
                      json_extract(old_flow.value, '$.original')
                          IS json_extract(new_flow.value, '$.original')
                      OR (json_type(old_flow.value, '$.original') = 'null' AND
                          json_type(new_flow.value, '$.original') = 'object' AND
                          json_type(new_flow.value, '$.original.artifact_id') = 'text' AND
                          json_type(new_flow.value, '$.original.digest') = 'text' AND
                          (SELECT count(*) FROM json_each(
                              json_extract(new_flow.value, '$.original'))) = 2)
                  )
                  OR (SELECT count(*) FROM json_each(new_flow.value)) != 5
           )))
  OR NOT (OLD.outcome = NEW.outcome OR
          (OLD.outcome = 'owed' AND NEW.outcome IN ('in_flight', 'not_required')) OR
          (OLD.outcome = 'in_flight' AND NEW.outcome IN ('complete', 'failed', 'unknown')) OR
          (OLD.outcome IN ('failed', 'unknown') AND NEW.outcome = 'complete'))
BEGIN
    SELECT RAISE(ABORT, 'run_cleanup evidence is not monotonic');
END;

-- put_cleanup uses a validated UPDATE for an existing object. Refuse a
-- duplicate INSERT so INSERT OR REPLACE cannot delete and recreate its
-- authority ledger, and never allow raw deletion of an outstanding result.
CREATE TRIGGER run_cleanup_no_replace
BEFORE INSERT ON run_cleanup
WHEN EXISTS (
    SELECT 1 FROM run_cleanup AS stored
    WHERE stored.run_id = NEW.run_id
      AND stored.round = NEW.round
      AND stored.object = NEW.object
)
BEGIN
    SELECT RAISE(ABORT, 'run_cleanup replacement is forbidden');
END;

CREATE TRIGGER run_cleanup_no_delete
BEFORE DELETE ON run_cleanup
BEGIN
    SELECT RAISE(ABORT, 'run_cleanup deletion is forbidden');
END;

-- Every cleanup flow is a typed projection of the already-durable C RunStep.
-- This trigger is deliberately stricter than the terminal-outcome checks:
-- malformed or sibling evidence may not hide earlier in the flow array.
CREATE TRIGGER run_cleanup_flow_binding_insert
BEFORE INSERT ON run_cleanup
WHEN scourge_flow_refs_valid(NEW.flow_refs) != 1 OR EXISTS (
    SELECT 1 FROM json_each(NEW.flow_refs) AS cleanup_flow
    WHERE json_type(cleanup_flow.value) IS NOT 'object'
       OR (SELECT count(*) FROM json_each(cleanup_flow.value)) != 5
       OR json_type(cleanup_flow.value, '$.step') IS NOT 'text'
       OR json_extract(cleanup_flow.value, '$.step') NOT IN
            ('C.primary.request', 'C.primary.redirect', 'C.primary.login', 'C.primary.retry',
             'C.control.request', 'C.control.redirect', 'C.control.login', 'C.control.retry')
       OR (NEW.object = 'primary' AND
           json_extract(cleanup_flow.value, '$.step') NOT IN
             ('C.primary.request', 'C.primary.redirect', 'C.primary.login', 'C.primary.retry'))
       OR (NEW.object = 'control' AND
           json_extract(cleanup_flow.value, '$.step') NOT IN
             ('C.control.request', 'C.control.redirect', 'C.control.login', 'C.control.retry'))
       OR (json_type(cleanup_flow.value, '$.flow_id') IS NOT 'null' AND
           json_type(cleanup_flow.value, '$.flow_id') IS NOT 'integer')
       OR (json_type(cleanup_flow.value, '$.flow_id') = 'integer' AND
           json_extract(cleanup_flow.value, '$.flow_id') < 0)
       OR json_type(cleanup_flow.value, '$.completeness') IS NOT 'text'
       OR json_extract(cleanup_flow.value, '$.completeness') NOT IN
            ('missing', 'partial', 'complete')
       OR (json_type(cleanup_flow.value, '$.decoder') IS NOT 'null' AND
           json_type(cleanup_flow.value, '$.decoder') IS NOT 'object')
       OR (json_type(cleanup_flow.value, '$.original') IS NOT 'null' AND
           json_type(cleanup_flow.value, '$.original') IS NOT 'object')
       OR (json_type(cleanup_flow.value, '$.original') = 'object' AND
           ((SELECT count(*) FROM json_each(json_extract(cleanup_flow.value, '$.original'))) != 2 OR
            json_type(cleanup_flow.value, '$.original.artifact_id') IS NOT 'text' OR
            length(json_extract(cleanup_flow.value, '$.original.artifact_id')) = 0 OR
            instr(json_extract(cleanup_flow.value, '$.original.artifact_id'), char(0)) != 0 OR
            json_type(cleanup_flow.value, '$.original.digest') IS NOT 'text' OR
            length(json_extract(cleanup_flow.value, '$.original.digest')) != 64 OR
            json_extract(cleanup_flow.value, '$.original.digest') GLOB '*[^0-9a-f]*'))
       OR NOT EXISTS (
           SELECT 1
           FROM run_steps AS step_row, json_each(step_row.flow_refs) AS step_flow
           WHERE step_row.run_id = NEW.run_id
             AND step_row.number = NEW.cleanup_step
             AND step_row.step = 'round.' || NEW.round || '.C'
             AND (SELECT count(*)
                  FROM json_each(step_row.flow_refs) AS prior_flow
                  WHERE CAST(prior_flow.key AS INTEGER) < CAST(step_flow.key AS INTEGER)
                    AND ((NEW.object = 'primary' AND
                          json_extract(prior_flow.value, '$.step') IN
                            ('C.primary.request', 'C.primary.redirect',
                             'C.primary.login', 'C.primary.retry')) OR
                         (NEW.object = 'control' AND
                          json_extract(prior_flow.value, '$.step') IN
                            ('C.control.request', 'C.control.redirect',
                             'C.control.login', 'C.control.retry'))))
                   = CAST(cleanup_flow.key AS INTEGER)
             AND json_extract(step_flow.value, '$.step')
                    IS json_extract(cleanup_flow.value, '$.step')
             AND (step_flow.value -> '$.flow_id')
                    IS (cleanup_flow.value -> '$.flow_id')
             AND json_extract(step_flow.value, '$.completeness')
                    IS json_extract(cleanup_flow.value, '$.completeness')
             AND json_extract(step_flow.value, '$.decoder')
                    IS json_extract(cleanup_flow.value, '$.decoder')
             AND ((json_type(step_flow.value, '$.original') = 'null' AND
                   json_type(cleanup_flow.value, '$.original') = 'null') OR
                  (json_type(step_flow.value, '$.original') = 'object' AND
                   json_type(cleanup_flow.value, '$.original') = 'object' AND
                   json_extract(step_flow.value, '$.original.artifact_id')
                     IS json_extract(cleanup_flow.value, '$.original.artifact_id') AND
                   json_extract(step_flow.value, '$.original.digest')
                     IS json_extract(cleanup_flow.value, '$.original.digest')))
       )
) OR (NEW.cleanup_step IS NOT NULL AND EXISTS (
    SELECT 1 FROM run_steps AS step_row
    WHERE step_row.run_id = NEW.run_id
      AND step_row.number = NEW.cleanup_step
      AND step_row.step IS NOT ('round.' || NEW.round || '.C')
)) OR (NEW.cleanup_step IS NOT NULL AND EXISTS (
    SELECT 1 FROM run_steps AS step_row
    WHERE step_row.run_id = NEW.run_id
      AND step_row.number = NEW.cleanup_step
      AND step_row.step = 'round.' || NEW.round || '.C'
) AND json_array_length(NEW.flow_refs) != (
    SELECT count(*)
    FROM run_steps AS step_row, json_each(step_row.flow_refs) AS step_flow
    WHERE step_row.run_id = NEW.run_id
      AND step_row.number = NEW.cleanup_step
      AND step_row.step = 'round.' || NEW.round || '.C'
      AND ((NEW.object = 'primary' AND
            json_extract(step_flow.value, '$.step') IN
              ('C.primary.request', 'C.primary.redirect',
               'C.primary.login', 'C.primary.retry')) OR
           (NEW.object = 'control' AND
            json_extract(step_flow.value, '$.step') IN
              ('C.control.request', 'C.control.redirect',
               'C.control.login', 'C.control.retry')))
))
BEGIN
    SELECT RAISE(ABORT, 'run_cleanup flow is not bound to its cleanup step');
END;

CREATE TRIGGER run_cleanup_flow_binding_update
BEFORE UPDATE ON run_cleanup
WHEN scourge_flow_refs_valid(NEW.flow_refs) != 1 OR EXISTS (
    SELECT 1 FROM json_each(NEW.flow_refs) AS cleanup_flow
    WHERE json_type(cleanup_flow.value) IS NOT 'object'
       OR (SELECT count(*) FROM json_each(cleanup_flow.value)) != 5
       OR json_type(cleanup_flow.value, '$.step') IS NOT 'text'
       OR json_extract(cleanup_flow.value, '$.step') NOT IN
            ('C.primary.request', 'C.primary.redirect', 'C.primary.login', 'C.primary.retry',
             'C.control.request', 'C.control.redirect', 'C.control.login', 'C.control.retry')
       OR (NEW.object = 'primary' AND
           json_extract(cleanup_flow.value, '$.step') NOT IN
             ('C.primary.request', 'C.primary.redirect', 'C.primary.login', 'C.primary.retry'))
       OR (NEW.object = 'control' AND
           json_extract(cleanup_flow.value, '$.step') NOT IN
             ('C.control.request', 'C.control.redirect', 'C.control.login', 'C.control.retry'))
       OR (json_type(cleanup_flow.value, '$.flow_id') IS NOT 'null' AND
           json_type(cleanup_flow.value, '$.flow_id') IS NOT 'integer')
       OR (json_type(cleanup_flow.value, '$.flow_id') = 'integer' AND
           json_extract(cleanup_flow.value, '$.flow_id') < 0)
       OR json_type(cleanup_flow.value, '$.completeness') IS NOT 'text'
       OR json_extract(cleanup_flow.value, '$.completeness') NOT IN
            ('missing', 'partial', 'complete')
       OR (json_type(cleanup_flow.value, '$.decoder') IS NOT 'null' AND
           json_type(cleanup_flow.value, '$.decoder') IS NOT 'object')
       OR (json_type(cleanup_flow.value, '$.original') IS NOT 'null' AND
           json_type(cleanup_flow.value, '$.original') IS NOT 'object')
       OR (json_type(cleanup_flow.value, '$.original') = 'object' AND
           ((SELECT count(*) FROM json_each(json_extract(cleanup_flow.value, '$.original'))) != 2 OR
            json_type(cleanup_flow.value, '$.original.artifact_id') IS NOT 'text' OR
            length(json_extract(cleanup_flow.value, '$.original.artifact_id')) = 0 OR
            instr(json_extract(cleanup_flow.value, '$.original.artifact_id'), char(0)) != 0 OR
            json_type(cleanup_flow.value, '$.original.digest') IS NOT 'text' OR
            length(json_extract(cleanup_flow.value, '$.original.digest')) != 64 OR
            json_extract(cleanup_flow.value, '$.original.digest') GLOB '*[^0-9a-f]*'))
       OR NOT EXISTS (
           SELECT 1
           FROM run_steps AS step_row, json_each(step_row.flow_refs) AS step_flow
           WHERE step_row.run_id = NEW.run_id
             AND step_row.number = NEW.cleanup_step
             AND step_row.step = 'round.' || NEW.round || '.C'
             AND (SELECT count(*)
                  FROM json_each(step_row.flow_refs) AS prior_flow
                  WHERE CAST(prior_flow.key AS INTEGER) < CAST(step_flow.key AS INTEGER)
                    AND ((NEW.object = 'primary' AND
                          json_extract(prior_flow.value, '$.step') IN
                            ('C.primary.request', 'C.primary.redirect',
                             'C.primary.login', 'C.primary.retry')) OR
                         (NEW.object = 'control' AND
                          json_extract(prior_flow.value, '$.step') IN
                            ('C.control.request', 'C.control.redirect',
                             'C.control.login', 'C.control.retry'))))
                   = CAST(cleanup_flow.key AS INTEGER)
             AND json_extract(step_flow.value, '$.step')
                    IS json_extract(cleanup_flow.value, '$.step')
             AND (step_flow.value -> '$.flow_id')
                    IS (cleanup_flow.value -> '$.flow_id')
             AND json_extract(step_flow.value, '$.completeness')
                    IS json_extract(cleanup_flow.value, '$.completeness')
             AND json_extract(step_flow.value, '$.decoder')
                    IS json_extract(cleanup_flow.value, '$.decoder')
             AND ((json_type(step_flow.value, '$.original') = 'null' AND
                   json_type(cleanup_flow.value, '$.original') = 'null') OR
                  (json_type(step_flow.value, '$.original') = 'object' AND
                   json_type(cleanup_flow.value, '$.original') = 'object' AND
                   json_extract(step_flow.value, '$.original.artifact_id')
                     IS json_extract(cleanup_flow.value, '$.original.artifact_id') AND
                   json_extract(step_flow.value, '$.original.digest')
                     IS json_extract(cleanup_flow.value, '$.original.digest')))
       )
) OR (NEW.cleanup_step IS NOT NULL AND EXISTS (
    SELECT 1 FROM run_steps AS step_row
    WHERE step_row.run_id = NEW.run_id
      AND step_row.number = NEW.cleanup_step
      AND step_row.step IS NOT ('round.' || NEW.round || '.C')
)) OR (NEW.cleanup_step IS NOT NULL AND EXISTS (
    SELECT 1 FROM run_steps AS step_row
    WHERE step_row.run_id = NEW.run_id
      AND step_row.number = NEW.cleanup_step
      AND step_row.step = 'round.' || NEW.round || '.C'
) AND json_array_length(NEW.flow_refs) != (
    SELECT count(*)
    FROM run_steps AS step_row, json_each(step_row.flow_refs) AS step_flow
    WHERE step_row.run_id = NEW.run_id
      AND step_row.number = NEW.cleanup_step
      AND step_row.step = 'round.' || NEW.round || '.C'
      AND ((NEW.object = 'primary' AND
            json_extract(step_flow.value, '$.step') IN
              ('C.primary.request', 'C.primary.redirect',
               'C.primary.login', 'C.primary.retry')) OR
           (NEW.object = 'control' AND
            json_extract(step_flow.value, '$.step') IN
              ('C.control.request', 'C.control.redirect',
               'C.control.login', 'C.control.retry')))
))
BEGIN
    SELECT RAISE(ABORT, 'run_cleanup flow is not bound to its cleanup step');
END;
