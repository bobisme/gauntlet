use super::{
    Artifact, BUSY_TIMEOUT, CleanupObjectRole, Flow, RUN_RECONCILE, RequestScope, Result,
    RoundFlow, RunAcceptance, RunCleanup, RunId, RunStep, Store, StoreError, Transaction,
    TransactionBehavior, acceptance, commit, conflicts_resolved, insert_run, json, json_value,
    linked_experiment, load_run, one, original_enrichment, params, put_step,
    require_unbound_import_key, stored_request, stored_step, tag, validate_run_update,
};
use crate::{
    domain::CleanupObjectOutcome,
    evidence::{CaptureHandle, Evidence},
    ids::{RequestKey, WireText},
    rounds::flow_original_key,
    teapot::decode_retained_flow,
    wire::{Effect, RunFlag, RunState},
};
use rusqlite::OptionalExtension;
use std::{collections::BTreeSet, time::Instant};

/// Result of reconciling one service-issued recovery identity. `committed`
/// describes the local recovery metadata write; the acceptance itself was
/// necessarily durable before this operation could resolve it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReconciliation {
    pub acceptance: RunAcceptance,
    pub capture_handle: Option<CaptureHandle>,
    pub effects: Effect,
    pub committed: bool,
    pub revision: u64,
}

impl Store {
    #[cfg(test)]
    pub(crate) fn classify_production_recovery_fixture(
        &self,
        run: &mut crate::domain::Run,
    ) -> Result<Effect> {
        project_recovery_steps(&self.db, run)?;
        Ok(recovery_effect(run))
    }

    /// Retain the Investigation handle issued for the exact accepted run.
    /// Execution calls this immediately after capture creation and before the
    /// first target adapter call.
    pub(super) fn record_capture_handle(
        &mut self,
        run: &RunId,
        handle: &CaptureHandle,
    ) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let accepted = exact_recovery_acceptance(&tx, None, run)?;
        if accepted.capture_handle.as_ref() == Some(handle) && accepted.trusted_evidence {
            return Ok(accepted.acceptance.receipt);
        }
        if accepted.capture_handle.is_some() {
            return Err(StoreError::Conflict);
        }
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM run_recovery WHERE capture_handle=?1 AND run_id<>?2)",
            params![handle.as_str(), run.as_str()],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(StoreError::Conflict);
        }
        one(tx.execute(
            "UPDATE run_recovery SET capture_handle=?1, trusted_evidence=1
             WHERE run_id=?2 AND request_key=?3 AND capture_handle IS NULL",
            params![
                handle.as_str(),
                run.as_str(),
                accepted.acceptance.run.request_key.as_str()
            ],
        )?)?;
        commit(tx, "run.capture", run.as_str())
    }

    /// Reconcile one accepted run strictly from its already-durable instrument
    /// record. This method has no adapter or Evidence handle and therefore
    /// cannot resend, retry, mint a run, or infer an outcome from absence.
    pub fn reconcile_run(
        &mut self,
        scope: &RequestScope,
        run: &RunId,
    ) -> Result<RunReconciliation> {
        // A live execution writer holds this lease across every adapter call.
        // Recovery never waits and guesses: a live owner is a typed conflict,
        // while process death releases the kernel lease before this proceeds.
        let until = Instant::now() + BUSY_TIMEOUT;
        let locks = self.execution_locks()?;
        let _lease = loop {
            match locks.acquire_recovery(run) {
                Ok(lease) => break lease,
                Err(crate::preflight::LockError::Busy) if Instant::now() < until => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(crate::preflight::LockError::Busy) => return Err(StoreError::Conflict),
                Err(crate::preflight::LockError::Unsafe) => {
                    return Err(StoreError::ConnectionSettings);
                }
            }
        };
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut exact = exact_recovery_acceptance(&tx, Some(scope), run)?;
        let mut update = exact.acceptance.run.clone();
        let already_reconciled = super::reconciled_run(&tx, run)?;
        let steps_changed = if exact.trusted_evidence {
            project_recovery_steps(&tx, &mut update)?
        } else {
            false
        };
        let effects = if exact.trusted_evidence {
            recovery_effect(&update)
        } else {
            // Pre-v15 rows share the historical writer lane with a former
            // public API. Their step claims are retained for audit only.
            Effect::Unknown
        };

        // A bare untrusted declaration has no authenticated refusal or exact
        // send record and stays untouched. Once the exact production capture
        // is durable, even a capture-to-first-intent crash must transfer
        // ownership monotonically to recovery: finalize it unknown and record
        // run.reconcile so no later preparation or writer can resume it.
        let mut changed = steps_changed;
        let trusted_empty_fence =
            exact.trusted_evidence && update.steps.is_empty() && !already_reconciled;
        if trusted_empty_fence
            || !update.steps.is_empty()
                && (update.state != RunState::Finalized || update.effects != effects)
        {
            update.state = RunState::Finalized;
            update.effects = effects;
            if !update.flags.contains(&RunFlag::ReconciliationRequired) {
                update.flags.push(RunFlag::ReconciliationRequired);
            }
            changed = true;
        }

        let revision = if changed {
            if steps_changed {
                for step in &update.steps {
                    put_step(&tx, run, step)?;
                }
            }
            let valid = if trusted_empty_fence {
                validate_trusted_empty_recovery_update(&tx, &update)?
            } else if exact.trusted_evidence {
                validate_run_update(&tx, &update)?
            } else {
                validate_untrusted_recovery_update(&tx, &update)?
            };
            if !valid {
                return Err(StoreError::Conflict);
            }
            insert_run(&tx, &update)?;
            if effects != Effect::Unknown && conflicts_resolved(&tx, run)? {
                super::release_conflict_rows(&tx, run)?;
            }
            commit(tx, RUN_RECONCILE, run.as_str())?
        } else {
            super::run_metadata_revision(&tx, run)?
                .map(|(revision, _)| revision)
                .ok_or(StoreError::Integrity)?
        };
        exact.acceptance.run = update;
        Ok(RunReconciliation {
            acceptance: exact.acceptance,
            capture_handle: exact.capture_handle,
            effects,
            committed: changed,
            revision,
        })
    }

    /// Attach a missing original from this run's finalized Investigation
    /// capture to an existing step flow and its existing cleanup projection.
    /// This recovery has no authority to initiate work or change outcomes.
    pub fn recover_flow_original(
        &mut self,
        evidence: &Evidence,
        handle: &CaptureHandle,
        run: &RunId,
        step_number: u64,
        flow_id: u64,
    ) -> Result<()> {
        let step = stored_step(&self.db, run, step_number)?.ok_or(StoreError::SelectorNotFound)?;
        let flow = recorded_flow(&step, flow_id)?;
        let (key, cleanup) = original_identity(&step, flow, flow_id)?;
        let experiment = linked_experiment(&self.db, &load_run(&self.db, run)?)?;
        if evidence
            .describe(&experiment.artifact_id)
            .map_err(|_| StoreError::Integrity)?
            .reference
            != experiment
        {
            return Err(StoreError::Integrity);
        }
        let state = evidence
            .recover_for_run(handle, run)
            .map_err(|_| StoreError::Integrity)?;
        let finalized = state.finalized.ok_or(StoreError::Conflict)?;
        let mut originals = finalized
            .original_artifacts
            .into_iter()
            .filter(|original| original.attachment.key == key);
        let original = originals.next().ok_or(StoreError::SelectorNotFound)?;
        if originals.next().is_some() {
            return Err(StoreError::Integrity);
        }
        let read = evidence
            .read(&original.artifact.artifact_id)
            .map_err(|_| StoreError::Integrity)?;
        if read.artifact.reference != original.artifact
            || read.artifact.size_bytes != original.attachment.size_bytes
            || original.artifact.digest != original.attachment.digest
            || decode_retained_flow(&read.bytes, flow_id)
                .map_err(|_| StoreError::Integrity)?
                .retained_response()
                .completeness
                != flow.completeness
        {
            return Err(StoreError::Integrity);
        }
        self.attach_verified_original(run, &step, flow_id, cleanup, &original.artifact)
    }

    fn attach_verified_original(
        &mut self,
        run: &RunId,
        observed: &RunStep,
        flow_id: u64,
        cleanup: Option<(u64, CleanupObjectRole)>,
        artifact: &Artifact,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_unbound_import_key(&tx, run)?;
        let stored = stored_step(&tx, run, observed.number)?.ok_or(StoreError::SelectorNotFound)?;
        let mut expected = observed.clone();
        expected.flows.clone_from(&stored.flows);
        if expected != stored || !original_enrichment(&observed.flows, &stored.flows) {
            return Err(StoreError::Conflict);
        }
        let flow = recorded_flow(&stored, flow_id)?;
        if original_identity(&stored, flow, flow_id)?.1 != cleanup {
            return Err(StoreError::Conflict);
        }

        let mut linked = stored.clone();
        attach_original(&mut linked.flows, flow, artifact)?;
        if linked != stored {
            one(tx.execute(
                "UPDATE run_steps SET flow_refs=?1 WHERE run_id=?2 AND number=?3 AND flow_refs=?4",
                params![
                    json(&linked.flows)?,
                    run.as_str(),
                    stored.number.to_string(),
                    json(&stored.flows)?
                ],
            )?)?;
        }
        let cleanup_updated = if let Some((round, object)) = cleanup {
            recover_cleanup_original(&tx, run, &stored, flow, artifact, round, object)?
        } else {
            false
        };
        if linked == stored && !cleanup_updated {
            return Ok(());
        }
        commit(tx, "run.original.recover", run.as_str())?;
        Ok(())
    }
}

fn validate_untrusted_recovery_update(
    db: &rusqlite::Connection,
    update: &crate::domain::Run,
) -> Result<bool> {
    let mut expected = load_run(db, &update.id)?;
    expected.state = RunState::Finalized;
    expected.effects = Effect::Unknown;
    if !expected.flags.contains(&RunFlag::ReconciliationRequired) {
        expected.flags.push(RunFlag::ReconciliationRequired);
    }
    Ok(&expected == update)
}

fn validate_trusted_empty_recovery_update(
    db: &rusqlite::Connection,
    update: &crate::domain::Run,
) -> Result<bool> {
    let mut expected = load_run(db, &update.id)?;
    if !expected.steps.is_empty() {
        return Ok(false);
    }
    expected.state = RunState::Finalized;
    expected.effects = Effect::Unknown;
    if !expected.flags.contains(&RunFlag::ReconciliationRequired) {
        expected.flags.push(RunFlag::ReconciliationRequired);
    }
    Ok(&expected == update)
}

struct ExactRecovery {
    acceptance: RunAcceptance,
    capture_handle: Option<CaptureHandle>,
    trusted_evidence: bool,
}

/// Rebuild the exact request acceptance and its recovery context in the
/// caller's transaction. The canonical request bytes, digest, key, run and
/// optional workspace scope must all agree before any outcome is considered.
fn exact_recovery_acceptance(
    db: &rusqlite::Connection,
    scope: Option<&RequestScope>,
    run: &RunId,
) -> Result<ExactRecovery> {
    type ContextRow = (String, String, Option<String>, bool, String, String);
    let row: ContextRow = db
        .query_row(
            "SELECT rr.request_key, rr.input_digest, rr.capture_handle, rr.trusted_evidence,
                    q.engagement_id, q.binding
             FROM run_recovery rr
             JOIN request_keys q ON q.key=rr.request_key AND q.run_id=rr.run_id
             JOIN runs r ON r.id=rr.run_id AND r.request_key=rr.request_key
             WHERE rr.run_id=?1
               AND NOT EXISTS (
                   SELECT 1 FROM request_keys other
                   WHERE other.run_id=rr.run_id AND other.key<>rr.request_key
               )",
            [run.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::SelectorNotFound)?;
    if scope
        .is_some_and(|scope| row.4 != scope.engagement.as_str() || row.5 != scope.binding.as_str())
    {
        return Err(StoreError::SelectorNotFound);
    }
    let key = RequestKey::try_from(row.0).map_err(|_| StoreError::Integrity)?;
    let stored = stored_request(db, &key)?.ok_or(StoreError::Integrity)?;
    let input = stored.verify()?;
    let canonical = input.to_bytes().map_err(|_| StoreError::Integrity)?;
    if crate::canonical::Sha256Digest::of(&canonical).as_str() != row.1
        || !stored.in_scope(&RequestScope::new(
            row.4.parse().map_err(|_| StoreError::Integrity)?,
            row.5.parse().map_err(|_| StoreError::Integrity)?,
        ))
    {
        return Err(StoreError::Integrity);
    }
    let acceptance = acceptance(db, &key, &stored)?;
    if acceptance.run.id != *run || acceptance.run.request_key != key {
        return Err(StoreError::Conflict);
    }
    let capture_handle = row
        .2
        .map(|handle| handle.parse().map_err(|_| StoreError::Integrity))
        .transpose()?;
    Ok(ExactRecovery {
        acceptance,
        capture_handle,
        trusted_evidence: row.3,
    })
}

/// Establish the aggregate only from exact per-step durable records. A digest
/// match is deliberately irrelevant. A flow claimed by another run in the
/// workspace store is conflicting evidence, not a basis for attribution.
fn recovery_effect(run: &crate::domain::Run) -> Effect {
    if run.steps.is_empty() {
        return Effect::Unknown;
    }
    let mut aggregate = Effect::None;
    for step in &run.steps {
        if step.instrument_reference.as_ref().map(WireText::as_str) == Some("sent:no-flow")
            || step.flows.iter().any(|flow| flow.flow_id.is_none())
        {
            return Effect::Unknown;
        }
        match step.effects {
            None | Some(Effect::Unknown) => aggregate = Effect::Unknown,
            Some(Effect::None) => {}
            Some(Effect::Observed) => {
                if aggregate != Effect::Unknown {
                    aggregate = Effect::Observed;
                }
            }
        }
    }
    aggregate
}

/// Validate and monotonically project exact service outcomes already bound to
/// this run and step. `flow:N` establishes a send, `not-sent` establishes a
/// refusal before dispatch, and `sent:no-flow` establishes neither effect nor
/// absence. Matching bytes or digests never enter this decision.
fn project_recovery_steps(db: &rusqlite::Connection, run: &mut crate::domain::Run) -> Result<bool> {
    let mut changed = false;
    let mut claimed_ids = BTreeSet::new();
    for step in &mut run.steps {
        let mut step_flow_ids = BTreeSet::new();
        let reference = step.instrument_reference.as_ref().map(WireText::as_str);
        let reference_flow = match reference {
            Some(reference) if reference.starts_with("flow:") => Some(
                reference
                    .strip_prefix("flow:")
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|id| *id > 0)
                    .ok_or(StoreError::Conflict)?,
            ),
            Some("not-sent" | "sent:no-flow") | None => None,
            Some(_) => return Err(StoreError::Conflict),
        };
        if let Some(id) = reference_flow
            && (step.flow_id_floor.is_some_and(|floor| id <= floor) || !claimed_ids.insert(id))
        {
            return Err(StoreError::Conflict);
        }
        let mut has_missing = false;
        for flow in &step.flows {
            let Some(id) = flow.flow_id else {
                if flow.completeness != crate::wire::Completeness::Missing
                    || flow.original.is_some()
                    || flow.decoder.is_some()
                {
                    return Err(StoreError::Conflict);
                }
                has_missing = true;
                continue;
            };
            if id == 0
                || step.flow_id_floor.is_some_and(|floor| id <= floor)
                || !step_flow_ids.insert(id)
                || (reference_flow != Some(id) && !claimed_ids.insert(id))
            {
                return Err(StoreError::Conflict);
            }
        }

        match step.effects {
            None => {
                if reference.is_some()
                    || !step.flows.is_empty()
                        && !authenticated_partial_cleanup_step(db, &run.id, step)?
                {
                    return Err(StoreError::Conflict);
                }
            }
            Some(Effect::Unknown) => {
                if has_missing || reference == Some("sent:no-flow") {
                    // A missing action is authenticated uncertainty even when
                    // another action in the same step retained a flow.
                } else if reference_flow.is_some() || !step.flows.is_empty() {
                    step.effects = Some(Effect::Observed);
                    changed = true;
                } else if reference == Some("not-sent") {
                    if !step.flows.is_empty() {
                        return Err(StoreError::Conflict);
                    }
                    step.effects = Some(Effect::None);
                    changed = true;
                } else if !matches!(reference, Some("sent:no-flow") | None) {
                    unreachable!("references were validated above");
                }
            }
            Some(Effect::None) => {
                if reference != Some("not-sent") || !step.flows.is_empty() || has_missing {
                    return Err(StoreError::Conflict);
                }
            }
            Some(Effect::Observed) => {
                if has_missing
                    || reference.is_none()
                    || (reference_flow.is_none() && step.flows.is_empty())
                    || reference == Some("sent:no-flow")
                {
                    return Err(StoreError::Conflict);
                }
            }
        }
    }

    if !claimed_ids.is_empty() {
        let mut rows = db.prepare("SELECT s.flow_refs FROM run_steps s WHERE s.run_id<>?1")?;
        let other = rows.query_map([run.id.as_str()], |row| row.get::<_, String>(0))?;
        for flows in other {
            for flow in json_value::<Vec<Flow>>(&flows?)? {
                if flow.flow_id.is_some_and(|id| claimed_ids.contains(&id)) {
                    return Err(StoreError::Conflict);
                }
            }
        }
        let mut references = db.prepare(
            "SELECT s.instrument_reference FROM run_steps s
             WHERE s.run_id<>?1 AND s.instrument_reference GLOB 'flow:*'",
        )?;
        for reference in references.query_map([run.id.as_str()], |row| row.get::<_, String>(0))? {
            if reference?
                .strip_prefix("flow:")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|id| claimed_ids.contains(&id))
            {
                return Err(StoreError::Conflict);
            }
        }
    }
    Ok(changed)
}

fn authenticated_partial_cleanup_step(
    db: &rusqlite::Connection,
    run: &RunId,
    step: &RunStep,
) -> Result<bool> {
    let Some(round) = super::frozen_cleanup_round(step) else {
        return Ok(false);
    };
    if step.instrument_reference.is_some() || step.effects.is_some() || step.flows.is_empty() {
        return Ok(false);
    }

    let mut retained = 0usize;
    for object in [CleanupObjectRole::Primary, CleanupObjectRole::Control] {
        let flows = step
            .flows
            .iter()
            .filter(|flow| super::cleanup_flow_role(flow) == Some(object))
            .cloned()
            .collect::<Vec<_>>();
        if flows.is_empty() {
            continue;
        }
        retained += flows.len();
        if flows
            .iter()
            .any(|flow| flow.original.is_some() || flow.decoder.is_some())
        {
            return Ok(false);
        }
        let Some(cleanup) = super::cleanup_object(db, run, round, object)? else {
            return Ok(false);
        };
        if cleanup.cleanup_step != Some(step.number)
            || cleanup.flow_id_floor != step.flow_id_floor
            || cleanup.effects.is_none()
        {
            return Ok(false);
        }
        if cleanup.flows.is_empty() {
            if cleanup.outcome != CleanupObjectOutcome::InFlight {
                return Ok(false);
            }
            let established = match cleanup.instrument_reference.as_ref().map(WireText::as_str) {
                Some("sent:no-flow") => flows.iter().any(|flow| flow.flow_id.is_none()),
                Some(reference) => reference
                    .strip_prefix("flow:")
                    .and_then(|id| id.parse::<u64>().ok())
                    .is_some_and(|id| flows.iter().any(|flow| flow.flow_id == Some(id))),
                None => false,
            };
            if !established {
                return Ok(false);
            }
        } else if cleanup.flows != flows {
            return Ok(false);
        }
    }
    Ok(retained == step.flows.len())
}

fn recorded_flow(step: &RunStep, id: u64) -> Result<&Flow> {
    if step.effects.is_none() || id == 0 || step.flow_id_floor.is_some_and(|floor| id <= floor) {
        return Err(StoreError::Conflict);
    }
    let mut matching = step.flows.iter().filter(|flow| flow.flow_id == Some(id));
    let flow = matching.next().ok_or(StoreError::SelectorNotFound)?;
    if matching.next().is_some() {
        return Err(StoreError::Integrity);
    }
    Ok(flow)
}

fn original_identity(
    step: &RunStep,
    flow: &Flow,
    id: u64,
) -> Result<(String, Option<(u64, CleanupObjectRole)>)> {
    let [prefix, round, name]: [&str; 3] = step
        .step
        .as_str()
        .split('.')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| StoreError::Conflict)?;
    let round_number = round.parse::<u64>().map_err(|_| StoreError::Conflict)?;
    if round != round_number.to_string() {
        return Err(StoreError::Conflict);
    }
    let round = round_number;
    let contract = RoundFlow::REQUIRED
        .iter()
        .copied()
        .find(|contract| contract.as_str() == name);
    if prefix != "round"
        || contract.and_then(|contract| contract.step_number(round)) != Some(step.number)
    {
        return Err(StoreError::Conflict);
    }
    let suffix = flow
        .step
        .as_str()
        .strip_prefix(name)
        .and_then(|part| part.strip_prefix('.'))
        .ok_or(StoreError::Conflict)?;
    let (role, cleanup) = if contract == Some(RoundFlow::C) {
        let (object, role) = suffix.split_once('.').ok_or(StoreError::Conflict)?;
        let object = match object {
            "primary" => CleanupObjectRole::Primary,
            "control" => CleanupObjectRole::Control,
            _ => return Err(StoreError::Conflict),
        };
        (role, Some((round, object)))
    } else {
        (suffix, None)
    };
    if !matches!(role, "request" | "redirect" | "login" | "retry") {
        return Err(StoreError::Conflict);
    }
    Ok((flow_original_key(round, step.number, role, id), cleanup))
}

fn recover_cleanup_original(
    tx: &Transaction<'_>,
    run: &RunId,
    step: &RunStep,
    flow: &Flow,
    artifact: &Artifact,
    round: u64,
    object: CleanupObjectRole,
) -> Result<bool> {
    let stored =
        super::cleanup_object(tx, run, round, object)?.ok_or(StoreError::SelectorNotFound)?;
    if !cleanup_matches_step(&stored, step) {
        return Err(StoreError::Conflict);
    }
    let mut linked = stored.flows.clone();
    attach_original(&mut linked, flow, artifact)?;
    if linked == stored.flows {
        return Ok(false);
    }
    one(tx.execute(
        "UPDATE run_cleanup SET flow_refs=?1 WHERE run_id=?2 AND round=?3 AND object=?4 AND flow_refs=?5",
        params![json(&linked)?, run.as_str(), round.to_string(), tag(object)?, json(&stored.flows)?],
    )?)?;
    Ok(true)
}

fn cleanup_matches_step(cleanup: &RunCleanup, step: &RunStep) -> bool {
    let prefix = match cleanup.object {
        CleanupObjectRole::Primary => "C.primary.",
        CleanupObjectRole::Control => "C.control.",
    };
    let step_flows = step
        .flows
        .iter()
        .filter(|flow| flow.step.as_str().starts_with(prefix))
        .cloned()
        .collect::<Vec<_>>();
    cleanup.cleanup_step == Some(step.number)
        && cleanup.cleanup_request_digest.as_ref() == Some(&step.request_digest)
        && cleanup.flow_id_floor == step.flow_id_floor
        && original_enrichment(&cleanup.flows, &step_flows)
}

fn attach_original(flows: &mut [Flow], flow: &Flow, artifact: &Artifact) -> Result<()> {
    let mut matching = flows.iter_mut().filter(|candidate| {
        candidate.step == flow.step
            && candidate.flow_id == flow.flow_id
            && candidate.completeness == flow.completeness
            && candidate.decoder == flow.decoder
    });
    let existing = matching.next().ok_or(StoreError::SelectorNotFound)?;
    if matching.next().is_some() {
        return Err(StoreError::Integrity);
    }
    match &existing.original {
        Some(original) if original != artifact => Err(StoreError::Conflict),
        Some(_) => Ok(()),
        None => {
            existing.original = Some(artifact.clone());
            Ok(())
        }
    }
}
