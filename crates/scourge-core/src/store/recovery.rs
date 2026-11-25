use super::{
    Artifact, CleanupObjectRole, Flow, Result, RoundFlow, RunCleanup, RunId, RunStep, Store,
    StoreError, Transaction, TransactionBehavior, commit, json, linked_experiment, load_run, one,
    original_enrichment, params, require_unbound_import_key, stored_step, tag,
};
use crate::{
    evidence::{CaptureHandle, Evidence},
    rounds::flow_original_key,
    teapot::decode_retained_flow,
};

impl Store {
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
