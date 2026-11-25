//! Trusted live verification orchestration.

use std::collections::BTreeSet;

use clap::Args;
use scourge_core::{
    domain::Run,
    engagement::PassState,
    evidence::CaptureHandle,
    ids::{EngagementId, LeadId},
    planning::verification_claim,
    preflight::{
        LiveServices, PreflightDeclaration, PreflightPass, RunLocks, declare, prepare_declared,
    },
    request::{self, DEFAULT_VERIFY_ROUNDS},
    response::Context,
    rounds::{ExecutionFailure, execute_live},
    store::{RunAcceptance, Store},
    teapot::Teapot,
    template::{SlotName, SlotValue, Templates},
    verification::{VerificationContext, VerificationRecordOptions, evaluate_and_publish},
    wire::{AbsolutePath, ActionEffect, CommitStatus, Effect, ErrorCode, ResponseV1, RunSummary},
    workspace::{BoundWorkspace, RuntimeAuthorityError, VerifierEvidenceError},
};
use serde_json::json;

use crate::lead;

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct VerifyArgs {
    #[arg(value_name = "LEAD")]
    pub lead: LeadId,
    /// Plan only. Sends no target traffic.
    #[arg(long)]
    pub plan: bool,
    /// Number of independently acquired true rounds.
    #[arg(long, default_value_t = DEFAULT_VERIFY_ROUNDS)]
    pub rounds: u64,
    /// Preview a lead-supplied slot as NAME=VALUE.
    #[arg(long = "slot", value_name = "NAME=VALUE", requires = "plan")]
    pub slots: Vec<String>,
}

pub fn execute(
    mut context: Context,
    workspace: &BoundWorkspace,
    engagement: EngagementId,
    declaration: &[u8],
    args: &VerifyArgs,
) -> ResponseV1 {
    context.engagement = Some(engagement.clone());
    if args.plan {
        let slots = match preview_slots(&args.slots) {
            Ok(value) => value,
            Err(code) => {
                return fail(
                    &context,
                    code,
                    CommitStatus::NotCommitted,
                    Effect::None,
                    "A preview slot is invalid or supplied twice.",
                );
            }
        };
        return lead::plan(
            context,
            workspace,
            engagement,
            declaration,
            &args.lead,
            args.rounds,
            &slots,
        );
    }
    if args.rounds == 0 {
        return fail(
            &context,
            ErrorCode::UsageError,
            CommitStatus::NotCommitted,
            Effect::None,
            "Verification requires at least one round.",
        );
    }

    // Resolve every selector and freeze the experiment before any adapter or
    // evidence handle is opened. Unsupported classes and slot conflicts leave
    // no admission receipt and cannot reach target traffic.
    let current = match lead::detail(workspace, &engagement, &args.lead) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                &context,
                error.error_code(),
                CommitStatus::NotCommitted,
                Effect::None,
                "The lead could not be resolved.",
            );
        }
    };
    let (manifest, claim) = match verification_claim(workspace, &engagement, &current.lead, &[]) {
        Ok(value) => value,
        Err(code) => {
            let mut response = fail(
                &context,
                code,
                CommitStatus::NotCommitted,
                Effect::None,
                if code == ErrorCode::OracleUnavailable {
                    "No compiled template matches this class; the observation remains a lead."
                } else {
                    "The verification claim could not be resolved."
                },
            );
            if code == ErrorCode::OracleUnavailable {
                response
                    .extensions
                    .insert("lead_remains_lead".into(), json!(true));
                response.extensions.insert(
                    "supported_classes".into(),
                    json!(
                        Templates::registry()
                            .iter()
                            .map(|template| template.claim_class())
                            .collect::<Vec<_>>()
                    ),
                );
            }
            return response;
        }
    };
    let resolution = match Templates::resolve(&claim, &manifest) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                &context,
                error.code(),
                CommitStatus::NotCommitted,
                Effect::None,
                "The verification claim is incomplete.",
            );
        }
    };
    let experiment = match resolution.ready() {
        Ok(value) => value,
        Err(_) => {
            return fail(
                &context,
                ErrorCode::SlotsIncomplete,
                CommitStatus::NotCommitted,
                Effect::None,
                "The verification claim is incomplete.",
            );
        }
    };
    let experiment_digest = match experiment.freeze() {
        Ok((_, digest)) => digest,
        Err(_) => {
            return fail(
                &context,
                ErrorCode::IntegrityFailure,
                CommitStatus::NotCommitted,
                Effect::None,
                "The frozen experiment could not be encoded.",
            );
        }
    };
    let input = match request::Invocation::new(
        "verify",
        json!({
            "lead_id": args.lead,
            "lead_revision": current.lead.revision,
            "engagement_revision": manifest.revision(),
            "rounds": args.rounds,
        }),
    )
    .normalize()
    {
        Ok(value) => value,
        Err(_) => {
            return fail(
                &context,
                ErrorCode::UsageError,
                CommitStatus::NotCommitted,
                Effect::None,
                "The verification request is invalid.",
            );
        }
    };
    let run = Run::declare(engagement.clone(), experiment_digest);
    let scope = match workspace.request_scope(&engagement) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                &context,
                error.code(),
                CommitStatus::NotCommitted,
                Effect::None,
                "The request scope is unavailable.",
            );
        }
    };
    let runtime = match workspace.resolve_verifier_runtime(engagement.as_str()) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                &context,
                match error {
                    RuntimeAuthorityError::Missing => ErrorCode::CapabilityUnavailable,
                    RuntimeAuthorityError::Conflict => ErrorCode::IntegrityFailure,
                },
                CommitStatus::NotCommitted,
                Effect::None,
                "Verifier runtime authority is unavailable or conflicts.",
            );
        }
    };
    let pass_file = match runtime
        .pass
        .path
        .to_str()
        .and_then(|value| value.parse::<AbsolutePath>().ok())
    {
        Some(value) => value,
        None => {
            return fail(
                &context,
                ErrorCode::IntegrityFailure,
                CommitStatus::NotCommitted,
                Effect::None,
                "The admitted pass path is invalid.",
            );
        }
    };
    let locks = match RunLocks::open(&runtime.investigation.scratch_root) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                &context,
                error.code(),
                CommitStatus::NotCommitted,
                Effect::None,
                "The verifier lock namespace is unavailable.",
            );
        }
    };
    let mut store = match workspace.open_coordination_writer() {
        Ok(value) => value,
        Err(error) => {
            return fail(
                &context,
                error.code(),
                CommitStatus::NotCommitted,
                Effect::None,
                "The coordination store is unavailable.",
            );
        }
    };
    let declaration = PreflightDeclaration {
        scope: &scope,
        input: &input,
        run: &run,
        claim: &claim,
        lead_revision: current.lead.revision,
        engagement: &manifest,
        manifest_artifact: &runtime.manifest.artifact.reference,
    };
    let declared = match declare(&mut store, declaration) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                &context,
                error.code(),
                CommitStatus::NotCommitted,
                Effect::None,
                "The verification request was refused before execution.",
            );
        }
    };
    let acceptance = declared.acceptance().clone();
    context.request_key = Some(acceptance.run.request_key.clone());

    // The same operator runtime, Teapot and qualified Evidence instances stay
    // bound through preparation, acquisition and publication.
    let qualified = match workspace.open_verifier_evidence(&engagement) {
        Ok(value) => value,
        Err(error) => {
            return committed_failure(
                &context,
                &store,
                &acceptance,
                match error {
                    VerifierEvidenceError::Authority(RuntimeAuthorityError::Missing) => {
                        ErrorCode::CapabilityUnavailable
                    }
                    VerifierEvidenceError::Authority(RuntimeAuthorityError::Conflict) => {
                        ErrorCode::IntegrityFailure
                    }
                    VerifierEvidenceError::Evidence(error) => error.code(),
                },
                Effect::None,
                "The qualified Evidence workspace is unavailable.",
                None,
            );
        }
    };
    let teapot = match Teapot::from_runtime(runtime) {
        Ok(value) => value,
        Err(error) => {
            return committed_failure(
                &context,
                &store,
                &acceptance,
                error.code(),
                Effect::None,
                "The admitted Teapot runtime is invalid.",
                None,
            );
        }
    };
    let services = match LiveServices::new(&teapot, qualified.evidence(), runtime) {
        Ok(value) => value,
        Err(error) => {
            return committed_failure(
                &context,
                &store,
                &acceptance,
                error.code(),
                Effect::None,
                "The verifier adapters do not match admitted authority.",
                None,
            );
        }
    };
    let prepared = match prepare_declared(&mut store, &locks, declared, || {
        Ok((
            &services,
            PreflightPass {
                pass_reference: &manifest.settings().pass_ref,
                pass_state: PassState::Active(manifest.pass_digest()),
                pass_file: &pass_file,
            },
        ))
    }) {
        Ok(value) => value,
        Err(error) => {
            return committed_failure(
                &context,
                &store,
                &acceptance,
                error.code(),
                Effect::None,
                "Verification preflight was refused.",
                None,
            );
        }
    };
    let execution = match execute_live(
        &mut store,
        prepared,
        &manifest,
        &teapot,
        qualified.evidence(),
        &runtime.origin,
    ) {
        Ok(value) => value,
        Err(error) => {
            return execution_failure(&context, &store, &acceptance, error);
        }
    };
    let (_, head) = match store.checkpoint(&engagement) {
        Ok(value) => value,
        Err(error) => {
            return committed_failure(
                &context,
                &store,
                &acceptance,
                error.error_code(),
                execution.settlement().1.known_effects(),
                "The publication checkpoint is unavailable.",
                None,
            );
        }
    };
    let context_record = match VerificationContext::from_execution(
        &execution,
        VerificationRecordOptions {
            sequence: head.sequence.saturating_add(1),
            prev_record_digest: head.record_digest,
            policy_rule: None,
            environment_kind: runtime.environment_kind,
        },
    ) {
        Ok(value) => value,
        Err(error) => {
            return committed_failure(
                &context,
                &store,
                &acceptance,
                error.code(),
                execution.settlement().1.known_effects(),
                "The sealed verification context is inconsistent.",
                None,
            );
        }
    };
    let published =
        match evaluate_and_publish(qualified.evidence(), &mut store, &execution, context_record) {
            Ok(value) => value,
            Err(error) => {
                return committed_failure(
                    &context,
                    &store,
                    &acceptance,
                    error.code(),
                    execution.settlement().1.known_effects(),
                    "The evaluator could not publish the verification record.",
                    None,
                );
            }
        };
    let record = &published.stored.record;
    let recovered = store
        .recover_run(&record.run_id)
        .unwrap_or_else(|_| acceptance.run.clone());
    let summary = Some(run_summary(&recovered));
    let disposition = published.stored.disposition;
    let badge = match crate::read::coherent_badge(workspace, &engagement, &args.lead) {
        Ok(value) => value,
        Err(code) => {
            let mut response = committed_failure(
                &context,
                &store,
                &acceptance,
                code,
                record.effects,
                "The verification was published but its coherent badge could not be read.",
                None,
            );
            response.extensions.insert(
                "verification".into(),
                json!({
                    "record_id": record.record_id,
                    "result": record.result,
                    "publication_revision": published.publication.revision,
                }),
            );
            return response;
        }
    };
    let mut response = if let Some(code) = disposition.error {
        committed_failure(
            &context,
            &store,
            &acceptance,
            code,
            record.effects,
            "Verification completed without a true or false oracle result.",
            None,
        )
    } else {
        let mut response = context.success("verified");
        response.effects = record.effects;
        response
    };
    response.run = summary;
    response.finding = Some(badge);
    response.extensions.insert(
        "verification".into(),
        json!({
            "record_id": record.record_id,
            "result": record.result,
            "status_source": "operator_policy",
            "publication_revision": published.publication.revision,
            "artifact": published.stored.artifact,
        }),
    );
    response
}

fn fail(
    context: &Context,
    code: ErrorCode,
    commit: CommitStatus,
    effects: Effect,
    message: &'static str,
) -> ResponseV1 {
    context.failure(code, message, commit, effects)
}

fn execution_failure(
    context: &Context,
    store: &Store,
    acceptance: &RunAcceptance,
    failure: ExecutionFailure,
) -> ResponseV1 {
    if failure.recovery != acceptance.recovery() {
        return committed_failure(
            context,
            store,
            acceptance,
            ErrorCode::IntegrityFailure,
            failure.effects,
            "The acquisition recovery identity did not match the accepted run.",
            None,
        );
    }
    committed_failure(
        context,
        store,
        acceptance,
        failure.code(),
        failure.effects,
        "Verification acquisition failed. Inspect the accepted run; do not start a fresh verification.",
        failure.capture_handle.as_ref(),
    )
}

fn committed_failure(
    context: &Context,
    store: &Store,
    acceptance: &RunAcceptance,
    code: ErrorCode,
    effects: Effect,
    message: &'static str,
    capture_handle: Option<&CaptureHandle>,
) -> ResponseV1 {
    let recovery = acceptance.recovery();
    let run = store
        .recover_run(&recovery.run_id)
        .unwrap_or_else(|_| acceptance.run.clone());
    let mut response = context.failure(code, message, CommitStatus::Committed, effects);
    response.request_key = Some(recovery.request_key.clone());
    response.run = Some(run_summary(&run));
    response.extensions.insert(
        "recovery".into(),
        json!({
            "run_id": recovery.run_id,
            "request_key": recovery.request_key,
            "capture_handle": capture_handle,
        }),
    );
    response.next.push(context.action(
        ActionEffect::None,
        [
            text("show"),
            text(run.id.as_str()),
            text("--depth"),
            text("full"),
        ],
    ));
    response
}

fn run_summary(run: &Run) -> RunSummary {
    RunSummary {
        cleanup: run.cleanup,
        flags: run.flags.clone(),
        id: run.id.clone(),
        oracle_result: run.oracle_result,
        reproduction: run.reproduction,
        state: run.state,
    }
}

fn text(value: &str) -> scourge_core::ids::WireText {
    value.parse().expect("valid recovery action")
}

fn preview_slots(values: &[String]) -> Result<Vec<SlotValue>, ErrorCode> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .map(|value| {
            let (name, value) = value.split_once('=').ok_or(ErrorCode::UsageError)?;
            let name = name
                .parse::<SlotName>()
                .map_err(|_| ErrorCode::UsageError)?;
            if !seen.insert(name.clone()) {
                return Err(ErrorCode::SlotConflict);
            }
            Ok(SlotValue {
                name,
                value: value.parse().map_err(|_| ErrorCode::UsageError)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scourge_core::{
        canonical::Sha256Digest,
        ids::RequestKey,
        rounds::RoundError,
        store::RunRecovery,
        wire::{self, ActionEffect},
    };

    fn accepted() -> RunAcceptance {
        let run = Run::declare(
            "review".parse().unwrap(),
            Sha256Digest::of(b"review recovery experiment"),
        );
        RunAcceptance {
            run,
            receipt: 7,
            lead_id: Some("L-review".parse().unwrap()),
            lead_revision: Some(3),
            engagement_revision: 4,
        }
    }

    fn context(acceptance: &RunAcceptance) -> Context {
        Context {
            command: Some(text("verify")),
            workspace: Some("/tmp/bn-23g-recovery-test".parse().unwrap()),
            engagement: Some(acceptance.run.engagement.clone()),
            request_key: Some(acceptance.run.request_key.clone()),
        }
    }

    fn failure(
        acceptance: &RunAcceptance,
        effects: Effect,
        capture_handle: Option<CaptureHandle>,
    ) -> ExecutionFailure {
        ExecutionFailure {
            error: Box::new(RoundError::AdmissionMismatch),
            recovery: acceptance.recovery(),
            capture_handle,
            effects,
        }
    }

    #[test]
    fn acquisition_failures_keep_exact_committed_recovery_and_advise_only_safe_inspection() {
        let acceptance = accepted();
        let context = context(&acceptance);
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path().join("state.sqlite3")).unwrap();
        let handle: CaptureHandle = "handle_12345678-1234-4234-8234-123456789abc"
            .parse()
            .unwrap();

        for (effects, capture) in [
            (Effect::None, None),
            (Effect::Observed, Some(handle.clone())),
            (Effect::Unknown, Some(handle.clone())),
        ] {
            let response = execution_failure(
                &context,
                &store,
                &acceptance,
                failure(&acceptance, effects, capture.clone()),
            );
            let error = response.error.as_ref().unwrap();
            assert_eq!(error.commit_status, CommitStatus::Committed);
            assert_eq!(response.effects, effects);
            assert_eq!(
                response.request_key,
                Some(acceptance.run.request_key.clone())
            );
            assert_eq!(
                response.run.as_ref().map(|run| &run.id),
                Some(&acceptance.run.id)
            );
            assert_eq!(
                response.extensions["recovery"],
                json!({
                    "run_id": acceptance.run.id,
                    "request_key": acceptance.run.request_key,
                    "capture_handle": capture,
                })
            );
            assert_eq!(response.next.len(), 1);
            assert_eq!(response.next[0].effects, ActionEffect::None);
            let argv = response.next[0]
                .argv
                .iter()
                .map(|value| value.as_str())
                .collect::<Vec<_>>();
            assert!(
                argv.windows(2)
                    .any(|pair| pair == ["show", acceptance.run.id.as_str()])
            );
            assert!(!argv.contains(&"verify"));
        }
    }

    #[test]
    fn mismatched_service_recovery_is_not_attributed_to_the_accepted_run() {
        let acceptance = accepted();
        let context = context(&acceptance);
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path().join("state.sqlite3")).unwrap();
        let mut failure = failure(
            &acceptance,
            Effect::Unknown,
            Some(
                "handle_12345678-1234-4234-8234-123456789abc"
                    .parse()
                    .unwrap(),
            ),
        );
        failure.recovery = RunRecovery {
            run_id: acceptance.run.id.clone(),
            request_key: RequestKey::generate(),
        };

        let response = execution_failure(&context, &store, &acceptance, failure);
        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(ErrorCode::IntegrityFailure)
        );
        assert_eq!(
            response.error.as_ref().map(|error| error.commit_status),
            Some(CommitStatus::Committed)
        );
        assert_eq!(response.effects, Effect::Unknown);
        assert_eq!(
            response.extensions["recovery"]["run_id"],
            acceptance.run.id.as_str()
        );
        assert_eq!(
            response.extensions["recovery"]["request_key"],
            acceptance.run.request_key.as_str()
        );
        assert!(response.extensions["recovery"]["capture_handle"].is_null());
    }

    #[test]
    fn recovery_json_and_human_output_are_stable_while_predeclaration_has_no_selector() {
        let acceptance = accepted();
        let context = context(&acceptance);
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path().join("state.sqlite3")).unwrap();
        let handle: CaptureHandle = "handle_12345678-1234-4234-8234-123456789abc"
            .parse()
            .unwrap();
        let response = execution_failure(
            &context,
            &store,
            &acceptance,
            failure(&acceptance, Effect::Observed, Some(handle.clone())),
        );

        let json_first = wire::to_vec(&response).unwrap();
        let json_second = wire::to_vec(&response).unwrap();
        assert_eq!(json_first, json_second);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = crate::emit_response(
            response.clone(),
            crate::Format::Text,
            &mut stdout,
            &mut stderr,
        )
        .unwrap();
        assert_eq!(exit, ErrorCode::IntegrityFailure.exit_code());
        assert!(stdout.is_empty());
        let rendered = String::from_utf8(stderr).unwrap();
        assert!(rendered.contains(&format!("recovery run  {}\n", acceptance.run.id.as_str())));
        assert!(rendered.contains(&format!(
            "recovery request  {}\n",
            acceptance.run.request_key.as_str()
        )));
        assert!(rendered.contains(&format!("recovery capture  {}\n", handle.as_str())));
        assert!(rendered.contains(&format!(
            " show {} --depth full\n",
            acceptance.run.id.as_str()
        )));
        assert!(!rendered.contains(" verify "));

        let before = fail(
            &Context::for_command("verify"),
            ErrorCode::CapabilityUnavailable,
            CommitStatus::NotCommitted,
            Effect::None,
            "Verifier runtime authority is unavailable or conflicts.",
        );
        assert!(before.request_key.is_none());
        assert!(before.run.is_none());
        assert!(before.next.is_empty());
        assert!(!before.extensions.contains_key("recovery"));
    }
}
