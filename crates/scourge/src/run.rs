//! Read-only run inspection and lost-response reconciliation from durable
//! local state plus qualified retained evidence, with a conservative fallback.

use std::io::{self, Write};

use clap::{Args, Subcommand};
use scourge_core::{
    canonical::Sha256Digest,
    domain::Run,
    ids::{EngagementId, RequestKey, RunId, WireText},
    response::Context,
    store::{
        RunReconciliation, StoreError,
        read::{RecoverySelector, RunRecovery},
    },
    teapot::Teapot,
    wire::{ActionEffect, CommitStatus, Effect, ErrorCode, ResponseV1, RunSummary},
    workspace::{BoundWorkspace, WorkspaceError},
};
use serde_json::{Value, json};

use crate::{Format, workspace_failure};

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum RunCommand {
    /// Show an accepted run by its service-issued run ID or request key.
    #[command(
        after_help = "Examples:\n  scourge run show \"$run_id\"\n  scourge run show --request-key \"$request_key\"\n\nUse the run ID or request key from the verification response."
    )]
    Show(RunShowArgs),
    /// Reconcile an existing run from durable local and retained evidence.
    #[command(after_help = "This sends no target traffic and never creates or retries a run.")]
    Reconcile {
        /// The original service-issued run ID.
        #[arg(value_name = "RUN")]
        run: RunId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct RunShowArgs {
    /// The original service-issued run ID.
    #[arg(
        value_name = "RUN",
        conflicts_with = "request_key",
        required_unless_present = "request_key"
    )]
    pub(crate) run: Option<RunId>,
    /// The original service-issued request key.
    #[arg(
        long,
        value_name = "KEY",
        conflicts_with = "run",
        required_unless_present = "run"
    )]
    pub(crate) request_key: Option<RequestKey>,
}

pub(crate) fn dispatch(
    mut context: Context,
    workspace: &BoundWorkspace,
    requested: Option<&EngagementId>,
    command: &RunCommand,
) -> ResponseV1 {
    let (name, _) = match workspace.select_engagement(requested.map(EngagementId::as_str)) {
        Ok(selected) => selected,
        Err(error) => return workspace_failure(&context, error),
    };
    let engagement: EngagementId = match name.parse() {
        Ok(engagement) => engagement,
        Err(_) => return workspace_failure(&context, WorkspaceError::InvalidEngagement),
    };
    context.engagement = Some(engagement.clone());
    let scope = match workspace.request_scope(&engagement) {
        Ok(scope) => scope,
        Err(error) => return workspace_failure(&context, error),
    };

    match command {
        RunCommand::Show(args) => {
            let store = match workspace.open_coordination() {
                Ok(store) => store,
                Err(error) => return workspace_failure(&context, error),
            };
            let selector = match (&args.run, &args.request_key) {
                (Some(run), None) => RecoverySelector::Run(run),
                (None, Some(key)) => RecoverySelector::RequestKey(key),
                _ => unreachable!("Clap requires exactly one run selector"),
            };
            match store.recover(&scope, selector) {
                Ok(recovery) => show_response(&context, &recovery),
                Err(error) => store_failure(&context, error, None),
            }
        }
        RunCommand::Reconcile { run } => {
            // Preserve the accepted identity in all post-resolution failures.
            // Qualified Investigation reads may authenticate a retained
            // refusal, but reconciliation sends no target traffic. If that
            // authority is unavailable, the local projection stays unknown.
            let prior = match workspace.open_coordination().and_then(|store| {
                store
                    .recover(&scope, RecoverySelector::Run(run))
                    .map_err(WorkspaceError::from)
            }) {
                Ok(recovery) => recovery,
                Err(error) => return workspace_failure(&context, error),
            };
            let mut store = match workspace.open_coordination_writer() {
                Ok(store) => store,
                Err(error) => return writer_open_failure(&context, error, &prior),
            };
            let reconciled = workspace
                .resolve_verifier_runtime(engagement.as_str())
                .ok()
                .and_then(|runtime| {
                    let qualified = workspace.open_verifier_evidence(&engagement).ok()?;
                    let teapot = Teapot::from_runtime(runtime).ok()?;
                    Some(store.reconcile_run_with_evidence(
                        &scope,
                        run,
                        qualified.evidence(),
                        &teapot,
                    ))
                })
                .unwrap_or_else(|| store.reconcile_run(&scope, run));
            match reconciled {
                Ok(reconciled) => reconcile_response(&context, reconciled),
                Err(error) => store_failure(&context, error, Some(&prior)),
            }
        }
    }
}

fn writer_open_failure(
    context: &Context,
    error: WorkspaceError,
    prior: &RunRecovery,
) -> ResponseV1 {
    let run = &prior.acceptance.run;
    let effects = prior.established_effects();
    let mut response = context.failure(
        error.code(),
        "The accepted run is durable, but its local coordination writer could not be opened; no target action was attempted.",
        CommitStatus::Committed,
        effects,
    );
    response.request_key = Some(run.request_key.clone());
    response.run = Some(run_summary(run));
    attach_recovery(&mut response, prior, effects);
    response.extensions.insert(
        "writer".into(),
        json!({"opened": false, "target_requests": 0, "new_runs": 0}),
    );
    response.next.push(show_action(context, &run.id));
    response
}

pub(crate) fn show_response(context: &Context, recovery: &RunRecovery) -> ResponseV1 {
    let run = &recovery.acceptance.run;
    let mut response = context.success("shown");
    response.request_key = Some(run.request_key.clone());
    response.run = Some(run_summary(run));
    response.effects = Effect::None;
    attach_recovery(&mut response, recovery, recovery.established_effects());
    if !recovery.trusted_evidence || recovery.has_unresolved_dispatch() {
        response.blockers.push(ErrorCode::EffectUnknown);
    }
    response
}

fn reconcile_response(context: &Context, reconciled: RunReconciliation) -> ResponseV1 {
    let run = &reconciled.acceptance.run;
    let mut response = if reconciled.effects == Effect::Unknown {
        context.failure(
            ErrorCode::EffectUnknown,
            "No exact durable outcome establishes this run's target effects; nothing was repeated.",
            CommitStatus::Committed,
            Effect::Unknown,
        )
    } else {
        let mut response = context.success("reconciled");
        response.effects = reconciled.effects;
        response
    };
    response.request_key = Some(run.request_key.clone());
    response.run = Some(run_summary(run));
    response.extensions.insert(
        "recovery".into(),
        json!({
            "run_id": run.id,
            "request_key": run.request_key,
            "capture_handle": reconciled.capture_handle,
        }),
    );
    response.extensions.insert(
        "reconciliation".into(),
        json!({
            "committed": reconciled.committed,
            "revision": reconciled.revision,
            "effects": reconciled.effects,
            "target_requests": 0,
            "new_runs": 0,
        }),
    );
    response.next.push(show_action(context, &run.id));
    response
}

fn store_failure(context: &Context, error: StoreError, prior: Option<&RunRecovery>) -> ResponseV1 {
    let code = error.error_code();
    let mut response = context.failure(
        code,
        match code {
            ErrorCode::ObjectNotFound => "No accepted run matches that selector in this scope.",
            ErrorCode::ConflictingRun => {
                "The run's durable recovery evidence conflicts; no outcome was attributed."
            }
            ErrorCode::IntegrityFailure => {
                "The accepted request or recovery identity failed an integrity check."
            }
            _ => "The run could not be reconciled from local durable evidence.",
        },
        if prior.is_some() {
            CommitStatus::Committed
        } else {
            CommitStatus::NotCommitted
        },
        prior.map_or(Effect::None, RunRecovery::established_effects),
    );
    if let Some(prior) = prior {
        response.request_key = Some(prior.acceptance.run.request_key.clone());
        response.run = Some(run_summary(&prior.acceptance.run));
        response.extensions.insert(
            "recovery".into(),
            json!({
                "run_id": prior.acceptance.run.id,
                "request_key": prior.acceptance.run.request_key,
                "capture_handle": prior.capture_handle,
            }),
        );
        response
            .next
            .push(show_action(context, &prior.acceptance.run.id));
    }
    response
}

fn attach_recovery(response: &mut ResponseV1, recovery: &RunRecovery, effects: Effect) {
    let run = &recovery.acceptance.run;
    response
        .extensions
        .insert("run_effects".into(), json!(effects));
    response.extensions.insert(
        "recovery".into(),
        json!({
            "run_id": run.id,
            "request_key": run.request_key,
            "capture_handle": recovery.capture_handle,
        }),
    );
    response.extensions.insert(
        "accepted_request".into(),
        json!({
            "schema": "scourge.request-input.v1",
            "command": recovery.input.command(),
            "input_digest": recovery.input.digest().unwrap_or_else(|_| Sha256Digest::of(b"invalid")),
            "receipt": recovery.acceptance.receipt,
            "lead_id": recovery.acceptance.lead_id,
            "lead_revision": recovery.acceptance.lead_revision,
            "engagement_revision": recovery.acceptance.engagement_revision,
        }),
    );
    response.extensions.insert(
        "reconciliation".into(),
        json!({
            "unresolved": !recovery.trusted_evidence || recovery.has_unresolved_dispatch(),
            "trusted_evidence": recovery.trusted_evidence,
            "run_revision": recovery.run_revision,
            "store_revision": recovery.store_revision,
            "target_requests": 0,
            "new_runs": 0,
        }),
    );
    response.extensions.insert(
        "steps".into(),
        Value::Array(
            run.steps
                .iter()
                .map(|step| {
                    json!({
                        "number": step.number,
                        "step": step.step,
                        "request_digest": step.request_digest,
                        "flow_id_floor": step.flow_id_floor,
                        "instrument_reference": step.instrument_reference,
                        "effects": step.effects,
                        "flow_ids": step.flows.iter().map(|flow| flow.flow_id).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        ),
    );
}

fn show_action(context: &Context, run: &RunId) -> scourge_core::wire::Action {
    context.action(
        ActionEffect::None,
        [text("run"), text("show"), text(run.as_str())],
    )
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

fn text(value: &str) -> WireText {
    value.parse().expect("valid run action")
}

pub(crate) fn write_human(
    response: &ResponseV1,
    format: Format,
    stream: &mut impl Write,
) -> io::Result<bool> {
    if !matches!(
        response.command.as_ref().map(WireText::as_str),
        Some("run show" | "run reconcile")
    ) || response.error.is_some()
    {
        return Ok(false);
    }
    let Some(run) = &response.run else {
        return Ok(false);
    };
    let separator = if format == Format::Pretty {
        "  │  "
    } else {
        "  "
    };
    writeln!(
        stream,
        "{}{}run{}{}{}effects={}",
        run.id.as_str(),
        separator,
        separator,
        format!("{:?}", run.state).to_ascii_lowercase(),
        separator,
        format!("{:?}", response.effects).to_ascii_lowercase()
    )?;
    if let Some(recovery) = response.extensions.get("recovery") {
        for (label, field) in [("request", "request_key"), ("capture", "capture_handle")] {
            if let Some(value) = recovery.get(field).and_then(Value::as_str) {
                writeln!(stream, "recovery {label}  {value}")?;
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scourge_core::{
        domain::RunStep,
        request::Invocation,
        store::{RunAcceptance, read::RunAuditEvent},
        wire::{Cleanup, Reproduction, RunFlag, RunState, Timestamp},
    };

    fn recovery(effect: Effect) -> RunRecovery {
        let engagement: EngagementId = "local".parse().unwrap();
        let input = Invocation::new("verify", json!({"lead_id": "L-1"}))
            .normalize()
            .unwrap();
        let mut run = Run::declare(engagement, Sha256Digest::of(b"experiment"));
        run.id = "R-recovery".parse().unwrap();
        run.request_key = "rk_recovery".parse().unwrap();
        run.effects = effect;
        run.state = RunState::Finalized;
        run.flags = vec![RunFlag::ReconciliationRequired];
        run.reproduction = Reproduction::NotAttempted;
        run.cleanup = Cleanup::NotRequired;
        run.steps.push(RunStep {
            number: 1,
            step: "probe".parse().unwrap(),
            request_digest: Sha256Digest::of(b"request"),
            flow_id_floor: Some(7),
            instrument_reference: (effect == Effect::Unknown)
                .then(|| "sent:no-flow".parse().unwrap()),
            effects: Some(effect),
            flows: Vec::new(),
        });
        RunRecovery {
            acceptance: RunAcceptance {
                run,
                receipt: 3,
                lead_id: Some("L-1".parse().unwrap()),
                lead_revision: Some(1),
                engagement_revision: 2,
            },
            input,
            experiment_artifact_id: None,
            capture_handle: Some(
                "handle_12345678-1234-4234-8234-123456789abc"
                    .parse()
                    .unwrap(),
            ),
            trusted_evidence: true,
            run_revision: 8,
            store_revision: 9,
            audit: vec![RunAuditEvent {
                revision: 3,
                operation: "request.accept".parse().unwrap(),
                recorded_at: Timestamp::now_utc(),
            }],
        }
    }

    #[test]
    fn run_show_projects_original_identity_and_read_only_unknown_effects() {
        let mut context = Context::for_command("run show");
        context.workspace = Some("/tmp/recovery-workspace".parse().unwrap());
        context.engagement = Some("local".parse().unwrap());
        let response = show_response(&context, &recovery(Effect::Unknown));
        assert!(response.ok);
        assert_eq!(response.effects, Effect::None, "show itself is read-only");
        assert_eq!(response.blockers, [ErrorCode::EffectUnknown]);
        assert_eq!(response.extensions["recovery"]["run_id"], "R-recovery");
        assert_eq!(
            response.extensions["recovery"]["capture_handle"],
            "handle_12345678-1234-4234-8234-123456789abc"
        );
        assert_eq!(response.extensions["reconciliation"]["target_requests"], 0);
        assert_eq!(response.extensions["reconciliation"]["new_runs"], 0);
        assert!(response.next.is_empty(), "show does not encourage a retry");
        let bytes = scourge_core::wire::to_vec(&response).unwrap();
        let decoded: ResponseV1 = scourge_core::wire::from_slice(&bytes).unwrap();
        assert_eq!(decoded.request_key.unwrap().as_str(), "rk_recovery");
    }

    #[test]
    fn unresolved_reconcile_is_committed_effect_unknown_and_advises_only_show() {
        let prior = recovery(Effect::Unknown);
        let response = reconcile_response(
            &Context::for_command("run reconcile"),
            RunReconciliation {
                acceptance: prior.acceptance,
                capture_handle: prior.capture_handle,
                effects: Effect::Unknown,
                committed: true,
                revision: 10,
            },
        );
        assert_eq!(
            response.error.as_ref().unwrap().code,
            ErrorCode::EffectUnknown
        );
        assert_eq!(
            response.error.as_ref().unwrap().commit_status,
            CommitStatus::Committed
        );
        assert_eq!(response.effects, Effect::Unknown);
        assert_eq!(response.next.len(), 1);
        let argv = response.next[0]
            .argv
            .iter()
            .map(WireText::as_str)
            .collect::<Vec<_>>();
        assert!(argv.ends_with(&["run", "show", "R-recovery"]));
        assert!(
            !argv
                .iter()
                .any(|arg| *arg == "verify" || *arg == "reconcile")
        );
        assert_eq!(response.extensions["reconciliation"]["target_requests"], 0);
    }

    #[test]
    fn human_run_output_keeps_service_selectors_stable() {
        let response = show_response(
            &Context::for_command("run show"),
            &recovery(Effect::Unknown),
        );
        let mut text = Vec::new();
        assert!(write_human(&response, Format::Text, &mut text).unwrap());
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("R-recovery  run  finalized"));
        assert!(text.contains("recovery request  rk_recovery"));
        assert!(text.contains("recovery capture  handle_12345678-1234-4234-8234-123456789abc"));
    }

    #[test]
    fn writer_open_failure_preserves_durable_recovery_and_safe_show_only() {
        let prior = recovery(Effect::Unknown);
        let response = writer_open_failure(
            &Context::for_command("run reconcile"),
            WorkspaceError::CoordinationInvalid,
            &prior,
        );
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.commit_status, CommitStatus::Committed);
        assert_eq!(response.effects, Effect::Unknown);
        assert_eq!(response.extensions["recovery"]["run_id"], "R-recovery");
        assert_eq!(
            response.extensions["recovery"]["request_key"],
            "rk_recovery"
        );
        assert_eq!(response.extensions["writer"]["target_requests"], 0);
        let argv = response.next[0]
            .argv
            .iter()
            .map(WireText::as_str)
            .collect::<Vec<_>>();
        assert!(argv.ends_with(&["run", "show", "R-recovery"]));
        assert!(
            !argv
                .iter()
                .any(|arg| *arg == "verify" || *arg == "reconcile")
        );
    }
}
