use std::sync::{Arc, Mutex};

use axum::{
    extract::Request,
    middleware::{self, Next},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use scourge_core::{
    domain::{CleanupObjectOutcome, CleanupObjectRole, CleanupOwnership, RunStep},
    evidence::CaptureState,
    rounds::RoundError,
    store::StoreError,
    teapot::{BodyWindow, DispatchEvidence, InvocationError, SendOutcome, decode_retained_flow},
    wire::{Cleanup, Effect, RunFlag},
};

use super::*;

const TEAPOT_PIN: &str = include_str!("../../contracts/request-reference-manifest.json");
const IDENTITY: &str = "GET /app/api/me";
const PLANT: &str = "POST /app/api/orders";

struct OwnedTarget {
    server: DevelopmentTarget,
    fixture: scourge_fixture::RecoveryFixture,
    requests: Arc<Mutex<Vec<String>>>,
}

impl OwnedTarget {
    fn start() -> Self {
        let fixture = scourge_fixture::RecoveryFixture::new(
            ADMIN_SECRET.to_owned(),
            [ALICE_PASSWORD.to_owned(), BOB_PASSWORD.to_owned()],
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let trace = Arc::clone(&requests);
        let app = fixture
            .app()
            .layer(middleware::from_fn(move |request: Request, next: Next| {
                trace
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", request.method(), request.uri()));
                next.run(request)
            }));
        Self {
            server: DevelopmentTarget::serve(app),
            fixture,
            requests,
        }
    }

    fn assert_traffic(&self, before: usize, expected: &[&str]) {
        assert_eq!(&self.requests.lock().unwrap()[before..], expected);
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

#[test]
#[ignore = "requires Linux loopback and the qualified Teapot and Investigation executables"]
fn qualified_lost_response_recovery_on_owned_loopback() {
    let teapot_path = required_path(
        env::var_os("SCOURGE_RECOVERY_TEAPOT").map(PathBuf::from),
        "TEAPOT",
    );
    let investigation = required_path(
        env::var_os("SCOURGE_RECOVERY_INVESTIGATION").map(PathBuf::from),
        "INVESTIGATION",
    );
    qualify_teapot(&teapot_path, TEAPOT_PIN);
    Evidence::qualified_executable_bytes(&investigation)
        .expect("the exact qualified Investigation binary is required");

    lost_plant_and_equal_digest(&teapot_path, &investigation);
    capture_loss(&teapot_path, &investigation);
    pre_dispatch_refusal(&teapot_path, &investigation);
}

fn declare(harness: &mut Harness, name: &str) -> FixtureCase {
    harness.declare_case(name, "orders", "alice", "bob", json!({}))
}

fn failed_execution(
    harness: &mut Harness,
    case: &FixtureCase,
) -> (RunAcceptance, ExecutionFailure, CaptureState) {
    let (accepted, executed) = harness.execute(case).expect("live preparation");
    let failure = executed.expect_err("acquisition should stop");
    assert_eq!(accepted.run.id, case.run.id);
    assert_eq!(accepted.run.request_key, case.run.request_key);
    assert_eq!(failure.recovery, accepted.recovery());
    assert_eq!(failure.effects, Effect::Unknown);
    assert_eq!(failure.code(), ErrorCode::EffectUnknown);
    let handle = failure.capture_handle.as_ref().expect("run-bound capture");
    let retained = harness
        .evidence
        .recover(handle)
        .expect("recover native capture");
    let sealed = retained
        .finalized
        .as_ref()
        .expect("sealed interrupted capture");
    assert_eq!(&retained.capture.handle, handle);
    assert!(!sealed.complete);
    assert!(sealed.missing_positions.is_empty());

    for key in ["edit-surface-start", "edit-surface-end"] {
        let (original, bytes) = original(harness, &retained, key);
        assert_eq!(original.attachment.digest, Sha256Digest::of(&bytes));
        let observation: Value = serde_json::from_slice(&bytes).unwrap();
        let identity = &observation["observation"]["admitted"]["identity"];
        let pin: Value = serde_json::from_str(TEAPOT_PIN).unwrap();
        assert_eq!(identity["commit"], pin["source_commit"]);
        assert_eq!(identity["binary_digest"], pin["binary_sha256"]);
        assert_eq!(
            identity["engine_instance"],
            harness.runtime.engine.instance.as_str()
        );
        assert_eq!(
            identity["project_id"],
            harness.runtime.engine.project_id.as_str()
        );
    }

    (accepted, failure, retained)
}

fn original<'a>(
    harness: &Harness,
    capture: &'a CaptureState,
    key: &str,
) -> (&'a scourge_core::evidence::Original, Vec<u8>) {
    let original = capture
        .finalized
        .as_ref()
        .unwrap()
        .original_artifacts
        .iter()
        .find(|original| original.attachment.key == key)
        .unwrap_or_else(|| panic!("missing original {key}"));
    let read = harness
        .evidence
        .read_json(&original.artifact.artifact_id)
        .unwrap();
    assert_eq!(read.artifact.reference, original.artifact);
    assert_eq!(Sha256Digest::of(&read.bytes), original.artifact.digest);
    (original, read.bytes)
}

fn native_error(failure: &ExecutionFailure, exit: i64, reason: &str) {
    let RoundError::Instrument(InvocationError::DependencyUnavailable {
        diagnostic,
        native_reason,
        transport_failure,
    }) = failure.error.as_ref()
    else {
        panic!("expected native send failure, got {failure:?}");
    };
    assert_eq!(diagnostic.stage.as_str(), "send");
    assert_eq!(diagnostic.native_exit, Some(exit));
    assert_eq!(native_reason.as_ref().unwrap().as_str(), reason);
    assert!(transport_failure.is_none());
}

fn assert_recovery(
    harness: &mut Harness,
    case: &FixtureCase,
    accepted: &RunAcceptance,
    retained: &CaptureState,
    effect: Effect,
) -> Run {
    let reconcile = |store: &mut Store| {
        store
            .reconcile_run_with_evidence(
                &harness.scope,
                &accepted.run.id,
                &harness.evidence,
                &harness.teapot,
            )
            .unwrap()
    };
    let first = reconcile(&mut harness.store);
    assert_eq!(first.acceptance.recovery(), accepted.recovery());
    assert_eq!(first.acceptance.receipt, accepted.receipt);
    assert_eq!(
        first.capture_handle.as_ref(),
        Some(&retained.capture.handle)
    );
    assert_eq!(first.effects, effect);
    assert!(first.committed);
    let run = first.acceptance.run.clone();
    assert_eq!(run.state, RunState::Finalized);
    assert_eq!(run.effects, effect);
    assert!(run.flags.contains(&RunFlag::ReconciliationRequired));

    let reopened = harness
        .store
        .reopen_request(&harness.scope, &case.run.request_key, &case.input)
        .unwrap();
    assert_eq!(reopened, first.acceptance);
    let again = reconcile(&mut harness.store);
    assert!(!again.committed);
    assert_eq!(again.revision, first.revision);
    assert_eq!(again.acceptance, first.acceptance);
    assert_eq!(again.capture_handle, first.capture_handle);
    assert_eq!(again.effects, first.effects);
    assert_eq!(
        harness.evidence.recover(&retained.capture.handle).unwrap(),
        *retained,
        "reopen and reconciliation must preserve the original capture",
    );
    run
}

fn lost_plant_and_equal_digest(teapot_path: &Path, investigation: &Path) {
    let target = OwnedTarget::start();
    let project = PinnedProject::new(teapot_path, target.server.address());
    let (project, mut first) = start_harness(project, &target.server, investigation);
    target.assert_traffic(0, &["POST /app/login", "POST /app/login"]);

    let (first_run, first_capture) = one_lost_plant(&target, &project, &mut first, "lost-plant");
    let competing = declare(&mut first, "conflicts-with-lost-plant");
    let before = target.request_count();
    assert!(matches!(
        first.execute(&competing),
        Err(PreflightError::Store(StoreError::Conflict))
    ));
    target.assert_traffic(before, &[]);

    // Independent coordination histories use the same target, credentials,
    // operation and Teapot engine while each retains its own conflict fence.
    let mut second = open_harness(
        &project,
        &target.server,
        investigation,
        Teapot::from_runtime(&first.runtime).unwrap(),
        first.runtime.engine.clone(),
    );
    let (second_run, second_capture) =
        one_lost_plant(&target, &project, &mut second, "lost-plant-peer");
    assert_ne!(first_run.id, second_run.id);
    assert_ne!(first_run.request_key, second_run.request_key);
    assert_ne!(first_capture.capture.handle, second_capture.capture.handle);
    assert_ne!(
        first_capture.finalized.as_ref().unwrap().manifest_digest,
        second_capture.finalized.as_ref().unwrap().manifest_digest,
    );
    let first_id = &first_run.steps[0];
    let second_id = &second_run.steps[0];
    assert_eq!(first_id.request_digest, second_id.request_digest);
    // Each plant contains fresh private canaries. The identical I1 GETs
    // instead exercise digest equality without substituting for OS entropy.
    assert_ne!(
        first_run.steps[2].request_digest,
        second_run.steps[2].request_digest
    );
    let first_flow = &first_id.flows[0];
    let second_flow = &second_id.flows[0];
    assert!(first_flow.flow_id.unwrap() < second_flow.flow_id.unwrap());
    assert_ne!(first_flow.original, second_flow.original);
    assert!(
        first
            .evidence
            .read_json(&second_flow.original.as_ref().unwrap().artifact_id)
            .is_err()
    );
    assert!(
        second
            .evidence
            .read_json(&first_flow.original.as_ref().unwrap().artifact_id)
            .is_err()
    );
    target.assert_traffic(2, &[IDENTITY, IDENTITY, PLANT, IDENTITY, IDENTITY, PLANT]);
    assert_eq!(target.fixture.order_count(), 2);
    println!(
        "equal-identity-digest: digest={} runs={}/{} keys={}/{} captures={}/{} flows={}/{} traffic={:?}",
        first_id.request_digest.as_str(),
        first_run.id.as_str(),
        second_run.id.as_str(),
        first_run.request_key.as_str(),
        second_run.request_key.as_str(),
        first_capture.capture.handle.as_str(),
        second_capture.capture.handle.as_str(),
        first_flow.flow_id.unwrap(),
        second_flow.flow_id.unwrap(),
        [IDENTITY, IDENTITY],
    );

    let native_project = project.project.clone();
    drop(project);
    assert!(!native_project.exists());
    let before = target.request_count();
    for (harness, run, capture) in [
        (&mut first, &first_run, &first_capture),
        (&mut second, &second_run, &second_capture),
    ] {
        let (_, retained_lookup) = retained_dispatch(harness, run, capture);
        assert!(!retained_lookup.is_empty());
        let reconciled = harness
            .store
            .reconcile_run_with_evidence(
                &harness.scope,
                &run.id,
                &harness.evidence,
                &harness.teapot,
            )
            .unwrap();
        assert_eq!(&reconciled.acceptance.run, run);
        assert_eq!(reconciled.effects, Effect::Unknown);
        assert!(!reconciled.committed);
        assert_eq!(
            reconciled.capture_handle.as_ref(),
            Some(&capture.capture.handle)
        );
        assert_eq!(
            harness
                .store
                .find_request(&harness.scope, &run.request_key)
                .unwrap()
                .unwrap(),
            reconciled.acceptance
        );
    }
    target.assert_traffic(before, &[]);
}

fn one_lost_plant(
    target: &OwnedTarget,
    project: &PinnedProject,
    harness: &mut Harness,
    label: &str,
) -> (Run, CaptureState) {
    let case = declare(harness, label);
    let before = target.request_count();
    let orders = target.fixture.order_count();
    target.fixture.drop_next_order_response();
    let (accepted, failure, retained) = failed_execution(harness, &case);
    native_error(&failure, 2, "outcome-unknown");
    target.assert_traffic(before, &[IDENTITY, IDENTITY, PLANT]);
    assert_eq!(target.fixture.order_count(), orders + 1);

    let run = harness.store.recover_run(&case.run.id).unwrap();
    assert_eq!(run.known_effects(), Effect::Unknown);
    let [i1, i2, plant] = run.steps.as_slice() else {
        panic!("expected exactly two identity observations and one plant");
    };
    assert_identity(harness, &retained, i1, "I1", "user-alice-verify");
    assert_identity(harness, &retained, i2, "I2", "user-bob-verify");
    assert_eq!(plant.step.as_str(), "round.1.P");
    assert_eq!(plant.effects, Some(Effect::Unknown));
    assert!(plant.flows.is_empty());
    assert_eq!(plant.flow_id_floor, i2.flows[0].flow_id);

    let after_floor = harness.teapot.passive().highest_flow_id().unwrap();
    let plant_flow_id = plant.flow_id_floor.unwrap() + 1;
    assert_eq!(after_floor, Some(plant_flow_id));
    let native_plant = harness
        .teapot
        .read_flow(
            plant_flow_id,
            Some(BodyWindow::new(0, 1024 * 1024).unwrap()),
        )
        .unwrap();
    assert_eq!(native_plant.value.method.as_deref(), Some("POST"));
    assert_eq!(
        native_plant.value.url.as_deref(),
        Some(format!("{}/app/api/orders", harness.runtime.origin.as_str()).as_str())
    );
    assert_ne!(
        native_plant.value.retained_response().completeness,
        Completeness::Complete
    );

    let reference = native_plant
        .value
        .tags
        .iter()
        .find_map(|tag| tag.strip_prefix("send-ref:"))
        .expect("the real dispatch retained its caller reference");
    assert!(reference.starts_with("scourge:"));
    let lookup = project.command(&["requests", "lookup", reference]);
    assert!(lookup.status.success());
    let (authority, retained_lookup) = retained_dispatch(harness, &run, &retained);
    assert_eq!(authority["reference"], reference);
    assert_eq!(retained_lookup, lookup.stdout);
    assert_eq!(
        native_plant
            .value
            .request
            .body
            .as_ref()
            .unwrap()
            .bytes
            .as_deref(),
        Some(authority["target"]["body"].as_str().unwrap().as_bytes()),
    );
    let reply: Value = serde_json::from_slice(&lookup.stdout).unwrap();
    let recorded = &reply["lookup"];
    assert_eq!(recorded["ref"], reference);
    assert_eq!(recorded["state"], "failed");
    assert_eq!(recorded["reason"], "outcome-unknown");
    let [hop] = recorded["flows"].as_array().unwrap().as_slice() else {
        panic!("expected one recorded native plant hop");
    };
    assert_eq!(hop["flow"], plant_flow_id);
    assert_eq!(hop["source"], "record");
    assert_eq!(hop["present"], true);
    assert_eq!(hop["outcome"], "unknown");
    assert_eq!(recorded["evidence"]["units_admitted"], 1);
    assert_eq!(recorded["evidence"]["units_used"], 1);
    assert_eq!(recorded["evidence"]["dial"], "started");
    assert_eq!(
        recorded["evidence"]["engine"],
        harness.runtime.engine.instance.as_str()
    );

    let cleanup = harness.store.recover_cleanup(&case.run.id).unwrap();
    let [owed] = cleanup.as_slice() else {
        panic!("expected one durable cleanup obligation");
    };
    assert_eq!(owed.object, CleanupObjectRole::Primary);
    assert_eq!(owed.plant_step, plant.number);
    assert_eq!(owed.plant_request_digest, plant.request_digest);
    assert_eq!(owed.ownership, CleanupOwnership::Unknown);
    assert_eq!(owed.outcome, CleanupObjectOutcome::Owed);
    assert!(owed.object_id.is_none() && owed.cleanup_step.is_none() && owed.flows.is_empty());
    assert!(harness.store.conflicts_held(&case.run.id).unwrap());

    let reconciled = assert_recovery(harness, &case, &accepted, &retained, Effect::Unknown);
    assert_eq!(reconciled.steps, run.steps);
    assert_eq!(reconciled.cleanup, Cleanup::Unknown);
    assert_eq!(
        harness.store.recover_cleanup(&case.run.id).unwrap(),
        cleanup
    );
    assert!(harness.store.conflicts_held(&case.run.id).unwrap());
    assert!(matches!(
        harness.execute(&case),
        Err(PreflightError::Replay)
    ));
    assert_eq!(
        harness.teapot.passive().highest_flow_id().unwrap(),
        after_floor
    );
    target.assert_traffic(before, &[IDENTITY, IDENTITY, PLANT]);
    assert_eq!(target.fixture.order_count(), orders + 1);
    println!(
        "{label}: run={} key={} capture={} plant_digest={} native_flow={} native_original_sha256={} ref={} lookup_sha256={} authority={} native_exit=2 reason=outcome-unknown effects=unknown cleanup=owed traffic={:?} orders_delta=1 recovery_traffic=0",
        case.run.id.as_str(),
        case.run.request_key.as_str(),
        retained.capture.handle.as_str(),
        plant.request_digest.as_str(),
        plant_flow_id,
        Sha256Digest::of(native_plant.evidence.stdout()).as_str(),
        reference,
        Sha256Digest::of(&lookup.stdout).as_str(),
        plant.instrument_reference.as_ref().unwrap().as_str(),
        [IDENTITY, IDENTITY, PLANT],
    );
    (reconciled, retained)
}

fn retained_dispatch(harness: &Harness, run: &Run, capture: &CaptureState) -> (Value, Vec<u8>) {
    let step = &run.steps[2];
    let linked_digest = step
        .instrument_reference
        .as_ref()
        .unwrap()
        .as_str()
        .strip_prefix("dispatch:")
        .expect("durable dispatch authority reference");
    let attachments = capture
        .attachments
        .iter()
        .filter(|item| item.key.starts_with("dispatch-failure-"))
        .collect::<Vec<_>>();
    let [attachment] = attachments.as_slice() else {
        panic!("expected one retained dispatch failure");
    };
    let (published, bytes) = original(harness, capture, &attachment.key);
    assert_eq!(published.artifact.digest.as_str(), linked_digest);
    let authority: Value = scourge_core::canonical::from_canonical_slice(&bytes).unwrap();
    assert_eq!(authority["schema"], "scourge.dispatch-failure-authority.v1");
    assert_eq!(authority["run_id"], run.id.as_str());
    assert_eq!(authority["request_key"], run.request_key.as_str());
    assert_eq!(authority["step_number"], step.number);
    assert_eq!(authority["step"], step.step.as_str());
    assert_eq!(authority["request_digest"], step.request_digest.as_str());
    assert_eq!(authority["action_index"], 1);
    assert_eq!(authority["native_state"], "failed");
    assert_eq!(authority["native_reason"], "outcome-unknown");

    let instrument = &authority["instrument"];
    for boundary in ["start", "end"] {
        let (_, observation) = original(harness, capture, &format!("edit-surface-{boundary}"));
        let observed: Value = serde_json::from_slice(&observation).unwrap();
        assert_eq!(instrument, &observed["observation"]["admitted"]["identity"]);
    }
    let target = &authority["target"];
    assert_eq!(target["kind"], "send");
    assert_eq!(
        target["url"],
        format!("{}/app/api/orders", harness.runtime.origin.as_str())
    );
    assert_eq!(target["method"], "POST");
    assert_eq!(target["session"], "alice_verify");
    assert_eq!(target["headers"], json!(["Content-Type: application/json"]));
    let digest = |value: &Value| Sha256Digest::of(&scourge_core::canonical::to_vec(value).unwrap());
    assert_eq!(authority["instrument_digest"], digest(instrument).as_str());
    assert_eq!(authority["target_digest"], digest(target).as_str());
    let reference_digest = digest(&json!({
        "schema": "scourge.send-reference.v1",
        "run_id": run.id,
        "request_key": run.request_key,
        "step_number": step.number,
        "step": step.step,
        "request_digest": step.request_digest,
        "action_index": 1,
        "instrument_digest": authority["instrument_digest"],
        "target_digest": authority["target_digest"],
    }));
    let reference = format!("scourge:{}", reference_digest.as_str());
    assert_eq!(authority["reference"], reference);
    assert_eq!(attachment.key, format!("dispatch-failure-{reference}"));
    let argv = json!([
        harness.runtime.teapot.executable,
        "--project",
        harness.runtime.teapot.project,
        "--json",
        "requests",
        "send",
        "POST",
        target["url"],
        "--session",
        "alice_verify",
        "--header",
        "Content-Type: application/json",
        "--body",
        target["body"],
        "--ref",
        reference,
    ]);
    assert_eq!(
        authority["argv_digest"],
        Sha256Digest::of(&serde_json::to_vec(&argv).unwrap()).as_str()
    );
    let lookup = STANDARD
        .decode(authority["lookup_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        authority["lookup_digest"],
        Sha256Digest::of(&lookup).as_str()
    );
    let reply: Value = serde_json::from_slice(&lookup).unwrap();
    assert_eq!(reply["lookup"]["ref"], reference);
    assert_eq!(reply["lookup"]["state"], authority["native_state"]);
    assert_eq!(reply["lookup"]["reason"], authority["native_reason"]);
    assert_eq!(
        reply["lookup"]["evidence"]["engine"],
        instrument["engine_instance"]
    );
    (authority, lookup)
}

fn assert_identity(
    harness: &Harness,
    capture: &CaptureState,
    step: &RunStep,
    role: &str,
    subject: &str,
) {
    assert_eq!(step.step.as_str(), format!("round.1.{role}"));
    assert_eq!(step.effects, Some(Effect::Observed));
    let [flow] = step.flows.as_slice() else {
        panic!("expected exactly one identity flow");
    };
    let id = flow.flow_id.unwrap();
    assert_eq!(
        step.instrument_reference.as_ref().unwrap().as_str(),
        format!("flow:{id}")
    );
    assert_eq!(flow.completeness, Completeness::Complete);
    let key = format!("r1-s{}-request-{id}", step.number);
    let (original, bytes) = original(harness, capture, &key);
    assert_eq!(flow.original.as_ref(), Some(&original.artifact));
    let native = decode_retained_flow(&bytes, id).unwrap();
    assert_eq!(native.method.as_deref(), Some("GET"));
    assert_eq!(
        native.url.as_deref(),
        Some(format!("{}/app/api/me", harness.runtime.origin.as_str()).as_str())
    );
    assert_eq!(native.status, Some(200));
    let identity: Value = serde_json::from_slice(&native.retained_response().body).unwrap();
    assert_eq!(identity["id"], subject);
}

fn capture_loss(teapot_path: &Path, investigation: &Path) {
    let target = OwnedTarget::start();
    let mut project = PinnedProject::new(teapot_path, target.server.address());
    project.start();
    project.provision_sessions(target.server.origin());
    project.stop();
    // Use Teapot's real capture failure state with a bound confined to this
    // disposable project. This consumes no disk space to induce the failure.
    project.run(&["config", "set", "budget.min-free-mib", "1099511627776"]);
    let (teapot, engine) = project.start();
    let mut harness = open_harness(&project, &target.server, investigation, teapot, engine);
    let status = project.run(&["proxy", "status"]);
    assert_eq!(
        status["proxy"]["health"]["capture"]["state"],
        "capture-failed"
    );
    let before = target.request_count();
    let floor = harness.teapot.passive().highest_flow_id().unwrap();
    assert!(
        floor.is_some(),
        "setup captured flows that could be borrowed"
    );
    let case = declare(&mut harness, "capture-loss-refused-by-admission");
    assert!(matches!(
        harness.execute(&case),
        Err(PreflightError::Gate(refusal))
            if refusal.reason == scourge_core::teapot::GateRefusalReason::EditableConfiguration
    ));
    assert!(
        harness
            .store
            .recover_run(&case.run.id)
            .unwrap()
            .steps
            .is_empty()
    );
    target.assert_traffic(before, &[]);

    // Referenced dispatch needs the store writer to admit the caller
    // reference. Qualify the uncaptured send on the native adapter itself.
    let url: WireText = format!("{}/app/api/orders", target.server.origin().as_str())
        .try_into()
        .unwrap();
    let sent = harness
        .teapot
        .send(
            Method::Post,
            &url,
            &"alice_verify".parse().unwrap(),
            SendOptions {
                headers: &["Content-Type: application/json".to_owned()],
                body: Some(r#"{"note":"owned fixture capture loss"}"#),
                ..SendOptions::default()
            },
        )
        .unwrap();
    assert_eq!(sent.value.status, Some(201));
    let dispatch = sent.value.dispatch();
    assert_eq!(
        dispatch,
        DispatchEvidence::NoFlow {
            outcome: SendOutcome::Complete
        }
    );
    assert!(dispatch.was_sent());
    assert!(!dispatch.is_not_sent());
    assert!(sent.value.flow.is_none());
    assert_eq!(harness.teapot.passive().highest_flow_id().unwrap(), floor);
    let after = project.run(&["proxy", "status"]);
    let before_capture = &status["proxy"]["health"]["capture"];
    let after_capture = &after["proxy"]["health"]["capture"];
    assert_eq!(after_capture["state"], "capture-failed");
    assert_eq!(
        after_capture["flows_not_captured"].as_u64().unwrap(),
        before_capture["flows_not_captured"].as_u64().unwrap() + 1
    );
    target.assert_traffic(0, &["POST /app/login", "POST /app/login", PLANT]);
    target.assert_traffic(before, &[PLANT]);
    assert_eq!(target.fixture.order_count(), 1);
    println!(
        "capture-loss: native_capture=capture-failed dispatch=sent:no-flow status=201 retained_flow_floor={} native_original_sha256={} traffic={:?} orders_delta=1 verifier_traffic=0",
        floor.unwrap(),
        Sha256Digest::of(sent.evidence.stdout()).as_str(),
        [PLANT],
    );
}

fn pre_dispatch_refusal(teapot_path: &Path, investigation: &Path) {
    let target = OwnedTarget::start();
    let project = PinnedProject::new(teapot_path, target.server.address());
    let (project, mut harness) = start_harness(project, &target.server, investigation);
    project.run(&["scope", "clear", "--yes"]);
    let before = target.request_count();
    let floor = harness.teapot.passive().highest_flow_id().unwrap();
    let case = declare(&mut harness, "pre-dispatch-refusal");
    let (accepted, failure, retained) = failed_execution(&mut harness, &case);
    native_error(&failure, 4, "out-of-scope");
    let run = harness.store.recover_run(&case.run.id).unwrap();
    let [step] = run.steps.as_slice() else {
        panic!("expected only the refused first step");
    };
    assert_eq!(step.step.as_str(), "round.1.I1");
    assert_eq!(step.effects, Some(Effect::Unknown));
    assert!(step.flows.is_empty());

    let refusal = retained
        .attachments
        .iter()
        .filter(|item| item.key.starts_with("pre-dispatch-refusal-"))
        .collect::<Vec<_>>();
    let [refusal] = refusal.as_slice() else {
        panic!("expected one authoritative native refusal original");
    };
    let (_, bytes) = original(&harness, &retained, &refusal.key);
    let authority: Value = serde_json::from_slice(&bytes).unwrap();
    let receipt_digest = authority["receipt_digest"].as_str().unwrap();
    assert_eq!(
        step.instrument_reference.as_ref().unwrap().as_str(),
        format!("refusal:{receipt_digest}")
    );
    assert_eq!(authority["run_id"], case.run.id.as_str());
    assert_eq!(authority["request_key"], case.run.request_key.as_str());
    assert_eq!(authority["step_number"], step.number);
    assert_eq!(authority["step"], step.step.as_str());
    assert_eq!(authority["request_digest"], step.request_digest.as_str());
    assert_eq!(authority["action_index"], 1);
    assert_eq!(authority["target"]["method"], "GET");
    assert_eq!(
        authority["target"]["url"],
        format!("{}/app/api/me", target.server.origin().as_str())
    );
    assert_eq!(authority["target"]["session"], "alice_verify");
    for boundary in ["start", "end"] {
        let (observation, _) = original(&harness, &retained, &format!("edit-surface-{boundary}"));
        assert_eq!(
            authority[format!("{boundary}_observation_digest")],
            observation.artifact.digest.as_str(),
        );
    }
    let reference = authority["reference"].as_str().unwrap();
    assert_eq!(refusal.key, format!("pre-dispatch-refusal-{reference}"));
    let native = project.command(&["requests", "lookup", reference]);
    assert!(native.status.success());
    let lookup = STANDARD
        .decode(authority["lookup_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        lookup, native.stdout,
        "Investigation retained the exact native lookup bytes"
    );
    let reply: Value = serde_json::from_slice(&lookup).unwrap();
    let lookup = &reply["lookup"];
    assert_eq!(lookup["ref"], reference);
    assert_eq!(lookup["state"], "refused");
    assert_eq!(lookup["reason"], "out-of-scope");
    assert_eq!(lookup["flows"], json!([]));
    assert_eq!(lookup["evidence"]["dispatching_at"], Value::Null);
    assert_eq!(lookup["evidence"]["dial"], "not-started");
    assert_eq!(lookup["evidence"]["units_admitted"], 0);
    assert_eq!(
        lookup["evidence"]["engine"],
        harness.runtime.engine.instance.as_str()
    );
    assert_eq!(
        lookup["accounting"]["units"],
        json!({"charged": 0, "used": 0, "unused": 0})
    );

    // A distinct Investigation case cannot authorize the receipt. Check
    // before reconciliation in the real case so no prior result can bias it.
    let other = open_harness(
        &project,
        &target.server,
        investigation,
        Teapot::from_runtime(&harness.runtime).unwrap(),
        harness.runtime.engine.clone(),
    );
    let without_authority = harness
        .store
        .reconcile_run_with_evidence(
            &harness.scope,
            &case.run.id,
            &other.evidence,
            &harness.teapot,
        )
        .unwrap();
    assert_eq!(without_authority.effects, Effect::Unknown);
    assert_eq!(without_authority.acceptance.run.steps, run.steps);
    assert!(harness.store.conflicts_held(&case.run.id).unwrap());

    let reconciled = assert_recovery(&mut harness, &case, &accepted, &retained, Effect::None);
    assert_eq!(reconciled.steps[0].effects, Some(Effect::None));
    assert_eq!(reconciled.steps[0].request_digest, step.request_digest);
    assert_eq!(
        reconciled.steps[0].instrument_reference,
        step.instrument_reference
    );
    assert_eq!(reconciled.steps[0].flow_id_floor, floor);
    assert!(reconciled.steps[0].flows.is_empty());
    assert!(!harness.store.conflicts_held(&case.run.id).unwrap());
    assert!(matches!(
        harness.execute(&case),
        Err(PreflightError::Replay)
    ));
    assert_eq!(harness.teapot.passive().highest_flow_id().unwrap(), floor);
    target.assert_traffic(0, &["POST /app/login", "POST /app/login"]);
    target.assert_traffic(before, &[]);
    println!(
        "pre-dispatch-refusal: run={} key={} capture={} digest={} authority_sha256={} ref={} native_exit=4 reason=out-of-scope traffic=0 effects=none",
        case.run.id.as_str(),
        case.run.request_key.as_str(),
        retained.capture.handle.as_str(),
        step.request_digest.as_str(),
        refusal.digest.as_str(),
        reference,
    );
}
