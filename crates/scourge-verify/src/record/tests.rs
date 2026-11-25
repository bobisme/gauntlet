use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use scourge_core::{
    canonical::Sha256Digest,
    domain::{CleanupObjectOutcome, CleanupObjectRole, CleanupOwnership, RunCleanup},
    ids::EngagementId,
    rounds::{AcquiredFlow, AcquiredIdentity, AcquiredRound, Canary, PlantedCanary, RoundFlow},
    template::{
        DecodeLimits as TemplateDecodeLimits, DecoderBinding, EngagementBinding, FrozenExperiment,
        PropertyBinding, SlotBinding,
    },
    wire::{
        AccountingV1, AccountingV1Tag, Artifact, Attribution, Cleanup, Completeness, Custody,
        Effect, Enforcement, EnvironmentKind, ErrorCode, Exposure, Instrument, OracleResult,
        Profile, RequestInputV1, SlotSource, Strength, Target, TargetIsolation, Timestamp,
        Verifier, VersionedDigest, VersionedId, Window,
    },
};

use super::*;

const PRIMARY: &str = "0123456789abcdef0123456789abcdef";
const CONTROL: &str = "fedcba9876543210fedcba9876543210";

#[derive(Default)]
struct FakeEvidence {
    bytes: RefCell<HashMap<String, Vec<u8>>>,
    inputs: RefCell<HashMap<String, Vec<Artifact>>>,
}

impl FakeEvidence {
    fn insert(&self, id: &str, bytes: Vec<u8>) -> Artifact {
        let artifact = Artifact {
            artifact_id: id.parse().unwrap(),
            digest: Sha256Digest::of(&bytes),
        };
        self.bytes.borrow_mut().insert(id.to_owned(), bytes);
        self.inputs.borrow_mut().entry(id.to_owned()).or_default();
        artifact
    }
}

impl RecordEvidence for FakeEvidence {
    fn store(&self, key: &str, bytes: &[u8], inputs: &[Artifact]) -> Result<Artifact, RecordError> {
        for input in inputs {
            let retained = self
                .bytes
                .borrow()
                .get(input.artifact_id.as_str())
                .cloned()
                .ok_or(RecordError::MissingOriginal)?;
            if Sha256Digest::of(&retained) != input.digest {
                return Err(RecordError::DigestMismatch);
            }
        }
        let artifact = self.insert(&format!("art_record_{}", &key[2..]), bytes.to_vec());
        self.inputs
            .borrow_mut()
            .insert(artifact.artifact_id.as_str().to_owned(), inputs.to_vec());
        Ok(artifact)
    }

    fn read(&self, artifact: &Artifact) -> Result<EvidenceRead, RecordError> {
        let bytes = self
            .bytes
            .borrow()
            .get(artifact.artifact_id.as_str())
            .cloned()
            .ok_or(RecordError::MissingOriginal)?;
        let inputs = self
            .inputs
            .borrow()
            .get(artifact.artifact_id.as_str())
            .cloned()
            .ok_or(RecordError::MissingOriginal)?;
        Ok(EvidenceRead { bytes, inputs })
    }
}

struct Fixture {
    evidence: FakeEvidence,
    run: RunId,
    engagement: EngagementId,
    experiment: FrozenExperiment,
    experiment_digest: Sha256Digest,
    experiment_artifact: Artifact,
    rounds: Vec<AcquiredRound>,
    retained: Vec<Artifact>,
    accounting: AccountingV1,
    cleanup: Cleanup,
}

impl Fixture {
    fn acquisition(&self) -> Acquisition<'_> {
        Acquisition {
            run: &self.run,
            engagement: &self.engagement,
            experiment: &self.experiment,
            experiment_digest: &self.experiment_digest,
            experiment_artifact: &self.experiment_artifact,
            rounds: &self.rounds,
            retained: self.retained.clone(),
            accounting: &self.accounting,
            cleanup: self.cleanup,
        }
    }
}

#[derive(Clone, Copy)]
enum F2Case {
    True,
    False,
    Partial,
    Missing,
    MalformedRetained,
    RetainedMismatch,
}

fn fixture(case: F2Case) -> Fixture {
    let evidence = FakeEvidence::default();
    let run: RunId = "R-record-test".parse().unwrap();
    let engagement: EngagementId = "record-test".parse().unwrap();
    let experiment = experiment();
    let (experiment_bytes, experiment_digest) = experiment.freeze().unwrap();
    let experiment_artifact = evidence.insert("art_experiment", experiment_bytes);
    let mut retained = Vec::new();
    let mut flows = Vec::new();
    for (index, contract) in RoundFlow::REQUIRED.into_iter().enumerate() {
        let id = index as u64 + 1;
        let (live_body, retained_body, completeness, original) = match contract {
            RoundFlow::I1 | RoundFlow::I3 => (
                json_body("alice"),
                json_body("alice"),
                Completeness::Complete,
                true,
            ),
            RoundFlow::I2 | RoundFlow::I4 => (
                json_body("bob"),
                json_body("bob"),
                Completeness::Complete,
                true,
            ),
            RoundFlow::P => (
                plant_body("primary", PRIMARY),
                plant_body("primary", PRIMARY),
                Completeness::Complete,
                true,
            ),
            RoundFlow::P2 => (
                plant_body("control", CONTROL),
                plant_body("control", CONTROL),
                Completeness::Complete,
                true,
            ),
            RoundFlow::F0 | RoundFlow::F3 | RoundFlow::C => {
                (b"{}".to_vec(), b"{}".to_vec(), Completeness::Complete, true)
            }
            RoundFlow::F1 => (
                plant_body("primary", PRIMARY),
                plant_body("primary", PRIMARY),
                Completeness::Complete,
                true,
            ),
            RoundFlow::F4 => (
                plant_body("control", CONTROL),
                plant_body("control", CONTROL),
                Completeness::Complete,
                true,
            ),
            RoundFlow::F2 => match case {
                F2Case::True => (
                    plant_body("primary", PRIMARY),
                    plant_body("primary", PRIMARY),
                    Completeness::Complete,
                    true,
                ),
                F2Case::False => (b"{}".to_vec(), b"{}".to_vec(), Completeness::Complete, true),
                F2Case::Partial => (
                    plant_body("primary", PRIMARY),
                    plant_body("primary", PRIMARY),
                    Completeness::Partial,
                    true,
                ),
                F2Case::Missing => (Vec::new(), Vec::new(), Completeness::Missing, false),
                F2Case::MalformedRetained => (
                    plant_body("primary", PRIMARY),
                    b"not json".to_vec(),
                    Completeness::Complete,
                    true,
                ),
                F2Case::RetainedMismatch => (
                    plant_body("primary", PRIMARY),
                    b"{}".to_vec(),
                    Completeness::Complete,
                    true,
                ),
            },
        };
        let artifact = original.then(|| {
            let bytes = if matches!(case, F2Case::MalformedRetained) && contract == RoundFlow::F2 {
                retained_body.clone()
            } else {
                retained_flow(id, &retained_body, completeness)
            };
            let artifact = evidence.insert(&format!("art_flow_{id}"), bytes);
            retained.push(artifact.clone());
            artifact
        });
        flows.push(AcquiredFlow {
            contract,
            sequence: id,
            reference: scourge_core::wire::Flow {
                step: if contract == RoundFlow::C {
                    "C.primary.request".parse().unwrap()
                } else {
                    format!("{}.request", contract.as_str()).try_into().unwrap()
                },
                flow_id: original.then_some(id),
                original: artifact,
                completeness,
                decoder: None,
            },
            response_body: live_body,
        });
    }
    let control_cleanup_id = 13;
    let control_cleanup_body = b"{}".to_vec();
    let control_cleanup_artifact = evidence.insert(
        "art_flow_13",
        retained_flow(
            control_cleanup_id,
            &control_cleanup_body,
            Completeness::Complete,
        ),
    );
    retained.push(control_cleanup_artifact.clone());
    flows.push(AcquiredFlow {
        contract: RoundFlow::C,
        sequence: control_cleanup_id,
        reference: scourge_core::wire::Flow {
            step: "C.control.request".parse().unwrap(),
            flow_id: Some(control_cleanup_id),
            original: Some(control_cleanup_artifact),
            completeness: Completeness::Complete,
            decoder: None,
        },
        response_body: control_cleanup_body,
    });
    let primary_cleanup_flow = flows
        .iter()
        .find(|flow| flow.reference.step.as_str() == "C.primary.request")
        .unwrap()
        .reference
        .clone();
    let control_cleanup_flow = flows
        .iter()
        .find(|flow| flow.reference.step.as_str() == "C.control.request")
        .unwrap()
        .reference
        .clone();
    let round = AcquiredRound {
        number: 1,
        primary: vec![PlantedCanary {
            field: "label".to_owned().try_into().unwrap(),
            canary: Canary::parse(PRIMARY).unwrap(),
        }],
        control: vec![PlantedCanary {
            field: "label".to_owned().try_into().unwrap(),
            canary: Canary::parse(CONTROL).unwrap(),
        }],
        flows,
        identities: vec![
            identity(RoundFlow::I1, "alice"),
            identity(RoundFlow::I2, "bob"),
            identity(RoundFlow::I3, "alice"),
            identity(RoundFlow::I4, "bob"),
        ],
        cleanup: vec![
            completed_cleanup(CleanupObjectRole::Primary, "primary", primary_cleanup_flow),
            completed_cleanup(CleanupObjectRole::Control, "control", control_cleanup_flow),
        ],
    };
    Fixture {
        evidence,
        run,
        engagement,
        experiment,
        experiment_digest,
        experiment_artifact,
        rounds: vec![round],
        retained,
        accounting: accounting(),
        cleanup: Cleanup::Complete,
    }
}

fn completed_cleanup(
    object: CleanupObjectRole,
    object_id: &str,
    flow: scourge_core::wire::Flow,
) -> RunCleanup {
    RunCleanup {
        round: 1,
        object,
        plant_step: match object {
            CleanupObjectRole::Primary => 3,
            CleanupObjectRole::Control => 4,
        },
        plant_request_digest: Sha256Digest::of(format!("plant-{object_id}").as_bytes()),
        object_id: Some(object_id.parse().unwrap()),
        ownership: CleanupOwnership::Established,
        cleanup_step: Some(12),
        cleanup_request_digest: Some(Sha256Digest::of(format!("cleanup-{object_id}").as_bytes())),
        flow_id_floor: Some(11),
        instrument_reference: Some(format!("send-{object_id}").parse().unwrap()),
        effects: Some(Effect::Observed),
        response_status: Some(204),
        flows: vec![flow],
        outcome: CleanupObjectOutcome::Complete,
    }
}

fn experiment() -> FrozenExperiment {
    let value: WireText = "owner-principal".to_owned().try_into().unwrap();
    FrozenExperiment {
        template: VersionedId {
            id: "web-authz/private-object-read"
                .to_owned()
                .try_into()
                .unwrap(),
            version: "1".to_owned().try_into().unwrap(),
        },
        engagement: EngagementBinding {
            revision: 3,
            digest: Sha256Digest::of(b"engagement"),
        },
        property: Some(PropertyBinding {
            label: "orders".parse().unwrap(),
            resource: "resource.orders".parse().unwrap(),
            digest: Sha256Digest::of(b"orders property"),
        }),
        slots: BTreeMap::from([(
            "owner".parse().unwrap(),
            SlotBinding {
                value: value.clone(),
                source: SlotSource::Engagement,
                supplied_by: "operator".to_owned().try_into().unwrap(),
                digest: Sha256Digest::of(value.as_str().as_bytes()),
            },
        )]),
        principals: BTreeMap::new(),
        oracle: VersionedDigest {
            id: registry::ORACLE_ID.to_owned().try_into().unwrap(),
            version: registry::ORACLE_VERSION.to_owned().try_into().unwrap(),
            digest: registry::oracle_digest(),
        },
        decoder: DecoderBinding {
            identity: VersionedId {
                id: "http-body".to_owned().try_into().unwrap(),
                version: "1".to_owned().try_into().unwrap(),
            },
            limits: TemplateDecodeLimits::DEFAULT,
        },
        effects: Vec::new(),
    }
}

fn identity(contract: RoundFlow, subject: &str) -> AcquiredIdentity {
    AcquiredIdentity {
        contract,
        subject_digest: Some(Sha256Digest::of(subject.as_bytes())),
    }
}

fn json_body(subject: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"id": subject})).unwrap()
}

fn plant_body(id: &str, canary: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"id": id, "label": canary})).unwrap()
}

fn retained_flow(id: u64, body: &[u8], completeness: Completeness) -> Vec<u8> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/contracts/read-flow.json"
    ))
    .unwrap();
    let mut output = fixture["output"].clone();
    output["flow"]["id"] = id.into();
    output["flow"]["response_body_base64"] = STANDARD.encode(body).into();
    let info = &mut output["flow"]["response_body_info"];
    info["capture"] = match completeness {
        Completeness::Complete => "complete",
        Completeness::Partial => "partial",
        Completeness::Missing | Completeness::Corrupt => "none",
    }
    .into();
    info["captured"] = (body.len() as u64).into();
    info["observed"] = (body.len() as u64).into();
    info["shown"] = (body.len() as u64).into();
    info["whole"] = (completeness == Completeness::Complete).into();
    serde_json::to_vec(&output).unwrap()
}

fn accounting() -> AccountingV1 {
    AccountingV1 {
        schema: AccountingV1Tag::AccountingV1,
        pass_id: None,
        pass_digest: None,
        instrument_job_ids: Vec::new(),
        window: Window {
            start: timestamp("2026-11-24T00:00:00Z"),
            end: timestamp("2026-11-24T00:00:02Z"),
        },
        dry_run_ceiling: None,
        counters_before: None,
        counters_after: None,
        ledger_debits: Vec::new(),
        held_before: None,
        held_after: None,
        requested: None,
        admitted: None,
        observed_sent: None,
        charged: None,
        attribution: Attribution::Unestablished,
        attribution_evidence: Vec::new(),
    }
}

fn context() -> VerificationContext {
    VerificationContext {
        sequence: 1,
        prev_record_digest: None,
        lead_id: "L-record-test".parse().unwrap(),
        lead_revision: 4,
        policy_rule: None,
        profile: Profile::RuntimeControlledV1,
        target: Target {
            origin: "http://fixture.invalid".to_owned().try_into().unwrap(),
            addresses: vec!["192.0.2.10".to_owned().try_into().unwrap()],
            tls_identity: None,
            deployment_marker: None,
            strength: Strength::RemotelyObserved,
        },
        environment_kind: EnvironmentKind::Simulated,
        custody: Custody::Shared,
        target_isolation: TargetIsolation::SeparatePrincipals,
        enforcement: Enforcement::Unenforced,
        destination_time_enforced: true,
        request_ceiling_enforced: true,
        edit_surface_start: Vec::new(),
        edit_surface_end: Vec::new(),
        effects: Effect::Observed,
        instrument: Instrument {
            name: "teapot".to_owned().try_into().unwrap(),
            version: "0.1.0".to_owned().try_into().unwrap(),
            commit: None,
            binary_digest: None,
            engine_instance: "engine-test".to_owned().try_into().unwrap(),
            project_id: "project-test".to_owned().try_into().unwrap(),
            protocol: 1,
        },
        verifier: Verifier {
            version: env!("CARGO_PKG_VERSION").to_owned().try_into().unwrap(),
            commit: None,
            binary_digest: Sha256Digest::of(b"test verifier"),
        },
        started_at: timestamp("2026-11-24T00:00:00Z"),
        finished_at: timestamp("2026-11-24T00:00:02Z"),
    }
}

fn timestamp(value: &str) -> Timestamp {
    value.parse().unwrap()
}

#[test]
fn exact_record_stores_reads_and_reevaluates_from_originals() {
    let fixture = fixture(F2Case::True);
    let stored =
        evaluate_and_store_with(&fixture.evidence, fixture.acquisition(), context()).unwrap();

    assert_eq!(stored.record.result, OracleResult::True);
    assert_eq!(stored.record.exposure, Some(Exposure::CrossPrincipal));
    assert_eq!(stored.disposition.error, None);
    assert_eq!(stored.disposition.exit_code, 0);
    assert_eq!(stored.record.accounting, fixture.accounting);
    assert_eq!(stored.record.experiment_digest, fixture.experiment_digest);
    assert_eq!(stored.record.cleanup, Cleanup::Complete);
    assert_eq!(stored.record.rounds[0].flows.len(), 13);
    assert_eq!(stored.record.rounds[0].identities.len(), 4);
    assert_eq!(
        stored.record.limitations.len(),
        registry::KNOWN_MISSES.len()
    );
    assert_eq!(
        reevaluate_record(
            &fixture.evidence,
            &stored.record,
            &read_record(&fixture.evidence, &stored.artifact)
                .unwrap()
                .inputs,
        )
        .unwrap()
        .summary
        .result,
        OracleResult::True
    );
    assert!(
        fixture
            .evidence
            .bytes
            .borrow()
            .contains_key(stored.artifact.artifact_id.as_str())
    );
}

#[test]
fn lost_cleanup_response_preserves_true_and_records_unknown_without_a_receipt() {
    let mut fixture = fixture(F2Case::True);
    fixture.rounds[0]
        .flows
        .retain(|flow| flow.contract != RoundFlow::C);
    fixture
        .retained
        .retain(|artifact| !matches!(artifact.artifact_id.as_str(), "art_flow_12" | "art_flow_13"));
    let [primary, control] = fixture.rounds[0].cleanup.as_mut_slice() else {
        panic!("fixture has one cleanup row per object");
    };
    primary.flows.clear();
    primary.effects = Some(Effect::Unknown);
    primary.response_status = None;
    primary.outcome = CleanupObjectOutcome::Unknown;
    control.flows.clear();
    control.instrument_reference = None;
    control.effects = None;
    control.response_status = None;
    control.outcome = CleanupObjectOutcome::Owed;
    fixture.cleanup = Cleanup::Unknown;

    let stored =
        evaluate_and_store_with(&fixture.evidence, fixture.acquisition(), context()).unwrap();

    assert_eq!(stored.record.result, OracleResult::True);
    assert_eq!(stored.record.cleanup, Cleanup::Unknown);
    assert_eq!(
        fixture.rounds[0]
            .cleanup
            .iter()
            .map(|cleanup| cleanup.outcome)
            .collect::<Vec<_>>(),
        [CleanupObjectOutcome::Unknown, CleanupObjectOutcome::Owed]
    );
    assert!(
        stored.record.rounds[0]
            .flows
            .iter()
            .all(|flow| !flow.step.as_str().starts_with("C.")),
        "a lost response must not invent a C flow receipt"
    );
    let lineage = read_record(&fixture.evidence, &stored.artifact)
        .unwrap()
        .inputs;
    assert!(lineage.iter().all(|artifact| {
        !matches!(artifact.artifact_id.as_str(), "art_flow_12" | "art_flow_13")
    }));
}

#[test]
fn instrument_crash_and_oracle_panic_are_error_exit_seven() {
    let instrument = evaluate_instrument::<(), _>(Err("crash"), |_| unreachable!());
    assert_eq!(instrument.result, Verdict::Error);
    assert_eq!(instrument.fault, Some(FaultCause::InstrumentUnavailable));

    let oracle = evaluate_instrument::<(), ()>(Ok(()), |_| panic!("oracle panic"));
    assert_eq!(oracle.result, Verdict::Error);
    assert_eq!(oracle.fault, Some(FaultCause::OraclePanic));
    let mapped = disposition(oracle.result.into(), &[]);
    assert_eq!(mapped.error, Some(ErrorCode::DependencyUnavailable));
    assert_eq!(mapped.exit_code, 7);
}

#[test]
fn incomplete_and_missing_originals_stay_invalid() {
    for case in [F2Case::Partial, F2Case::Missing] {
        let fixture = fixture(case);
        let stored =
            evaluate_and_store_with(&fixture.evidence, fixture.acquisition(), context()).unwrap();
        assert_eq!(stored.record.result, OracleResult::Invalid);
        assert_eq!(stored.record.rounds[0].result, OracleResult::Invalid);
        assert_eq!(
            stored.record.rounds[0].reason_codes[0].as_str(),
            "EVIDENCE_INCOMPLETE"
        );
        assert_eq!(
            stored.disposition.error,
            Some(ErrorCode::EvidenceIncomplete)
        );
        assert_eq!(stored.disposition.exit_code, 5);
    }
}

#[test]
fn malformed_and_changed_retained_originals_never_promote() {
    let malformed = fixture(F2Case::MalformedRetained);
    let error = evaluate_and_store_with(&malformed.evidence, malformed.acquisition(), context())
        .unwrap_err();
    assert!(matches!(error, RecordError::MalformedOriginal));
    assert_eq!(error.code(), ErrorCode::IntegrityFailure);
    assert_eq!(error.exit_code(), 6);

    let changed = fixture(F2Case::RetainedMismatch);
    let error =
        evaluate_and_store_with(&changed.evidence, changed.acquisition(), context()).unwrap_err();
    assert!(matches!(error, RecordError::ReevaluationMismatch));
    assert_eq!(error.exit_code(), 6);
}

#[test]
fn foreign_run_artifact_is_rejected_before_recording() {
    let mut fixture = fixture(F2Case::True);
    fixture.retained.pop();
    let error =
        evaluate_and_store_with(&fixture.evidence, fixture.acquisition(), context()).unwrap_err();
    assert!(matches!(error, RecordError::ForeignRunEvidence));
    assert_eq!(error.exit_code(), 6);
}

#[test]
fn caller_cannot_inject_observations_result_or_record() {
    let bytes = br#"{"schema":"scourge.request-input.v1","command":"verify","arguments":{"lead_id":"L-1","lead_revision":null,"engagement_revision":null,"rounds":1,"observations":[],"result":"true","record":{}}}"#;
    assert!(RequestInputV1::read(bytes).is_err());

    let _: fn(
        &Evidence,
        &ExecutedRounds,
        VerificationContext,
    ) -> Result<StoredVerification, RecordError> = evaluate_and_store;
}

#[test]
fn evaluation_and_storage_open_no_network_connection_and_sink_is_live() {
    let fixture = fixture(F2Case::True);
    evaluate_and_store_with(&fixture.evidence, fixture.acquisition(), context()).unwrap();

    // This module is the offline sink boundary: it can read/store Evidence but
    // cannot receive a URL, Teapot handle or socket. Keep the lexical detector
    // non-vacuous with a positive probe because CI sandboxes deny socket(2).
    fn network_sinks(source: &str) -> usize {
        ["TcpStream::connect", "UdpSocket::bind", "teapot.send("]
            .iter()
            .map(|needle| source.matches(needle).count())
            .sum()
    }
    let source = include_str!("../record.rs");
    assert_eq!(network_sinks(source), 0);
    assert_eq!(network_sinks("TcpStream::connect(target)"), 1);
}

#[test]
fn retained_original_reevaluation_is_non_vacuous() {
    let true_fixture = fixture(F2Case::True);
    let true_record = evaluate_and_store_with(
        &true_fixture.evidence,
        true_fixture.acquisition(),
        context(),
    )
    .unwrap();
    let false_fixture = fixture(F2Case::False);
    let false_record = evaluate_and_store_with(
        &false_fixture.evidence,
        false_fixture.acquisition(),
        context(),
    )
    .unwrap();
    assert_eq!(true_record.record.result, OracleResult::True);
    assert_eq!(false_record.record.result, OracleResult::False);
    assert_ne!(true_record.artifact.digest, false_record.artifact.digest);
}

#[test]
fn foreign_run_observation_is_invalid_not_false() {
    let fixture = fixture(F2Case::True);
    let mut observations =
        observations_from_acquired(&fixture.run, &fixture.experiment, &fixture.rounds[0]).unwrap();
    observations.flows[6].run = "R-foreign".parse().unwrap();
    let evaluation = evaluate(&observations);
    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(evaluation.reason_codes[0].as_str(), "EVIDENCE_INCOMPLETE");
}

#[test]
fn frozen_reason_and_exit_mapping_is_closed() {
    let same_subject = vec!["SAME_SUBJECT".parse().unwrap()];
    let identity = disposition(OracleResult::Invalid, &same_subject);
    assert_eq!(identity.error, Some(ErrorCode::IdentityUnestablished));
    assert_eq!(identity.exit_code, 5);

    let incomplete = vec!["EVIDENCE_INCOMPLETE".parse().unwrap()];
    let evidence = disposition(OracleResult::Invalid, &incomplete);
    assert_eq!(evidence.error, Some(ErrorCode::EvidenceIncomplete));
    assert_eq!(evidence.exit_code, 5);
}
