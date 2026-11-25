use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use scourge_core::{
    canonical::Sha256Digest,
    domain::{
        CleanupObjectOutcome, CleanupObjectRole, CleanupOwnership, LeadOrigin, LeadRevision, Run,
        RunCleanup,
    },
    ids::EngagementId,
    rounds::{AcquiredFlow, AcquiredIdentity, AcquiredRound, Canary, PlantedCanary, RoundFlow},
    store::{Store, StoreError},
    template::{
        DecodeLimits as TemplateDecodeLimits, DecoderBinding, EngagementBinding, FrozenExperiment,
        PropertyBinding, SlotBinding,
    },
    wire::{
        AccountingV1, AccountingV1Tag, Artifact, Attribution, Cleanup, Completeness, Custody,
        Effect, Enforcement, EnvironmentKind, ErrorCode, Exposure, Instrument, OracleResult,
        Profile, RequestInputV1, RunState, SlotSource, Strength, Target, TargetIsolation,
        Timestamp, Verifier, VersionedDigest, VersionedId, Window,
    },
};

use super::*;

const PRIMARY: &str = "0123456789abcdef0123456789abcdef";
const CONTROL: &str = "fedcba9876543210fedcba9876543210";

#[derive(Clone, Default)]
struct FakeEvidence {
    bytes: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    inputs: Arc<Mutex<HashMap<String, Vec<Artifact>>>>,
    receipts: Arc<Mutex<HashMap<String, Artifact>>>,
}

impl FakeEvidence {
    fn insert(&self, id: &str, bytes: Vec<u8>) -> Artifact {
        let artifact = Artifact {
            artifact_id: id.parse().unwrap(),
            digest: Sha256Digest::of(&bytes),
        };
        self.bytes.lock().unwrap().insert(id.to_owned(), bytes);
        self.inputs
            .lock()
            .unwrap()
            .entry(id.to_owned())
            .or_default();
        artifact
    }
}

impl RecordEvidence for FakeEvidence {
    fn store(&self, key: &str, bytes: &[u8], inputs: &[Artifact]) -> Result<Artifact, RecordError> {
        if let Some(artifact) = self.receipts.lock().unwrap().get(key).cloned() {
            let retained = self
                .bytes
                .lock()
                .unwrap()
                .get(artifact.artifact_id.as_str())
                .cloned()
                .ok_or(RecordError::MissingOriginal)?;
            let lineage = self
                .inputs
                .lock()
                .unwrap()
                .get(artifact.artifact_id.as_str())
                .cloned()
                .ok_or(RecordError::MissingOriginal)?;
            if retained != bytes || lineage != inputs {
                return Err(RecordError::DigestMismatch);
            }
            return Ok(artifact);
        }
        for input in inputs {
            let retained = self
                .bytes
                .lock()
                .unwrap()
                .get(input.artifact_id.as_str())
                .cloned()
                .ok_or(RecordError::MissingOriginal)?;
            if Sha256Digest::of(&retained) != input.digest {
                return Err(RecordError::DigestMismatch);
            }
        }
        let artifact = self.insert(&format!("art_record_{}", &key[2..]), bytes.to_vec());
        self.inputs
            .lock()
            .unwrap()
            .insert(artifact.artifact_id.as_str().to_owned(), inputs.to_vec());
        self.receipts
            .lock()
            .unwrap()
            .insert(key.to_owned(), artifact.clone());
        Ok(artifact)
    }

    fn read(&self, artifact: &Artifact) -> Result<EvidenceRead, RecordError> {
        let bytes = self
            .bytes
            .lock()
            .unwrap()
            .get(artifact.artifact_id.as_str())
            .cloned()
            .ok_or(RecordError::MissingOriginal)?;
        let inputs = self
            .inputs
            .lock()
            .unwrap()
            .get(artifact.artifact_id.as_str())
            .cloned()
            .ok_or(RecordError::MissingOriginal)?;
        Ok(EvidenceRead {
            bytes,
            inputs,
            record_lineage: true,
        })
    }

    fn recover(&self, key: &str) -> Result<Option<Artifact>, RecordError> {
        Ok(self.receipts.lock().unwrap().get(key).cloned())
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

struct PublicationStore {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    store: Store,
}

fn publication_store(fixture: &Fixture, result: OracleResult) -> PublicationStore {
    publication_store_for(fixture, result, &fixture_manifest())
}

fn publication_store_for(
    fixture: &Fixture,
    result: OracleResult,
    manifest: &scourge_core::engagement::ManifestRevision,
) -> PublicationStore {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.sqlite3");
    let mut store = Store::open(&path).unwrap();
    let pass_digest = manifest.pass_digest().clone();
    let artifact = fixture
        .evidence
        .insert("art_manifest", manifest.canonical_bytes().to_vec());
    store
        .append_manifest(&fixture.engagement, &artifact, &pass_digest)
        .unwrap();
    for revision in 1..=4 {
        store
            .append_lead_revision(
                &fixture.engagement,
                &LeadRevision {
                    lead_id: "L-record-test".parse().unwrap(),
                    revision,
                    text: format!("record test revision {revision}")
                        .try_into()
                        .unwrap(),
                    class: None,
                    property: None,
                    slots: BTreeMap::new(),
                    proposed_policy: None,
                    origin: LeadOrigin::Local,
                    source_ref: None,
                    endpoint: None,
                    flow_ids: Vec::new(),
                    producer_confidence: None,
                },
            )
            .unwrap();
    }
    add_fixture_run(&mut store, fixture, result);
    PublicationStore {
        _directory: directory,
        path,
        store,
    }
}

fn add_fixture_run(store: &mut Store, fixture: &Fixture, result: OracleResult) {
    let mut run = Run::declare(
        fixture.engagement.clone(),
        fixture.experiment_digest.clone(),
    );
    run.id = fixture.run.clone();
    run.state = RunState::Finalized;
    run.oracle_result = Some(result);
    run.effects = Effect::Observed;
    run.cleanup = fixture.cleanup;
    store.record_run(&run, None).unwrap();
}

fn pending_publication(
    fixture: &Fixture,
    store: &mut Store,
) -> (PublicationIntentV1, PreparedVerification) {
    let (_, head) = store.checkpoint(&fixture.engagement).unwrap();
    let mut context = context();
    context.sequence = head.sequence + 1;
    context.prev_record_digest = head.record_digest.clone();
    let prepared =
        evaluate_and_prepare_with(&fixture.evidence, fixture.acquisition(), context).unwrap();
    let intent = PublicationIntentV1 {
        schema: PublicationIntentV1Tag::PublicationIntentV1,
        intent_id: PublicationIntentId::generate(),
        engagement: fixture.engagement.clone(),
        run_id: fixture.run.clone(),
        record_id: prepared.record.record_id.clone(),
        record_digest: Sha256Digest::of(&prepared.bytes),
        expected_head: head,
        state: PublicationState::Pending,
        artifact_id: None,
    };
    store
        .stage_publication(&intent, &prepared.bytes, &prepared.inputs)
        .unwrap();
    (intent, prepared)
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
                let request_body = matches!(contract, RoundFlow::P | RoundFlow::P2)
                    .then_some(live_body.as_slice())
                    .unwrap_or_default();
                retained_flow(id, request_body, &retained_body, completeness)
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
            response_head: None,
        });
    }
    let control_cleanup_id = 13;
    let control_cleanup_body = b"{}".to_vec();
    let control_cleanup_artifact = evidence.insert(
        "art_flow_13",
        retained_flow(
            control_cleanup_id,
            &[],
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
        response_head: None,
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

fn fixture_manifest() -> scourge_core::engagement::ManifestRevision {
    let draft = scourge_core::engagement::EngagementDraft::parse_toml(include_bytes!(
        "../../../../fixtures/target/schema-examples/engagement.toml"
    ))
    .unwrap();
    let pass_ref = "pass.development-fixture".parse().unwrap();
    let pass_digest = Sha256Digest::of(b"fixture pass");
    draft
        .accept(scourge_core::engagement::PassPin {
            reference: &pass_ref,
            digest: &pass_digest,
        })
        .unwrap()
}

fn experiment() -> FrozenExperiment {
    let value: WireText = "alice".to_owned().try_into().unwrap();
    let manifest = fixture_manifest();
    let label = "orders".parse().unwrap();
    let property_digest = Sha256Digest::of(
        &scourge_core::canonical::to_vec(manifest.properties().get(&label).unwrap()).unwrap(),
    );
    let principals = [("owner", "alice"), ("other", "bob")]
        .into_iter()
        .map(|(slot, label)| {
            let label = label.parse().unwrap();
            let principal = manifest.principals().get(&label).unwrap();
            (
                slot.parse().unwrap(),
                scourge_core::template::BoundPrincipal {
                    principal: label,
                    session: principal.session.clone(),
                    verifier_session: principal.verifier_session.clone(),
                    groups: principal.groups.clone(),
                    identity_probe: principal.identity_probe.clone(),
                },
            )
        })
        .collect();
    FrozenExperiment {
        template: VersionedId {
            id: "web-authz/private-object-read"
                .to_owned()
                .try_into()
                .unwrap(),
            version: "1".to_owned().try_into().unwrap(),
        },
        engagement: EngagementBinding {
            revision: 1,
            digest: manifest.digest().clone(),
        },
        property: Some(PropertyBinding {
            label: "orders".parse().unwrap(),
            resource: "resource.orders".parse().unwrap(),
            digest: property_digest,
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
        principals,
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

fn retained_flow(
    id: u64,
    request_body: &[u8],
    response_body: &[u8],
    completeness: Completeness,
) -> Vec<u8> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/contracts/read-flow.json"
    ))
    .unwrap();
    let mut output = fixture["output"].clone();
    output["flow"]["id"] = id.into();
    output["flow"]["request_body_base64"] = STANDARD.encode(request_body).into();
    let request_info = &mut output["flow"]["request_body_info"];
    request_info["capture"] = "complete".into();
    request_info["captured"] = (request_body.len() as u64).into();
    request_info["observed"] = (request_body.len() as u64).into();
    request_info["shown"] = (request_body.len() as u64).into();
    request_info["whole"] = true.into();
    output["flow"]["response_body_base64"] = STANDARD.encode(response_body).into();
    let info = &mut output["flow"]["response_body_info"];
    info["capture"] = match completeness {
        Completeness::Complete => "complete",
        Completeness::Partial => "partial",
        Completeness::Missing | Completeness::Corrupt => "none",
    }
    .into();
    info["captured"] = (response_body.len() as u64).into();
    info["observed"] = (response_body.len() as u64).into();
    info["shown"] = (response_body.len() as u64).into();
    info["whole"] = (completeness == Completeness::Complete).into();
    serde_json::to_vec(&output).unwrap()
}

#[test]
fn missing_identity_subject_reevaluates_only_with_a_recorded_missing_digest() {
    let original = Artifact {
        artifact_id: "art_missing_identity".parse().unwrap(),
        digest: Sha256Digest::of(b"missing identity"),
    };
    let mut recorded = Identity {
        principal: principal(RoundFlow::I3).parse().unwrap(),
        step: "I3".parse().unwrap(),
        subject_digest: None,
        original: Some(original.clone()),
    };
    let missing = br#"{"error":"authentication_required"}"#;
    assert_eq!(
        subject_from_body(missing, FlowId::I3, &original, Some(&recorded)).unwrap(),
        None
    );

    assert!(matches!(
        subject_from_body(br#"{"id":"alice"}"#, FlowId::I3, &original, Some(&recorded)),
        Err(RecordError::DigestMismatch)
    ));
    recorded.subject_digest = Some(Sha256Digest::of(b"alice"));
    assert!(matches!(
        subject_from_body(missing, FlowId::I3, &original, Some(&recorded)),
        Err(RecordError::DigestMismatch)
    ));
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
            .lock()
            .unwrap()
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
fn bounded_raw_reads_still_fail_closed_on_size_digest_and_lineage() {
    struct TooLargeEvidence;

    impl RecordEvidence for TooLargeEvidence {
        fn store(&self, _: &str, _: &[u8], _: &[Artifact]) -> Result<Artifact, RecordError> {
            unreachable!("the size failure is a read boundary")
        }

        fn read(&self, _: &Artifact) -> Result<EvidenceRead, RecordError> {
            Err(EvidenceError::TooLarge.into())
        }

        fn recover(&self, _: &str) -> Result<Option<Artifact>, RecordError> {
            Ok(None)
        }
    }

    let reference = Artifact {
        artifact_id: "art_oversized_record".parse().unwrap(),
        digest: Sha256Digest::of(b"oversized"),
    };
    assert!(matches!(
        read_record(&TooLargeEvidence, &reference),
        Err(RecordError::Evidence(EvidenceError::TooLarge))
    ));

    let digest_fixture = fixture(F2Case::True);
    let stored = evaluate_and_store_with(
        &digest_fixture.evidence,
        digest_fixture.acquisition(),
        context(),
    )
    .unwrap();
    digest_fixture
        .evidence
        .bytes
        .lock()
        .unwrap()
        .get_mut(stored.artifact.artifact_id.as_str())
        .unwrap()
        .push(b' ');
    assert!(matches!(
        read_record(&digest_fixture.evidence, &stored.artifact),
        Err(RecordError::DigestMismatch)
    ));

    let lineage_fixture = fixture(F2Case::True);
    let stored = evaluate_and_store_with(
        &lineage_fixture.evidence,
        lineage_fixture.acquisition(),
        context(),
    )
    .unwrap();
    lineage_fixture
        .evidence
        .inputs
        .lock()
        .unwrap()
        .get_mut(stored.artifact.artifact_id.as_str())
        .unwrap()
        .retain(|input| input.digest != lineage_fixture.experiment_digest);
    let retained = read_record(&lineage_fixture.evidence, &stored.artifact).unwrap();
    assert!(matches!(
        reevaluate_record(&lineage_fixture.evidence, &stored.record, &retained.inputs,),
        Err(RecordError::MissingOriginal)
    ));
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

    let _: fn(&Evidence, &mut Store, &RunId) -> Result<PublishedVerification, PublicationError> =
        reconcile_publication;
}

#[test]
fn f20_import_lookalikes_cannot_link_and_both_crash_windows_reconcile_original_intent() {
    let receipt_fixture = fixture(F2Case::False);
    let fixture = fixture(F2Case::True);
    let mut publication = publication_store(&fixture, OracleResult::True);
    let (intent, prepared) = pending_publication(&fixture, &mut publication.store);

    // A record-shaped imported artifact has bytes but no verifier receipt.
    fixture
        .evidence
        .insert("art_imported_lookalike", prepared.bytes.clone());
    // Even exact bytes and lineage under another receipt key cannot be linked.
    fixture
        .evidence
        .store("P-lookalike", &prepared.bytes, &prepared.inputs)
        .unwrap();
    assert!(
        fixture
            .evidence
            .recover(intent.intent_id.as_str())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        publication
            .store
            .checkpoint(&fixture.engagement)
            .unwrap()
            .1
            .sequence,
        0
    );

    // Crash after the atomic stage but before Investigation receives a record.
    // Reopen loses every in-memory PreparedVerification, yet reconciliation
    // retries the immutable bytes and ordered inputs under the original key.
    drop(publication.store);
    publication.store = Store::open(&publication.path).unwrap();
    let linked =
        reconcile_publication_with(&fixture.evidence, &mut publication.store, &fixture.run)
            .unwrap();
    assert_eq!(linked.publication.index.sequence, 1);
    assert_eq!(linked.publication.intent.state, PublicationState::Complete);
    let replay =
        reconcile_publication_with(&fixture.evidence, &mut publication.store, &fixture.run)
            .unwrap();
    assert_eq!(replay.publication.revision, linked.publication.revision);
    assert_eq!(replay.publication.index, linked.publication.index);

    // The other crash window, after Investigation commits but before the
    // coordination link, recovers the already-issued same-key receipt.
    let mut receipt_publication = publication_store(&receipt_fixture, OracleResult::False);
    let (receipt_intent, receipt_prepared) =
        pending_publication(&receipt_fixture, &mut receipt_publication.store);
    receipt_fixture
        .evidence
        .store(
            receipt_intent.intent_id.as_str(),
            &receipt_prepared.bytes,
            &receipt_prepared.inputs,
        )
        .unwrap();
    drop(receipt_publication.store);
    receipt_publication.store = Store::open(&receipt_publication.path).unwrap();
    let receipt_linked = reconcile_publication_with(
        &receipt_fixture.evidence,
        &mut receipt_publication.store,
        &receipt_fixture.run,
    )
    .unwrap();
    assert_eq!(
        receipt_linked.publication.intent.state,
        PublicationState::Complete
    );
}

#[test]
fn f20_two_concurrent_reconciliations_leave_one_record_head_and_receipt() {
    let fixture = fixture(F2Case::True);
    let mut publication = publication_store(&fixture, OracleResult::True);
    let (intent, _prepared) = pending_publication(&fixture, &mut publication.store);
    assert!(
        fixture
            .evidence
            .recover(intent.intent_id.as_str())
            .unwrap()
            .is_none()
    );
    drop(publication.store);

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let path = publication.path.clone();
        let evidence = fixture.evidence.clone();
        let run = fixture.run.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = Store::open(path).unwrap();
            barrier.wait();
            reconcile_publication_with(&evidence, &mut store, &run)
                .unwrap()
                .publication
                .revision
        }));
    }
    let revisions = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(revisions[0], revisions[1]);

    publication.store = Store::open(&publication.path).unwrap();
    let (_, head) = publication.store.checkpoint(&fixture.engagement).unwrap();
    assert_eq!(head.sequence, 1);
    let raw = rusqlite::Connection::open(&publication.path).unwrap();
    let counts: (i64, i64, i64) = raw
        .query_row(
            "SELECT (SELECT count(*) FROM verifications),
                    (SELECT count(*) FROM publication_intents WHERE state='complete'),
                    (SELECT count(*) FROM audit_events WHERE operation='publication.link')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1, 1));
}

#[test]
fn staged_replay_fails_closed_when_an_original_changes() {
    let fixture = fixture(F2Case::True);
    let mut publication = publication_store(&fixture, OracleResult::True);
    let (intent, prepared) = pending_publication(&fixture, &mut publication.store);
    let changed = prepared
        .inputs
        .first()
        .unwrap()
        .artifact_id
        .as_str()
        .to_owned();
    fixture
        .evidence
        .insert(&changed, b"changed original".to_vec());

    drop(publication.store);
    publication.store = Store::open(&publication.path).unwrap();
    assert!(matches!(
        reconcile_publication_with(&fixture.evidence, &mut publication.store, &fixture.run),
        Err(PublicationError::Record(RecordError::DigestMismatch))
    ));
    assert!(
        fixture
            .evidence
            .recover(intent.intent_id.as_str())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        publication
            .store
            .checkpoint(&fixture.engagement)
            .unwrap()
            .1
            .sequence,
        0
    );
    assert_eq!(
        publication
            .store
            .publication(&fixture.run)
            .unwrap()
            .unwrap()
            .state,
        PublicationState::Pending
    );
}

#[test]
fn moved_head_supersedes_without_link_and_publish_rebuilds_on_the_new_head() {
    let primary = fixture(F2Case::True);
    let mut publication = publication_store(&primary, OracleResult::True);
    let (old_intent, prepared) = pending_publication(&primary, &mut publication.store);
    primary
        .evidence
        .store(
            old_intent.intent_id.as_str(),
            &prepared.bytes,
            &prepared.inputs,
        )
        .unwrap();

    let mut other = fixture(F2Case::False);
    other.run = "R-head-race".parse().unwrap();
    add_fixture_run(&mut publication.store, &other, OracleResult::False);
    let first = evaluate_and_publish_with(
        &other.evidence,
        &mut publication.store,
        other.acquisition(),
        context(),
    )
    .unwrap();
    assert_eq!(first.publication.index.sequence, 1);

    assert!(matches!(
        reconcile_publication_with(&primary.evidence, &mut publication.store, &primary.run),
        Err(PublicationError::Store(StoreError::HeadMoved))
    ));
    let raw = rusqlite::Connection::open(&publication.path).unwrap();
    let state: String = raw
        .query_row(
            "SELECT state FROM publication_intents WHERE id=?",
            [old_intent.intent_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "superseded");
    let old_links: i64 = raw
        .query_row(
            "SELECT count(*) FROM verifications WHERE run_id=?",
            [primary.run.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_links, 0);
    drop(raw);

    let rebuilt = evaluate_and_publish_with(
        &primary.evidence,
        &mut publication.store,
        primary.acquisition(),
        context(),
    )
    .unwrap();
    assert_eq!(rebuilt.publication.index.sequence, 2);
    assert_eq!(
        rebuilt.stored.record.prev_record_digest,
        Some(first.stored.artifact.digest)
    );
    assert_ne!(rebuilt.publication.intent.intent_id, old_intent.intent_id);
    assert_ne!(rebuilt.stored.record.record_id, old_intent.record_id);
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
    assert_eq!(network_sinks(include_str!("../status.rs")), 0);
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

#[test]
fn retained_headers_select_only_registered_bounded_decoders() {
    let document = serde_json::to_vec(&serde_json::json!({"label": PRIMARY})).unwrap();
    let escaped = serde_json::to_vec(&serde_json::json!({
        "document": String::from_utf8(document.clone()).unwrap()
    }))
    .unwrap();
    let escaped_decoding = decoding_for(
        Some("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
        &escaped,
        DecodeLimits::DEFAULT,
    )
    .unwrap();
    assert!(escaped_decoding.json_string_body);
    assert_eq!(
        decode_body(&escaped, escaped_decoding, DecodeLimits::DEFAULT)
            .unwrap()
            .bytes,
        document
    );

    let ordinary = serde_json::to_vec(&serde_json::json!({"note": PRIMARY})).unwrap();
    assert!(
        !decoding_for(
            Some("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
            &ordinary,
            DecodeLimits::DEFAULT,
        )
        .unwrap()
        .json_string_body
    );

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&ordinary).unwrap();
    let gzip = encoder.finish().unwrap();
    let gzip_decoding = decoding_for(
        Some("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n"),
        &gzip,
        DecodeLimits::DEFAULT,
    )
    .unwrap();
    assert_eq!(gzip_decoding.content, ContentCoding::Gzip);
    assert_eq!(
        decode_body(&gzip, gzip_decoding, DecodeLimits::DEFAULT)
            .unwrap()
            .bytes,
        ordinary
    );

    assert!(matches!(
        decoding_for(
            Some("HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n"),
            b"coded",
            DecodeLimits::DEFAULT,
        ),
        Err(RecordError::MalformedOriginal)
    ));
}

#[test]
fn immutable_snapshot_reevaluates_and_detects_missing_or_tampered_original() {
    let fixture = fixture(F2Case::True);
    let stored =
        evaluate_and_store_with(&fixture.evidence, fixture.acquisition(), context()).unwrap();
    let bytes = fixture.evidence.bytes.lock().unwrap();
    let inputs = fixture.evidence.inputs.lock().unwrap();
    let mut snapshot = EvidenceSnapshot {
        artifacts: bytes
            .iter()
            .map(|(id, data)| SnapshotArtifact {
                artifact: Artifact {
                    artifact_id: id.as_str().parse().unwrap(),
                    digest: Sha256Digest::of(data),
                },
                bytes: data.clone(),
                inputs: inputs.get(id).unwrap().clone(),
                record_lineage: true,
            })
            .collect(),
    };
    assert_eq!(
        snapshot_record(&snapshot, &stored.artifact).unwrap().result,
        OracleResult::True
    );
    let original = stored.record.rounds[0].flows[0].original.as_ref().unwrap();
    let index = snapshot
        .artifacts
        .iter()
        .position(|item| item.artifact == *original)
        .unwrap();
    let removed = snapshot.artifacts.remove(index);
    assert!(matches!(
        snapshot_record(&snapshot, &stored.artifact),
        Err(RecordError::MissingOriginal)
    ));
    snapshot.artifacts.push(removed);
    snapshot.artifacts.last_mut().unwrap().bytes.push(0);
    assert!(matches!(
        snapshot_record(&snapshot, &stored.artifact),
        Err(RecordError::DigestMismatch)
    ));
}

fn refresh_synthetic_record(snapshot: &mut LinkedEvidenceSnapshot, index: usize) {
    let (artifact, record) = &mut snapshot.records[index];
    let bytes = wire::to_vec(record).unwrap();
    artifact.digest = Sha256Digest::of(&bytes);
    let item = snapshot
        .evidence
        .artifacts
        .iter_mut()
        .find(|item| item.artifact.artifact_id == artifact.artifact_id)
        .unwrap();
    item.artifact = artifact.clone();
    item.bytes = bytes;
}

fn push_synthetic_record(
    snapshot: &mut LinkedEvidenceSnapshot,
    id: &str,
    record: VerificationV1,
    inputs: Vec<Artifact>,
) {
    let bytes = wire::to_vec(&record).unwrap();
    let artifact = Artifact {
        artifact_id: id.parse().unwrap(),
        digest: Sha256Digest::of(&bytes),
    };
    snapshot.evidence.artifacts.push(SnapshotArtifact {
        artifact: artifact.clone(),
        bytes,
        inputs,
        record_lineage: true,
    });
    snapshot.records.push((artifact, record));
}

#[test]
fn linked_snapshot_binds_exact_published_record_and_originals() {
    fn status_snapshot(snapshot: &LinkedEvidenceSnapshot) -> crate::status::StatusSnapshot {
        crate::status::StatusSnapshot::from_capture(Ok(snapshot.clone())).unwrap()
    }
    let fixture = fixture(F2Case::True);
    let mut publication = publication_store(&fixture, OracleResult::True);
    let published = evaluate_and_publish_with(
        &fixture.evidence,
        &mut publication.store,
        fixture.acquisition(),
        context(),
    )
    .unwrap();
    let read = scourge_core::store::read::ReadStore::open(&publication.path).unwrap();
    let chain = read
        .snapshot(|snapshot| {
            snapshot
                .scope(fixture.engagement.clone())?
                .linked_chain(&published.stored.record.lead_id)
        })
        .unwrap();
    let linked =
        capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id).unwrap();
    assert_eq!(linked.records.len(), 1);
    let result = crate::status::StatusComputer::compute(
        &published.stored.record.lead_id,
        &status_snapshot(&linked),
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::compiled(),
    );
    assert_eq!(result.status, crate::status::Status::Verified);
    assert_eq!(
        result.applicability,
        crate::status::Applicability::AsObserved
    );
    assert_eq!(
        result.status_record.as_ref(),
        Some(&published.stored.record.record_id)
    );
    assert_eq!(
        result.deciding_record.as_ref(),
        Some(&published.stored.record.record_id)
    );
    let revoked = crate::status::StatusComputer::compute(
        &published.stored.record.lead_id,
        &status_snapshot(&linked),
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::revoked(published.stored.record.oracle.clone()),
    );
    assert_eq!(revoked.status, crate::status::Status::NeedsReview);
    let mut changed =
        capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id).unwrap();
    let mut revision = changed.bindings.last().unwrap().clone();
    revision.revision += 1;
    revision.class = Some("new-class".parse().unwrap());
    changed.bindings.push(revision);
    assert_eq!(
        crate::status::StatusComputer::compute(
            &published.stored.record.lead_id,
            &status_snapshot(&changed),
            crate::status::Audience::Internal,
            &crate::status::RegistrySnapshot::compiled()
        )
        .status,
        crate::status::Status::NeedsReview
    );
    let mut missing =
        capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id).unwrap();
    let original = published.stored.record.rounds[0].flows[0]
        .original
        .as_ref()
        .unwrap();
    missing
        .evidence
        .artifacts
        .retain(|item| item.artifact != *original);
    assert_eq!(
        crate::status::StatusComputer::compute(
            &published.stored.record.lead_id,
            &status_snapshot(&missing),
            crate::status::Audience::Internal,
            &crate::status::RegistrySnapshot::compiled()
        )
        .status,
        crate::status::Status::IntegrityFailure
    );
    let mut tampered =
        capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id).unwrap();
    tampered
        .evidence
        .artifacts
        .iter_mut()
        .find(|item| item.artifact == *original)
        .unwrap()
        .bytes
        .push(0);
    assert_eq!(
        crate::status::StatusComputer::compute(
            &published.stored.record.lead_id,
            &status_snapshot(&tampered),
            crate::status::Audience::Internal,
            &crate::status::RegistrySnapshot::compiled()
        )
        .status,
        crate::status::Status::IntegrityFailure
    );
    let disputed = crate::status::StatusComputer::compute_for_test(
        &published.stored.record.lead_id,
        &linked,
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::compiled(),
        false,
        true,
        |_, _| Some(true),
    );
    assert_eq!(disputed.status, crate::status::Status::Disputed);
    let broken_with_objection = crate::status::StatusComputer::compute_for_test(
        &published.stored.record.lead_id,
        &linked,
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::compiled(),
        false,
        true,
        |_, _| None,
    );
    assert_eq!(
        broken_with_objection.status,
        crate::status::Status::IntegrityFailure
    );
    let mut no_records =
        capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id).unwrap();
    no_records.records.clear();
    let refuted = crate::status::StatusComputer::compute_for_test(
        &published.stored.record.lead_id,
        &no_records,
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::compiled(),
        true,
        false,
        |_, _| Some(true),
    );
    assert_eq!(refuted.status, crate::status::Status::Refuted);
    // Even if a modified record and locator agree, re-evaluation catches an edited reproduction summary.
    let mut edited =
        capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id).unwrap();
    edited.records[0].1.reproduction = Reproduction::Intermittent;
    let bytes = wire::to_vec(&edited.records[0].1).unwrap();
    let digest = Sha256Digest::of(&bytes);
    edited.records[0].0.digest = digest.clone();
    let material = edited
        .evidence
        .artifacts
        .iter_mut()
        .find(|item| item.artifact.artifact_id == edited.records[0].0.artifact_id)
        .unwrap();
    material.bytes = bytes;
    material.artifact.digest = digest;
    assert_eq!(
        crate::status::StatusComputer::compute(
            &published.stored.record.lead_id,
            &status_snapshot(&edited),
            crate::status::Audience::Internal,
            &crate::status::RegistrySnapshot::compiled()
        )
        .status,
        crate::status::Status::IntegrityFailure
    );
    // A controlled profile cannot promote a mixed true/false run even if an
    // older evaluator summarized the run as true.
    let mut mixed =
        capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id).unwrap();
    let mut second_round = mixed.records[0].1.rounds[0].clone();
    second_round.number = 2;
    second_round.result = OracleResult::False;
    mixed.records[0].1.rounds.push(second_round);
    mixed.records[0].1.reproduction = Reproduction::Intermittent;
    let mixed_result = crate::status::StatusComputer::compute_for_test(
        &published.stored.record.lead_id,
        &mixed,
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::compiled(),
        false,
        false,
        |_, _| Some(true),
    );
    assert!(matches!(
        mixed_result.status,
        crate::status::Status::Lead {
            last: crate::status::LastOutcome::Invalid,
            ..
        }
    ));
    assert_eq!(mixed_result.status_record, None);
    mixed.records[0].1.profile = Profile::RuntimeIntermittentV1;
    let one_true = crate::status::StatusComputer::compute_for_test(
        &published.stored.record.lead_id,
        &mixed,
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::compiled(),
        false,
        false,
        |_, _| Some(true),
    );
    assert_eq!(one_true.status_record, None);
    let mut third_round = mixed.records[0].1.rounds[0].clone();
    third_round.number = 3;
    mixed.records[0].1.rounds.push(third_round);
    refresh_synthetic_record(&mut mixed, 0);
    let two_true = crate::status::StatusComputer::compute_for_test(
        &published.stored.record.lead_id,
        &mixed,
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::compiled(),
        false,
        false,
        |_, _| Some(true),
    );
    assert_eq!(
        two_true.status_record.as_ref(),
        Some(&published.stored.record.record_id)
    );
    // Exercise the pure decision engine with a verifier-established retest.
    // M1 itself cannot establish one, so its production reevaluator marks it stale.
    let mut synthetic =
        capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id).unwrap();
    let mut retest = published.stored.record.clone();
    retest.sequence = 2;
    retest.record_id = "V-retest".parse().unwrap();
    retest.kind = RecordKind::Retest;
    retest.retest = Some(scourge_core::wire::Retest {
        baseline_record: published.stored.record.record_id.clone(),
        baseline_digest: published.stored.artifact.digest.clone(),
        mode: scourge_core::wire::RetestMode::Sequential,
        property_result: scourge_core::wire::PropertyResult::StillViolated,
        functional_result: scourge_core::wire::FunctionalResult::PreservedWithinTestedScope,
        paired_baseline_target: None,
        intermittent_sampling: None,
    });
    let retest_artifact = Artifact {
        artifact_id: "art_retest".parse().unwrap(),
        digest: Sha256Digest::of(b"synthetic retest"),
    };
    synthetic
        .records
        .push((retest_artifact.clone(), retest.clone()));
    for (property, functional, expected) in [
        (
            scourge_core::wire::PropertyResult::StillViolated,
            scourge_core::wire::FunctionalResult::PreservedWithinTestedScope,
            crate::status::Applicability::StillViolated,
        ),
        (
            scourge_core::wire::PropertyResult::NoViolationWithinTestedScope,
            scourge_core::wire::FunctionalResult::PreservedWithinTestedScope,
            crate::status::Applicability::FixedWithinTestedScope,
        ),
        (
            scourge_core::wire::PropertyResult::Inconclusive,
            scourge_core::wire::FunctionalResult::PreservedWithinTestedScope,
            crate::status::Applicability::Unestablished,
        ),
    ] {
        let details = synthetic.records[1].1.retest.as_mut().unwrap();
        details.property_result = property;
        details.functional_result = functional;
        let computed = crate::status::StatusComputer::compute_for_test(
            &published.stored.record.lead_id,
            &synthetic,
            crate::status::Audience::Internal,
            &crate::status::RegistrySnapshot::compiled(),
            false,
            false,
            |_, _| Some(true),
        );
        assert_eq!(computed.applicability, expected);
        assert_eq!(computed.deciding_record.as_ref(), Some(&retest.record_id));
    }
    // A newer true supersedes the retest; invalid runs cannot become D.
    let mut newer = retest.clone();
    newer.sequence = 3;
    newer.record_id = "V-newer".parse().unwrap();
    newer.kind = RecordKind::Verify;
    newer.retest = None;
    newer.result = OracleResult::True;
    let inputs = synthetic
        .evidence
        .artifacts
        .iter()
        .find(|item| item.artifact == published.stored.artifact)
        .unwrap()
        .inputs
        .clone();
    push_synthetic_record(&mut synthetic, "art_newer", newer.clone(), inputs);
    let computed = crate::status::StatusComputer::compute_for_test(
        &published.stored.record.lead_id,
        &synthetic,
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::compiled(),
        false,
        false,
        |_, _| Some(true),
    );
    assert_eq!(computed.status_record.as_ref(), Some(&newer.record_id));
    assert_eq!(computed.deciding_record.as_ref(), Some(&newer.record_id));
    assert_eq!(
        computed.applicability,
        crate::status::Applicability::AsObserved
    );
    let mut invalid = newer.clone();
    invalid.sequence = 4;
    invalid.record_id = "V-invalid".parse().unwrap();
    invalid.result = OracleResult::Invalid;
    synthetic.records.push((
        Artifact {
            artifact_id: "art_invalid".parse().unwrap(),
            digest: Sha256Digest::of(b"invalid"),
        },
        invalid,
    ));
    let computed = crate::status::StatusComputer::compute_for_test(
        &published.stored.record.lead_id,
        &synthetic,
        crate::status::Audience::Internal,
        &crate::status::RegistrySnapshot::compiled(),
        false,
        false,
        |_, _| Some(true),
    );
    assert_eq!(computed.deciding_record.as_ref(), Some(&newer.record_id));
    synthetic.records[0].1.custody = Custody::Isolated;
    refresh_synthetic_record(&mut synthetic, 0);
    let third_retest = crate::status::StatusComputer::compute_for_test(
        &published.stored.record.lead_id,
        &synthetic,
        crate::status::Audience::ThirdParty,
        &crate::status::RegistrySnapshot::compiled(),
        false,
        false,
        |_, _| Some(true),
    );
    assert_eq!(
        third_retest.status_record.as_ref(),
        Some(&published.stored.record.record_id)
    );
    assert_eq!(
        third_retest.applicability,
        crate::status::Applicability::Unestablished
    );
    let third = crate::status::StatusComputer::compute(
        &published.stored.record.lead_id,
        &status_snapshot(&linked),
        crate::status::Audience::ThirdParty,
        &crate::status::RegistrySnapshot::compiled(),
    );
    assert_eq!(third.status, crate::status::Status::Verified);
    assert!(!third.qualified);
    assert_eq!(
        third.applicability,
        crate::status::Applicability::Unestablished
    );
    assert_eq!(
        snapshot_record(&linked.evidence, &published.stored.artifact)
            .unwrap()
            .record_id,
        published.stored.record.record_id
    );
    fixture
        .evidence
        .bytes
        .lock()
        .unwrap()
        .get_mut(published.stored.artifact.artifact_id.as_str())
        .unwrap()
        .push(0);
    assert!(matches!(
        capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id),
        Err(RecordError::DigestMismatch)
    ));
}

#[test]
fn status_policy_admission_and_version_are_computed_without_a_new_run() {
    use crate::status::{Applicability, Audience, RegistrySnapshot, Status, StatusComputer};
    use scourge_core::engagement::{EngagementDraft, PassPin};
    let original = std::str::from_utf8(include_bytes!(
        "../../../../fixtures/target/schema-examples/engagement.toml"
    ))
    .unwrap();
    let no_rule = original.replacen("readers = \"owner\"\n", "", 1);
    let authenticated = original.replacen("readers = \"owner\"", "readers = \"authenticated\"", 1);
    let different_version = original.replace("version.fixture.v1", "version.other.v1");
    let pass_ref = "pass.development-fixture".parse().unwrap();
    let pass_digest = Sha256Digest::of(b"fixture pass");
    for (source, later, expected, after) in [
        (original, None, Status::Verified, Status::Verified),
        (
            no_rule.as_str(),
            None,
            Status::Conditional,
            Status::Conditional,
        ),
        (
            no_rule.as_str(),
            Some(different_version.as_str()),
            Status::Conditional,
            Status::Conditional,
        ),
        (
            authenticated.as_str(),
            None,
            Status::Refuted,
            Status::Refuted,
        ),
        (
            no_rule.as_str(),
            Some(original),
            Status::Conditional,
            Status::Verified,
        ),
    ] {
        let draft = EngagementDraft::parse_toml(source.as_bytes()).unwrap();
        let manifest = draft
            .accept(PassPin {
                reference: &pass_ref,
                digest: &pass_digest,
            })
            .unwrap();
        let mut fixture = fixture(F2Case::True);
        fixture.experiment.engagement.digest = manifest.digest().clone();
        let property = fixture.experiment.property.as_mut().unwrap();
        property.digest = Sha256Digest::of(
            &scourge_core::canonical::to_vec(manifest.properties().get(&property.label).unwrap())
                .unwrap(),
        );
        let (bytes, digest) = fixture.experiment.freeze().unwrap();
        fixture.experiment_digest = digest;
        fixture.experiment_artifact = fixture.evidence.insert("art_experiment", bytes);
        let mut publication = publication_store_for(&fixture, OracleResult::True, &manifest);
        let published = evaluate_and_publish_with(
            &fixture.evidence,
            &mut publication.store,
            fixture.acquisition(),
            context(),
        )
        .unwrap();
        // A document cited by the lead is a proposal, not operator admission.
        if source == no_rule.as_str() {
            publication
                .store
                .append_lead_revision(
                    &fixture.engagement,
                    &LeadRevision {
                        lead_id: published.stored.record.lead_id.clone(),
                        revision: 5,
                        text: "agent cites a document".parse().unwrap(),
                        class: None,
                        property: None,
                        slots: BTreeMap::new(),
                        proposed_policy: Some(serde_json::json!({"source": "unadmitted document"})),
                        origin: LeadOrigin::Local,
                        source_ref: None,
                        endpoint: None,
                        flow_ids: Vec::new(),
                        producer_confidence: None,
                    },
                )
                .unwrap();
        }
        let read = scourge_core::store::read::ReadStore::open(&publication.path).unwrap();
        let chain = read
            .snapshot(|snapshot| {
                snapshot
                    .scope(fixture.engagement.clone())?
                    .linked_chain(&published.stored.record.lead_id)
            })
            .unwrap();
        let snapshot =
            capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id)
                .unwrap();
        let before = StatusComputer::compute(
            &published.stored.record.lead_id,
            &crate::status::StatusSnapshot::from_capture(Ok(snapshot)).unwrap(),
            Audience::Internal,
            &RegistrySnapshot::compiled(),
        );
        assert_eq!(before.status, expected);
        assert_eq!(before.applicability, Applicability::AsObserved);
        if let Some(later) = later {
            let revision = manifest
                .amend(
                    EngagementDraft::parse_toml(later.as_bytes()).unwrap(),
                    PassPin {
                        reference: &pass_ref,
                        digest: &pass_digest,
                    },
                )
                .unwrap();
            let artifact = fixture
                .evidence
                .insert("art_manifest_2", revision.canonical_bytes().to_vec());
            publication
                .store
                .append_manifest(&fixture.engagement, &artifact, &pass_digest)
                .unwrap();
            let chain = read
                .snapshot(|snapshot| {
                    snapshot
                        .scope(fixture.engagement.clone())?
                        .linked_chain(&published.stored.record.lead_id)
                })
                .unwrap();
            let snapshot =
                capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id)
                    .unwrap();
            let after_result = StatusComputer::compute(
                &published.stored.record.lead_id,
                &crate::status::StatusSnapshot::from_capture(Ok(snapshot.clone())).unwrap(),
                Audience::Internal,
                &RegistrySnapshot::compiled(),
            );
            assert_eq!(after_result.status, after);
            assert_eq!(after_result.status_record, before.status_record);
            assert_eq!(after_result.deciding_record, before.deciding_record);
            if after == Status::Verified {
                let mut with_false = snapshot;
                let mut later_experiment = fixture.experiment.clone();
                later_experiment.engagement.revision = revision.revision();
                later_experiment.engagement.digest = revision.digest().clone();
                let property = later_experiment.property.as_mut().unwrap();
                property.digest = Sha256Digest::of(
                    &scourge_core::canonical::to_vec(
                        revision.properties().get(&property.label).unwrap(),
                    )
                    .unwrap(),
                );
                let (bytes, digest) = later_experiment.freeze().unwrap();
                let exp_artifact = Artifact {
                    artifact_id: "art_later_experiment".parse().unwrap(),
                    digest: digest.clone(),
                };
                with_false.evidence.artifacts.push(SnapshotArtifact {
                    artifact: exp_artifact.clone(),
                    bytes,
                    inputs: vec![],
                    record_lineage: true,
                });
                let mut record = published.stored.record.clone();
                record.sequence = 2;
                record.record_id = "V-false-later".parse().unwrap();
                record.engagement_revision = revision.revision();
                record.experiment_digest = digest;
                record.property.digest = later_experiment.property.as_ref().unwrap().digest.clone();
                record.result = OracleResult::False;
                let record_id = record.record_id.clone();
                let mut inputs = with_false
                    .evidence
                    .artifacts
                    .iter()
                    .find(|item| item.artifact == published.stored.artifact)
                    .unwrap()
                    .inputs
                    .clone();
                let old_experiment = inputs
                    .iter_mut()
                    .find(|item| item.digest == fixture.experiment_digest)
                    .unwrap();
                *old_experiment = exp_artifact;
                push_synthetic_record(&mut with_false, "art_false_later", record, inputs);
                let decision = StatusComputer::compute_for_test(
                    &published.stored.record.lead_id,
                    &with_false,
                    Audience::Internal,
                    &RegistrySnapshot::compiled(),
                    false,
                    false,
                    |_, _| Some(true),
                );
                assert_eq!(decision.deciding_record, Some(record_id));
                assert_eq!(decision.applicability, Applicability::Unestablished);
            }
        }
    }
}

#[test]
fn status_capture_errors_map_integrity_without_hiding_dependency_errors() {
    use crate::status::{
        Audience, RegistrySnapshot, Status, StatusCaptureError, StatusComputer, StatusSnapshot,
    };
    let lead = "L-record-test".parse().unwrap();
    for error in [
        StatusCaptureError::Store(StoreError::Integrity),
        StatusCaptureError::Record(RecordError::MissingOriginal),
    ] {
        let snapshot = StatusSnapshot::from_capture(Err(error)).unwrap();
        assert_eq!(
            StatusComputer::compute(
                &lead,
                &snapshot,
                Audience::Internal,
                &RegistrySnapshot::compiled()
            )
            .status,
            Status::IntegrityFailure
        );
    }
    assert!(
        StatusSnapshot::from_capture(Err(StatusCaptureError::Store(StoreError::Busy))).is_err()
    );
}

#[test]
fn broken_real_chain_maps_through_status_capture_outcome() {
    use crate::status::{
        Audience, RegistrySnapshot, Status, StatusCaptureError, StatusComputer, StatusSnapshot,
    };
    let fixture = fixture(F2Case::True);
    let mut publication = publication_store(&fixture, OracleResult::True);
    let published = evaluate_and_publish_with(
        &fixture.evidence,
        &mut publication.store,
        fixture.acquisition(),
        context(),
    )
    .unwrap();
    let raw = rusqlite::Connection::open(&publication.path).unwrap();
    raw.execute_batch("PRAGMA foreign_keys=OFF; DROP TRIGGER verification_no_update;")
        .unwrap();
    raw.execute(
        "UPDATE verifications SET record_digest=?1 WHERE record_id=?2",
        rusqlite::params![
            Sha256Digest::of(b"bad").as_str(),
            published.stored.record.record_id.as_str()
        ],
    )
    .unwrap();
    drop(raw);
    let read = scourge_core::store::read::ReadStore::open(&publication.path).unwrap();
    let chain = read.snapshot(|snapshot| {
        snapshot
            .scope(fixture.engagement.clone())?
            .linked_chain(&published.stored.record.lead_id)
    });
    assert!(matches!(chain, Err(StoreError::Integrity)));
    let captured =
        StatusSnapshot::from_capture(chain.map_err(StatusCaptureError::Store).and_then(|chain| {
            capture_linked_with(&fixture.evidence, &chain, &published.stored.record.lead_id)
                .map_err(StatusCaptureError::Record)
        }))
        .unwrap();
    assert_eq!(
        StatusComputer::compute(
            &published.stored.record.lead_id,
            &captured,
            Audience::Internal,
            &RegistrySnapshot::compiled()
        )
        .status,
        Status::IntegrityFailure
    );
}

#[test]
fn mixed_rounds_are_retained_as_intermittent_not_a_false_verdict() {
    let positive = fixture(F2Case::True);
    let negative = fixture(F2Case::False);
    let incomplete = fixture(F2Case::Partial);
    let evaluate_fixture = |fixture: &Fixture| {
        evaluate(
            &observations_from_acquired(&fixture.run, &fixture.experiment, &fixture.rounds[0])
                .unwrap(),
        )
    };
    let yes = evaluate_fixture(&positive);
    let no = evaluate_fixture(&negative);
    let invalid = evaluate_fixture(&incomplete);
    let mixed = summarize([&yes, &no].into_iter());
    assert_eq!(mixed.result, OracleResult::True);
    assert_eq!(mixed.reproduction, Reproduction::Intermittent);
    assert_eq!(
        summarize([&yes, &yes].into_iter()).reproduction,
        Reproduction::Reproduced
    );
    assert_eq!(
        summarize([&yes, &invalid].into_iter()).result,
        OracleResult::Invalid
    );
    assert_eq!(summarize(std::iter::empty()).result, OracleResult::Invalid);
}

#[test]
fn repeated_published_runs_resolve_identical_experiments_from_each_record_lineage() {
    use crate::status::{
        Applicability, Audience, RegistrySnapshot, Status, StatusComputer, StatusSnapshot,
    };

    let first = fixture(F2Case::True);
    let mut second = fixture(F2Case::False);
    second.run = "R-record-test-second".parse().unwrap();
    assert_eq!(first.experiment_digest, second.experiment_digest);

    // Retain the second run as separate evidence, including a separate
    // experiment receipt with exactly the same canonical bytes and digest.
    let copied: HashMap<String, Artifact> = second
        .evidence
        .bytes
        .lock()
        .unwrap()
        .iter()
        .map(|(id, bytes)| {
            (
                id.clone(),
                first
                    .evidence
                    .insert(&format!("second_{id}"), bytes.clone()),
            )
        })
        .collect();
    let remap = |artifact: &mut Artifact| {
        *artifact = copied[artifact.artifact_id.as_str()].clone();
    };
    remap(&mut second.experiment_artifact);
    for artifact in &mut second.retained {
        remap(artifact);
    }
    for round in &mut second.rounds {
        for flow in &mut round.flows {
            if let Some(original) = &mut flow.reference.original {
                remap(original);
            }
        }
        for cleanup in &mut round.cleanup {
            for flow in &mut cleanup.flows {
                if let Some(original) = &mut flow.original {
                    remap(original);
                }
            }
        }
    }
    second.evidence = first.evidence.clone();
    assert_ne!(
        first.experiment_artifact.artifact_id,
        second.experiment_artifact.artifact_id
    );
    assert_eq!(
        first.experiment_artifact.digest,
        second.experiment_artifact.digest
    );

    let mut publication = publication_store(&first, OracleResult::True);
    let positive = evaluate_and_publish_with(
        &first.evidence,
        &mut publication.store,
        first.acquisition(),
        context(),
    )
    .unwrap();
    add_fixture_run(&mut publication.store, &second, OracleResult::False);
    let negative = evaluate_and_publish_with(
        &second.evidence,
        &mut publication.store,
        second.acquisition(),
        context(),
    )
    .unwrap();
    assert_ne!(
        positive.publication.intent.intent_id,
        negative.publication.intent.intent_id
    );
    assert_ne!(positive.stored.artifact, negative.stored.artifact);
    assert_ne!(positive.stored.record.run_id, negative.stored.record.run_id);

    let read = scourge_core::store::read::ReadStore::open(&publication.path).unwrap();
    let chain = read
        .snapshot(|snapshot| {
            snapshot
                .scope(first.engagement.clone())?
                .linked_chain(&positive.stored.record.lead_id)
        })
        .unwrap();
    let linked =
        capture_linked_with(&first.evidence, &chain, &positive.stored.record.lead_id).unwrap();
    assert_eq!(
        linked
            .evidence
            .artifacts
            .iter()
            .filter(|item| item.artifact.digest == first.experiment_digest)
            .count(),
        2
    );
    for record_artifact in [&positive.stored.artifact, &negative.stored.artifact] {
        let material = linked
            .evidence
            .artifacts
            .iter()
            .find(|item| &item.artifact == record_artifact)
            .unwrap();
        assert_eq!(
            material
                .inputs
                .iter()
                .filter(|input| input.digest == first.experiment_digest)
                .count(),
            1
        );
    }
    assert_eq!(
        linked.reevaluate(&positive.stored.artifact).unwrap().result,
        OracleResult::True
    );
    assert_eq!(
        linked.reevaluate(&negative.stored.artifact).unwrap().result,
        OracleResult::False
    );
    let computed = StatusComputer::compute(
        &positive.stored.record.lead_id,
        &StatusSnapshot::from_capture(Ok(linked.clone())).unwrap(),
        Audience::Internal,
        &RegistrySnapshot::compiled(),
    );
    assert_eq!(computed.status, Status::Verified);
    assert_eq!(computed.applicability, Applicability::Unestablished);
    assert_eq!(
        computed.status_record,
        Some(positive.stored.record.record_id.clone())
    );
    assert_eq!(
        computed.deciding_record,
        Some(negative.stored.record.record_id.clone())
    );

    let mut duplicate = linked.clone();
    let positive_material = duplicate
        .evidence
        .artifacts
        .iter_mut()
        .find(|item| item.artifact == positive.stored.artifact)
        .unwrap();
    positive_material
        .inputs
        .push(second.experiment_artifact.clone());
    assert!(matches!(
        duplicate.experiment(&positive.stored.artifact, &positive.stored.record),
        Err(RecordError::DigestMismatch)
    ));
    let computed = StatusComputer::compute(
        &positive.stored.record.lead_id,
        &StatusSnapshot::from_capture(Ok(duplicate)).unwrap(),
        Audience::Internal,
        &RegistrySnapshot::compiled(),
    );
    assert_eq!(computed.status, Status::IntegrityFailure);

    let mut missing = linked;
    let positive_material = missing
        .evidence
        .artifacts
        .iter_mut()
        .find(|item| item.artifact == positive.stored.artifact)
        .unwrap();
    positive_material
        .inputs
        .retain(|input| input.digest != positive.stored.record.experiment_digest);
    assert!(matches!(
        missing.experiment(&positive.stored.artifact, &positive.stored.record),
        Err(RecordError::MissingOriginal)
    ));
    let computed = StatusComputer::compute(
        &positive.stored.record.lead_id,
        &StatusSnapshot::from_capture(Ok(missing)).unwrap(),
        Audience::Internal,
        &RegistrySnapshot::compiled(),
    );
    assert_eq!(computed.status, Status::IntegrityFailure);
}
