use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::{
    domain::{LeadRevision, RunStep},
    engagement::{EngagementDraft, PassPin},
    evidence::{Completion, Evidence},
    execution_effects::{ExecutionEffects, Snapshot as ExecutionEffectsSnapshot},
    ids::{EngagementId, LeadId, RequestKey},
    request::Invocation,
    rounds::{ExecutionFailure, RoundError, TargetOrigin, execute_live},
    store::read::ReadStore,
    teapot::{
        BoundEngine, EditSurface, Environment, ExecutableKind, GateRefusalReason, Teapot,
        accounting::{AccountingBinding, AccountingCapture},
    },
    template::{ClaimClass, EngagementPin, SlotName, SlotValue},
    wire::{Effect, RunFlag},
    workspace::{
        InvestigationAuthority, ManifestArtifactKind, ManifestArtifactPin, ManifestAuthority,
        PassAuthority, TeapotProjectAuthority,
    },
};

fn bound_teapot(instance: &str, project_id: &str, project: &str) -> Teapot {
    Teapot::new(
        "/bin/false".parse().unwrap(),
        ExecutableKind::Native,
        project.parse().unwrap(),
        Environment {
            home: "/tmp/scourge-admission-home".parse().unwrap(),
            config_home: None,
            data_home: None,
            state_home: None,
            cache_home: None,
            runtime_dir: None,
        },
        BoundEngine {
            instance: instance.parse().unwrap(),
            project_id: project_id.parse().unwrap(),
            enforced: false,
            policy_locked: false,
        },
    )
}

const ENGAGEMENT: &[u8] =
    include_bytes!("../../../../fixtures/target/schema-examples/engagement.toml");

fn pass_ref() -> PassRef {
    PassRef::from_str("pass.development-fixture").unwrap()
}

fn pass_digest() -> Sha256Digest {
    Sha256Digest::of(b"fixture pass")
}

fn manifest() -> ManifestRevision {
    manifest_from_source(ENGAGEMENT)
}

fn manifest_from_source(source: &[u8]) -> ManifestRevision {
    EngagementDraft::parse_toml(source)
        .unwrap()
        .accept(PassPin {
            reference: &pass_ref(),
            digest: &pass_digest(),
        })
        .unwrap()
}

fn one_run_source() -> String {
    std::str::from_utf8(ENGAGEMENT)
        .unwrap()
        .replace("max_verify_runs = 50", "max_verify_runs = 1")
}

fn manifest_with_route(project: &str, pass: &PassRef, digest: &Sha256Digest) -> ManifestRevision {
    let source = String::from_utf8(ENGAGEMENT.to_vec())
        .unwrap()
        .replace("pass.development-fixture", pass.as_str())
        .replace("project.teapot.development", project);
    EngagementDraft::parse_toml(source.as_bytes())
        .unwrap()
        .accept(PassPin {
            reference: pass,
            digest,
        })
        .unwrap()
}

fn slot(name: &str, value: &str) -> SlotValue {
    SlotValue {
        name: SlotName::from_str(name).unwrap(),
        value: WireText::try_from(value.to_owned()).unwrap(),
    }
}

fn registered_lead(lead: LeadId) -> LeadRevision {
    LeadRevision {
        lead_id: lead,
        revision: 1,
        text: "registered verifier claim".parse().unwrap(),
        class: Some("web-authz/private-object-read".parse().unwrap()),
        property: Some("orders".parse().unwrap()),
        slots: BTreeMap::from([
            ("owner".parse().unwrap(), json!("alice")),
            ("other".parse().unwrap(), json!("bob")),
        ]),
        proposed_policy: None,
        origin: crate::domain::LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    }
}

struct Fixture {
    _dir: TempDir,
    path: PathBuf,
    locks: RunLocks,
    store: RefCell<Store>,
    scope: RequestScope,
    engagement: ManifestRevision,
    manifest_artifact: Artifact,
    claim: Claim,
    input: NormalizedInput,
    pass_file: AbsolutePath,
}

impl Fixture {
    fn new() -> Self {
        Self::with_manifest(manifest(), &pass_digest())
    }

    fn with_manifest(engagement: ManifestRevision, stored_pass: &Sha256Digest) -> Self {
        Self::with_manifest_and_lead(
            engagement,
            stored_pass,
            registered_lead("L-preflight".parse().unwrap()),
        )
    }

    fn with_manifest_and_lead(
        engagement: ManifestRevision,
        stored_pass: &Sha256Digest,
        stored_lead: LeadRevision,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let locks = RunLocks::open(dir.path()).unwrap();
        let mut store = Store::open(&path).unwrap();
        let engagement_id: EngagementId = "local".parse().unwrap();
        let scope = RequestScope::new(engagement_id.clone(), "workspace:local".parse().unwrap());
        let manifest_artifact = Artifact {
            artifact_id: "art_manifest".parse().unwrap(),
            digest: engagement.digest().clone(),
        };
        store
            .append_manifest(&engagement_id, &manifest_artifact, stored_pass)
            .unwrap();
        let lead = LeadId::from_str("L-preflight").unwrap();
        assert_eq!(stored_lead.lead_id, lead);
        store
            .append_lead_revision(&engagement_id, &stored_lead)
            .unwrap();
        let claim = Claim {
            class: ClaimClass::from_str("web-authz/private-object-read").unwrap(),
            engagement: EngagementPin {
                revision: engagement.revision(),
                digest: engagement.digest().clone(),
            },
            lead: lead.clone(),
            property: Some("orders".parse().unwrap()),
            lead_slots: vec![slot("owner", "alice"), slot("other", "bob")],
            overrides: Vec::new(),
        };
        let input = verify_input(&lead, 1);
        Self {
            _dir: dir,
            path,
            locks,
            store: RefCell::new(store),
            scope,
            engagement,
            manifest_artifact,
            claim,
            input,
            pass_file: "/tmp/fixture.pass".parse().unwrap(),
        }
    }

    fn run(&self) -> Run {
        let experiment = Templates::resolve(&self.claim, &self.engagement)
            .unwrap()
            .ready()
            .unwrap();
        Run::declare(
            self.scope.engagement.clone(),
            experiment.freeze().unwrap().1,
        )
    }

    fn request<'a>(&'a self, run: &'a Run, pass_state: PassState<'a>) -> PreflightRequest<'a> {
        PreflightRequest {
            declaration: PreflightDeclaration {
                scope: &self.scope,
                input: &self.input,
                run,
                claim: &self.claim,
                lead_revision: 1,
                engagement: &self.engagement,
                manifest_artifact: &self.manifest_artifact,
            },
            pass: PreflightPass {
                pass_reference: &self.engagement.settings().pass_ref,
                pass_state,
                pass_file: &self.pass_file,
            },
        }
    }

    fn runtime(&self) -> VerifierRuntimeAuthority {
        VerifierRuntimeAuthority {
            manifest: ManifestAuthority {
                revision: self.engagement.revision(),
                digest: self.engagement.digest().clone(),
                canonical_bytes: self.engagement.canonical_bytes().to_vec(),
                artifact: ManifestArtifactPin {
                    kind: ManifestArtifactKind::EngagementManifest,
                    reference: self.manifest_artifact.clone(),
                    revision: 1,
                    size_bytes: self.engagement.canonical_bytes().len(),
                    source_id: "src_12345678-1234-4234-8234-123456789abc".parse().unwrap(),
                },
            },
            pass: PassAuthority {
                path: self.pass_file.as_str().into(),
                digest: self.engagement.pass_digest().clone(),
            },
            teapot: TeapotProjectAuthority {
                executable: "/never-open/teapot".into(),
                project: "/never-open/project".into(),
                home: "/never-open/home".into(),
                config_home: None,
                data_home: None,
                state_home: None,
                cache_home: None,
                runtime_dir: None,
                wrapper: false,
            },
            engine: BoundEngine {
                instance: "engine-a".parse().unwrap(),
                project_id: "project-a".parse().unwrap(),
                enforced: false,
                policy_locked: false,
            },
            investigation: InvestigationAuthority {
                executable: "/never-open/investigation".into(),
                case_root: "/never-open/case".into(),
                workspace_root: "/never-open/case/workspace".into(),
                import_root: "/never-open/import".into(),
                scratch_root: "/never-open/scratch".into(),
            },
            target: self.engagement.target_version().clone(),
            origin: TargetOrigin::parse("https://offline.invalid").unwrap(),
            environment_kind: crate::wire::EnvironmentKind::Simulated,
            custody: Custody::Shared,
            target_isolation: crate::wire::TargetIsolation::SeparatePrincipalsUnconfined,
            principal_slots: BTreeMap::new(),
        }
    }

    fn accept(&self, run: &Run) -> RunAcceptance {
        let request = self.request(run, PassState::Active(self.engagement.pass_digest()));
        declare(&mut self.store.borrow_mut(), request.declaration)
            .unwrap()
            .acceptance
    }
}

fn live_prepared<'a>(
    fixture: &Fixture,
    teapot: &'a Teapot,
    evidence: &'a Evidence,
    registered: bool,
) -> Prepared<LiveAdmission<'a>> {
    let run = fixture.run();
    let services = fake_for(fixture, &run);
    let prepared = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &services,
        fixture.request(&run, PassState::Active(fixture.engagement.pass_digest())),
    )
    .unwrap();
    let Prepared {
        acceptance,
        experiment,
        artifact,
        execution_plan,
        authority,
        lease,
        recovery_lease,
        ..
    } = prepared;
    let pass_id: WireText = "fixture-pass".parse().unwrap();
    let binding = AccountingBinding {
        run_id: acceptance.run.id.clone(),
        request_key: acceptance.run.request_key.clone(),
        pass_id: pass_id.clone(),
        pass_digest: fixture.engagement.pass_digest().clone(),
        pass_file: fixture.pass_file.clone(),
    };
    let instrument = InstrumentObservation::verification_fixture(
        pass_id,
        fixture.engagement.pass_digest().clone(),
        fixture.pass_file.clone(),
    );
    let accounting = AccountingCapture::verification_fixture(
        teapot,
        binding,
        execution_plan.required_requests,
        registered,
    );
    Prepared {
        acceptance,
        experiment,
        artifact,
        execution_plan,
        admission: LiveAdmission {
            instrument,
            accounting,
            sessions: Vec::new(),
            requirement: RequiredEnforcement::None,
            started_at: Timestamp::now_utc(),
            target_origin: TargetOrigin::parse("http://execution-probe.invalid").unwrap(),
            target_version: fixture.engagement.target_version().clone(),
            custody: Custody::Shared,
            target_isolation: crate::wire::TargetIsolation::SeparatePrincipalsUnconfined,
            environment_kind: crate::wire::EnvironmentKind::Simulated,
            teapot,
            evidence,
        },
        authority,
        lease,
        recovery_lease,
    }
}

fn assert_public_execution_rejection(
    fixture: &Fixture,
    prepared: Prepared<LiveAdmission<'_>>,
    teapot: &Teapot,
    evidence: &Evidence,
    effects: &ExecutionEffects,
) {
    let run = prepared.acceptance().run.id.clone();
    let origin = TargetOrigin::parse("http://execution-probe.invalid").unwrap();
    let revision = fixture.store.borrow().revision().unwrap();
    fixture
        .store
        .borrow_mut()
        .observe_execution_effects(effects.clone());
    let result = execute_live(
        &mut fixture.store.borrow_mut(),
        prepared,
        &fixture.engagement,
        teapot,
        evidence,
        &origin,
    );
    let observed_effects = effects.snapshot();
    let store = fixture.store.borrow();
    assert_eq!(
        store.revision().unwrap(),
        revision,
        "audit revision changed"
    );
    assert!(
        store.recover_run(&run).unwrap().steps.is_empty(),
        "step dispatched"
    );
    assert!(
        store.recover_cleanup(&run).unwrap().is_empty(),
        "cleanup changed"
    );
    assert!(
        store.publication(&run).unwrap().is_none(),
        "publication staged"
    );
    assert_eq!(observed_effects, ExecutionEffectsSnapshot::default());
    assert!(matches!(
        result,
        Err(ExecutionFailure { error, .. }) if matches!(*error, RoundError::AdmissionMismatch)
    ));
}

fn verify_input(lead: &LeadId, rounds: u64) -> NormalizedInput {
    Invocation::new(
        "verify",
        json!({"lead_id": lead.as_str(), "rounds": rounds}),
    )
    .normalize()
    .unwrap()
}

#[derive(Default)]
struct FakeServices {
    calls: Mutex<Vec<&'static str>>,
    artifacts: Mutex<BTreeMap<ArtifactId, (Artifact, Vec<u8>)>>,
    commands: Mutex<BTreeMap<String, ArtifactId>>,
    next_artifact: AtomicUsize,
    mutate_readback: AtomicBool,
    durable: Option<(PathBuf, RequestScope, RequestKey)>,
    refusal: Mutex<Option<ServiceRefusal>>,
}

#[derive(Clone, Copy, Debug)]
enum ServiceRefusal {
    Gate(GateRefusalReason),
    Accounting(AccountingRefusal),
    EvidenceRecordMissing,
    EvidenceRecordUnavailable,
    EvidenceReadIntegrity,
}

#[derive(Debug)]
struct FakeAdmission;

impl sealed::Sealed for FakeServices {}

impl PreflightServices for FakeServices {
    type Admission = FakeAdmission;

    fn admit(
        &self,
        sessions: &[SessionName],
        plan: &RegisteredExecutionPlan,
        _requirement: RequiredEnforcement,
        binding: PreflightAccounting<'_>,
    ) -> Result<Self::Admission, PreflightError> {
        assert!(sessions.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(sessions.contains(&plan.macro_session));
        assert_eq!(plan.macro_name.as_str(), "create-order");
        assert_eq!(plan.expected_macro_requests, 1);
        assert_eq!(plan.requests_per_round, 35);
        assert_eq!(
            plan.required_requests,
            35_u64.checked_mul(plan.round_count).unwrap()
        );
        assert_eq!(binding.pass_digest, &pass_digest());
        if let Some((path, scope, key)) = &self.durable {
            assert_eq!(&binding.run.request_key, key);
            let observer = Store::open(path).unwrap();
            let accepted = observer.find_request(scope, key).unwrap().unwrap();
            assert_eq!(accepted.run.id, binding.run.id);
        }
        self.calls.lock().unwrap().push("admit");
        let refusal = self.refusal.lock().unwrap().take();
        match refusal {
            Some(ServiceRefusal::Gate(reason)) => {
                return Err(PreflightError::Gate(GateRefusal {
                    reason,
                    calls: Vec::new(),
                    edit_surface: EditSurface::default(),
                    enforcement: None,
                    policy_locked: None,
                    invocation: None,
                }));
            }
            Some(ServiceRefusal::Accounting(reason)) => {
                return Err(PreflightError::AccountingPreflight(reason));
            }
            Some(refusal) => {
                *self.refusal.lock().unwrap() = Some(refusal);
            }
            None => {}
        }
        Ok(FakeAdmission)
    }

    fn record_experiment(
        &self,
        request_key: &str,
        bytes: &[u8],
        manifest: &Artifact,
    ) -> Result<Artifact, PreflightError> {
        assert_eq!(manifest.artifact_id.as_str(), "art_manifest");
        self.calls.lock().unwrap().push("record");
        let refusal = self.refusal.lock().unwrap().take();
        match refusal {
            Some(ServiceRefusal::EvidenceRecordMissing) => {
                return Err(PreflightError::Evidence(EvidenceError::Missing));
            }
            Some(ServiceRefusal::EvidenceRecordUnavailable) => {
                return Err(PreflightError::Evidence(
                    EvidenceError::UnqualifiedInvestigation,
                ));
            }
            Some(refusal) => {
                *self.refusal.lock().unwrap() = Some(refusal);
            }
            None => {}
        }
        if let Some(id) = self.commands.lock().unwrap().get(request_key).cloned() {
            let (artifact, stored) = self.artifacts.lock().unwrap().get(&id).unwrap().clone();
            assert_eq!(stored, bytes);
            return Ok(artifact);
        }
        let sequence = self.next_artifact.fetch_add(1, Ordering::SeqCst);
        let key = Sha256Digest::of(request_key.as_bytes());
        let artifact = Artifact {
            artifact_id: format!("art_experiment_{}_{sequence}", &key.as_str()[..16])
                .parse()
                .unwrap(),
            digest: Sha256Digest::of(bytes),
        };
        self.artifacts.lock().unwrap().insert(
            artifact.artifact_id.clone(),
            (artifact.clone(), bytes.to_vec()),
        );
        self.commands
            .lock()
            .unwrap()
            .insert(request_key.to_owned(), artifact.artifact_id.clone());
        Ok(artifact)
    }

    fn read_experiment(&self, id: &ArtifactId) -> Result<(Artifact, Vec<u8>), PreflightError> {
        self.calls.lock().unwrap().push("read");
        let refusal = self.refusal.lock().unwrap().take();
        match refusal {
            Some(ServiceRefusal::EvidenceReadIntegrity) => {
                return Err(PreflightError::Evidence(EvidenceError::Integrity));
            }
            Some(refusal) => {
                *self.refusal.lock().unwrap() = Some(refusal);
            }
            None => {}
        }
        let (artifact, mut bytes) = self.artifacts.lock().unwrap().get(id).unwrap().clone();
        if self.mutate_readback.load(Ordering::SeqCst) {
            bytes.push(b' ');
        }
        Ok((artifact, bytes))
    }
}

fn fake_for(fixture: &Fixture, run: &Run) -> FakeServices {
    FakeServices {
        durable: Some((
            fixture.path.clone(),
            fixture.scope.clone(),
            run.request_key.clone(),
        )),
        ..FakeServices::default()
    }
}

#[test]
fn success_declares_before_adapters_and_links_exact_evidence_readback() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let services = fake_for(&fixture, &run);
    let request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let mut writer = fixture.store.borrow_mut();
    let declared = declare(&mut writer, request.declaration).unwrap();
    assert_eq!(declared.acceptance().lead_revision, Some(1));
    assert_eq!(declared.acceptance().engagement_revision, 1);
    let prepared = prepare_declared(&mut writer, &fixture.locks, declared, || {
        let observer = Store::open(&fixture.path).unwrap();
        assert!(
            observer
                .find_request(&fixture.scope, &run.request_key)
                .unwrap()
                .is_some()
        );
        assert!(observer.conflicts_held(&run.id).unwrap());
        Ok((&services, request.pass))
    })
    .unwrap();

    assert!(prepared.holds_locks());
    assert_eq!(prepared.execution_plan().round_count, 1);
    assert_eq!(prepared.execution_plan().requests_per_round, 35);
    assert_eq!(prepared.execution_plan().required_requests, 35);
    assert_eq!(
        services.calls.lock().unwrap().as_slice(),
        ["admit", "record", "read"]
    );
    let frozen = prepared.experiment().freeze().unwrap();
    assert_eq!(prepared.artifact().digest, frozen.1);
    assert_eq!(
        services
            .artifacts
            .lock()
            .unwrap()
            .get(&prepared.artifact().artifact_id)
            .unwrap()
            .1,
        frozen.0
    );

    let reader = ReadStore::open(&fixture.path).unwrap();
    reader
        .snapshot(|snapshot| {
            let detail = snapshot
                .scope(fixture.scope.engagement.clone())?
                .run(&run.id)?;
            assert_eq!(detail.experiment_digest, prepared.artifact().digest);
            assert_eq!(
                detail.experiment_artifact_id,
                Some(prepared.artifact().artifact_id.clone())
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn required_isolated_custody_refuses_before_adapters_with_accepted_selectors() {
    let source = std::str::from_utf8(ENGAGEMENT).unwrap().replace(
        "required_custody = \"shared\"",
        "required_custody = \"isolated\"",
    );
    let manifest = EngagementDraft::parse_toml(source.as_bytes())
        .unwrap()
        .accept(PassPin {
            reference: &pass_ref(),
            digest: &pass_digest(),
        })
        .unwrap();
    let fixture = Fixture::with_manifest(manifest, &pass_digest());
    let run = fixture.run();
    let services = fake_for(&fixture, &run);
    let request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let declared = declare(&mut fixture.store.borrow_mut(), request.declaration).unwrap();
    let recovery = declared.acceptance().recovery();
    let failure = prepare_declared(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        declared,
        || Ok((&services, request.pass)),
    )
    .unwrap_err();

    assert!(matches!(failure, PreflightError::CustodyUnavailable));
    assert_eq!(failure.code(), ErrorCode::CustodyUnavailable);
    assert!(services.calls.lock().unwrap().is_empty());
    let store = fixture.store.borrow();
    let accepted = store
        .find_request(&fixture.scope, &run.request_key)
        .unwrap()
        .unwrap();
    assert_eq!(recovery, accepted.recovery());
    assert_eq!(accepted.run, run);
    assert!(!store.conflicts_held(&run.id).unwrap());
}

#[test]
fn live_adapter_bundle_rejects_cross_wired_teapot_and_evidence_inertly() {
    let runtime = Fixture::new().runtime();
    let teapot = Teapot::from_runtime(&runtime).unwrap();
    let evidence = Evidence::inert_fixture(Some(runtime.investigation.clone()));
    assert!(LiveServices::new(&teapot, &evidence, &runtime).is_ok());

    let teapot_changes: [fn(&mut VerifierRuntimeAuthority); 6] = [
        |other| other.teapot.project = "/never-open/other-project".into(),
        |other| other.engine.instance = "engine-b".parse().unwrap(),
        |other| other.engine.policy_locked = true,
        |other| other.teapot.executable = "/never-open/other-teapot".into(),
        |other| other.teapot.wrapper = true,
        |other| other.teapot.config_home = Some("/never-open/config".into()),
    ];
    for change in teapot_changes {
        let mut other = runtime.clone();
        change(&mut other);
        let cross_wired = Teapot::from_runtime(&other).unwrap();
        assert!(matches!(
            LiveServices::new(&cross_wired, &evidence, &runtime),
            Err(PreflightError::RuntimeBinding)
        ));
    }

    let evidence_changes: [fn(&mut InvestigationAuthority); 5] = [
        |other| other.executable = "/never-open/other-investigation".into(),
        |other| other.case_root = "/never-open/other-case".into(),
        |other| other.workspace_root = "/never-open/case/other-workspace".into(),
        |other| other.import_root = "/never-open/other-import".into(),
        |other| other.scratch_root = "/never-open/other-scratch".into(),
    ];
    for change in evidence_changes {
        let mut other = runtime.investigation.clone();
        change(&mut other);
        let cross_wired = Evidence::inert_fixture(Some(other));
        assert!(matches!(
            LiveServices::new(&teapot, &cross_wired, &runtime),
            Err(PreflightError::RuntimeBinding)
        ));
    }
    assert!(matches!(
        LiveServices::new(&teapot, &Evidence::inert_fixture(None), &runtime),
        Err(PreflightError::RuntimeBinding)
    ));
}

#[test]
fn mismatched_pass_path_refuses_before_live_gate_or_evidence_calls() {
    let fixture = Fixture::new();
    let runtime = fixture.runtime();
    let teapot = Teapot::from_runtime(&runtime).unwrap();
    let evidence = Evidence::inert_fixture(Some(runtime.investigation.clone()));
    let services = LiveServices::new(&teapot, &evidence, &runtime).unwrap();
    let run = fixture.run();
    let other: AbsolutePath = "/never-open/other-pass".parse().unwrap();
    let mut request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    request.pass.pass_file = &other;
    let declared = declare(&mut fixture.store.borrow_mut(), request.declaration).unwrap();
    let recovery = declared.acceptance().recovery();
    let failure = prepare_declared(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        declared,
        || Ok((&services, request.pass)),
    )
    .unwrap_err();
    assert!(matches!(failure, PreflightError::RuntimeBinding));
    assert_eq!(failure.code(), ErrorCode::IntegrityFailure);
    assert_eq!(recovery.run_id, run.id);
    assert!(!fixture.store.borrow().conflicts_held(&run.id).unwrap());
}

#[test]
fn declaration_fences_lead_artifact_pass_and_head_before_opening_adapters() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let request = || fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let mut writer = fixture.store.borrow_mut();
    let before = writer.revision().unwrap();
    let mut wrong_lead = request().declaration;
    wrong_lead.lead_revision += 1;
    let mut wrong_artifact = request().declaration;
    let lookalike = Artifact {
        artifact_id: "art_lookalike".parse().unwrap(),
        digest: fixture.manifest_artifact.digest.clone(),
    };
    wrong_artifact.manifest_artifact = &lookalike;
    for declaration in [wrong_lead, wrong_artifact] {
        let error = declare(&mut writer, declaration).unwrap_err();
        assert_eq!(error.code(), ErrorCode::RevisionConflict);
        assert_eq!(writer.revision().unwrap(), before);
        assert!(
            writer
                .find_request(&fixture.scope, &run.request_key)
                .unwrap()
                .is_none()
        );
    }
    let wrong_pass = Fixture::with_manifest(manifest(), &Sha256Digest::of(b"other accepted pass"));
    let bad_run = wrong_pass.run();
    let request_wrong_pass = wrong_pass.request(
        &bad_run,
        PassState::Active(wrong_pass.engagement.pass_digest()),
    );
    let error = declare(
        &mut wrong_pass.store.borrow_mut(),
        request_wrong_pass.declaration,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::RevisionConflict);

    let declared = declare(&mut writer, request().declaration).unwrap();
    writer
        .append_manifest(
            &fixture.scope.engagement,
            &fixture.manifest_artifact,
            fixture.engagement.pass_digest(),
        )
        .unwrap();
    let error = prepare_declared::<FakeServices>(&mut writer, &fixture.locks, declared, || {
        panic!("the adapter opener ran after the accepted revision moved")
    })
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::RevisionConflict);
    assert!(!writer.conflicts_held(&run.id).unwrap());
}

fn assert_new_claim_material_refusal(fixture: Fixture, expected: ErrorCode) {
    let run = fixture.run();
    let before = fixture.store.borrow().revision().unwrap();
    let request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let error = declare(&mut fixture.store.borrow_mut(), request.declaration).unwrap_err();
    assert_eq!(error.code(), expected);
    let store = fixture.store.borrow();
    assert_eq!(store.revision().unwrap(), before);
    assert!(
        store
            .find_request(&fixture.scope, &run.request_key)
            .unwrap()
            .is_none()
    );
    assert!(!store.conflicts_held(&run.id).unwrap());
    assert!(store.publication(&run.id).unwrap().is_none());
}

#[test]
fn accepted_lead_material_is_exactly_bound_before_the_request_receipt() {
    let changes: [fn(&mut LeadRevision); 8] = [
        |lead| lead.class = None,
        |lead| lead.class = Some("web-authz/state-change".parse().unwrap()),
        |lead| lead.property = None,
        |lead| lead.property = Some("accounts".parse().unwrap()),
        |lead| {
            lead.slots
                .remove(&WireText::try_from("other".to_owned()).unwrap());
        },
        |lead| {
            lead.slots.insert("extra".parse().unwrap(), json!("carol"));
        },
        |lead| {
            lead.slots.insert("owner".parse().unwrap(), json!("carol"));
        },
        |lead| {
            lead.slots.insert("owner".parse().unwrap(), json!(7));
        },
    ];
    for change in changes {
        let mut lead = registered_lead("L-preflight".parse().unwrap());
        change(&mut lead);
        assert_new_claim_material_refusal(
            Fixture::with_manifest_and_lead(manifest(), &pass_digest(), lead),
            ErrorCode::RevisionConflict,
        );
    }

    let fixture = Fixture::new();
    let mut foreign = fixture.claim.clone();
    foreign.lead = "L-foreign".parse().unwrap();
    let digest = Templates::resolve(&foreign, &fixture.engagement)
        .unwrap()
        .ready()
        .unwrap()
        .freeze()
        .unwrap()
        .1;
    let run = Run::declare(fixture.scope.engagement.clone(), digest);
    let mut request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    request.declaration.claim = &foreign;
    let before = fixture.store.borrow().revision().unwrap();
    let error = declare(&mut fixture.store.borrow_mut(), request.declaration).unwrap_err();
    assert_eq!(error.code(), ErrorCode::RevisionConflict);
    assert_eq!(fixture.store.borrow().revision().unwrap(), before);
    assert!(
        fixture
            .store
            .borrow()
            .find_request(&fixture.scope, &run.request_key)
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_duplicate_and_noncanonical_stored_slots_fail_as_integrity() {
    for slots in [
        r#"{"owner":"alice","owner":"alice","other":"bob"}"#,
        r#"{"owner":"alice","other":"bob"}"#,
    ] {
        let fixture = Fixture::new();
        fixture
            .store
            .borrow_mut()
            .replace_lead_material_fixture(
                &fixture.claim.lead,
                1,
                Some(fixture.claim.class.as_str()),
                fixture.claim.property.as_ref().map(|value| value.as_str()),
                slots,
            )
            .unwrap();
        assert_new_claim_material_refusal(fixture, ErrorCode::IntegrityFailure);
    }

    let fixture = Fixture::new();
    assert!(
        fixture
            .store
            .borrow_mut()
            .replace_lead_material_fixture(
                &fixture.claim.lead,
                1,
                Some(fixture.claim.class.as_str()),
                fixture.claim.property.as_ref().map(|value| value.as_str()),
                r#"{"other":"bob","owner":"alice""#,
            )
            .is_err()
    );
}

#[test]
fn lead_slot_order_is_normalized_but_duplicates_are_refused() {
    let mut fixture = Fixture::new();
    fixture.claim.lead_slots.reverse();
    let run = fixture.run();
    let services = fake_for(&fixture, &run);
    let request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let prepared = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &services,
        request,
    )
    .unwrap();
    assert_eq!(prepared.acceptance().lead_revision, Some(1));
    assert_eq!(
        services.calls.lock().unwrap().as_slice(),
        ["admit", "record", "read"]
    );

    let mut duplicate = Fixture::new();
    let run = duplicate.run();
    duplicate.claim.lead_slots.push(slot("owner", "alice"));
    let before = duplicate.store.borrow().revision().unwrap();
    let request = duplicate.request(&run, PassState::Active(duplicate.engagement.pass_digest()));
    let error = declare(&mut duplicate.store.borrow_mut(), request.declaration).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InputAmbiguous);
    assert_eq!(duplicate.store.borrow().revision().unwrap(), before);
    assert!(
        duplicate
            .store
            .borrow()
            .find_request(&duplicate.scope, &run.request_key)
            .unwrap()
            .is_none()
    );
}

#[test]
fn replay_rechecks_material_and_current_revision_before_adapter_open() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let exact = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let accepted = declare(&mut fixture.store.borrow_mut(), exact.declaration).unwrap();
    let receipt = accepted.acceptance().receipt;

    let mut reordered = fixture.claim.clone();
    reordered.lead_slots.reverse();
    let mut retry = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    retry.declaration.claim = &reordered;
    let replay = declare(&mut fixture.store.borrow_mut(), retry.declaration).unwrap();
    assert_eq!(replay.acceptance().receipt, receipt);
    let services = fake_for(&fixture, &run);
    let prepared = prepare_declared(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        replay,
        || Ok((&services, retry.pass)),
    )
    .unwrap();
    prepared.abandon(&mut fixture.store.borrow_mut()).unwrap();

    let mut substituted = fixture.claim.clone();
    substituted.lead_slots[0].value = "bob".parse().unwrap();
    substituted.lead_slots[1].value = "alice".parse().unwrap();
    let mut retry = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    retry.declaration.claim = &substituted;
    let replay = declare(&mut fixture.store.borrow_mut(), retry.declaration).unwrap();
    let before = fixture.store.borrow().revision().unwrap();
    let error = prepare_declared::<FakeServices>(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        replay,
        || panic!("adapter opener ran for substituted replay material"),
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::IntegrityFailure);
    assert_eq!(fixture.store.borrow().revision().unwrap(), before);
    assert!(!fixture.store.borrow().conflicts_held(&run.id).unwrap());

    let mut next = registered_lead(fixture.claim.lead.clone());
    next.revision = 2;
    next.text = "same material, newer revision".parse().unwrap();
    fixture
        .store
        .borrow_mut()
        .append_lead_revision(&fixture.scope.engagement, &next)
        .unwrap();
    let retry = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let replay = declare(&mut fixture.store.borrow_mut(), retry.declaration).unwrap();
    let before = fixture.store.borrow().revision().unwrap();
    let error = prepare_declared::<FakeServices>(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        replay,
        || panic!("adapter opener ran after the accepted lead revision moved"),
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::RevisionConflict);
    assert_eq!(fixture.store.borrow().revision().unwrap(), before);
    assert!(!fixture.store.borrow().conflicts_held(&run.id).unwrap());
}

#[test]
fn accepted_resource_and_historical_row_drift_refuse_before_adapter_open() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let mut declared = declare(&mut fixture.store.borrow_mut(), request.declaration).unwrap();
    let receipt = declared.acceptance().receipt;
    declared
        .resolved
        .as_mut()
        .unwrap()
        .experiment
        .property
        .as_mut()
        .unwrap()
        .resource = "resource.other".parse().unwrap();
    let before = fixture.store.borrow().revision().unwrap();
    let error = prepare_declared::<FakeServices>(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        declared,
        || panic!("adapter opener ran for substituted frozen property resource"),
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::RevisionConflict);
    assert_eq!(fixture.store.borrow().revision().unwrap(), before);
    assert!(!fixture.store.borrow().conflicts_held(&run.id).unwrap());

    fixture
        .store
        .borrow_mut()
        .replace_lead_material_fixture(
            &fixture.claim.lead,
            1,
            Some(fixture.claim.class.as_str()),
            fixture.claim.property.as_ref().map(|value| value.as_str()),
            r#"{"other":"mallory","owner":"alice"}"#,
        )
        .unwrap();
    let retry = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let replay = declare(&mut fixture.store.borrow_mut(), retry.declaration).unwrap();
    let before = fixture.store.borrow().revision().unwrap();
    let error = prepare_declared::<FakeServices>(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        replay,
        || panic!("adapter opener ran after accepted lead material changed"),
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::RevisionConflict);
    assert_eq!(fixture.store.borrow().revision().unwrap(), before);
    assert!(!fixture.store.borrow().conflicts_held(&run.id).unwrap());
    assert_eq!(
        fixture
            .store
            .borrow()
            .find_request(&fixture.scope, &run.request_key)
            .unwrap()
            .unwrap()
            .receipt,
        receipt,
    );
}

#[test]
fn preparation_enforces_verify_allowance_before_adapters_and_reopens_the_exact_key() {
    let declaration = one_run_source();
    let fixture =
        Fixture::with_manifest(manifest_from_source(declaration.as_bytes()), &pass_digest());
    let run = fixture.run();
    let services = fake_for(&fixture, &run);
    let request = |run| fixture.request(run, PassState::Active(fixture.engagement.pass_digest()));
    let mut writer = fixture.store.borrow_mut();
    let prepared = prepare(&mut writer, &fixture.locks, &services, request(&run)).unwrap();
    let receipt = prepared.acceptance().receipt;
    prepared.abandon(&mut writer).unwrap();

    let refused = fixture.run();
    let quiet = FakeServices::default();
    let before = writer.revision().unwrap();
    let error = prepare(&mut writer, &fixture.locks, &quiet, request(&refused)).unwrap_err();
    assert_eq!(error.code(), ErrorCode::BudgetRefused);
    assert_eq!(writer.revision().unwrap(), before);
    assert!(quiet.calls.lock().unwrap().is_empty());
    assert!(
        writer
            .find_request(&fixture.scope, &refused.request_key)
            .unwrap()
            .is_none()
    );

    let mut retry = fixture.run();
    retry.request_key = run.request_key.clone();
    let reopened = prepare(&mut writer, &fixture.locks, &services, request(&retry)).unwrap();
    assert_eq!(reopened.acceptance.receipt, receipt);
    assert_eq!(reopened.acceptance.run.id, run.id);
}

#[test]
fn metadata_verify_over_cap_reopens_its_receipt_without_execution() {
    let fixture = Fixture::with_manifest(
        manifest_from_source(one_run_source().as_bytes()),
        &pass_digest(),
    );
    fixture.accept(&fixture.run());
    let extra = fixture.run();
    let mut writer = fixture.store.borrow_mut();
    let metadata = writer
        .declare_metadata_fixture(&fixture.scope, &fixture.input, &extra)
        .unwrap();
    let before = writer.revision().unwrap();
    let request = fixture.request(&extra, PassState::Active(fixture.engagement.pass_digest()));
    let replay = declare(&mut writer, request.declaration).unwrap();
    assert_eq!(replay.acceptance(), &metadata);
    assert!(matches!(
        writer.claim_conflicts(&extra.id, &BTreeSet::from(["resource:metadata".to_owned()])),
        Err(StoreError::Conflict)
    ));
    let refusal = prepare_declared::<FakeServices>(&mut writer, &fixture.locks, replay, || {
        panic!("the adapter opener ran for a metadata-only request")
    })
    .unwrap_err();
    assert_eq!(refusal.code(), ErrorCode::ConflictingRun);
    assert_eq!(writer.revision().unwrap(), before);
    assert!(!writer.conflicts_held(&extra.id).unwrap());
}

#[test]
fn only_validated_preflight_plans_can_gain_execution_eligibility() {
    let fixture = Fixture::new();
    let mut forged_experiment = fixture.run();
    forged_experiment.experiment_digest = Sha256Digest::of(b"unvalidated experiment");
    let bad_rounds = verify_input(&fixture.claim.lead, MAX_SAFE_INTEGER / 35 + 1);
    let overflow = fixture.run();
    let mut writer = fixture.store.borrow_mut();
    let keys = BTreeSet::from(["resource:unvalidated".to_owned()]);

    for (run, input, expected) in [
        (
            &forged_experiment,
            &fixture.input,
            ErrorCode::IntegrityFailure,
        ),
        (&overflow, &bad_rounds, ErrorCode::UsageError),
    ] {
        let mut request = fixture.request(run, PassState::Active(fixture.engagement.pass_digest()));
        request.declaration.input = input;
        let before = writer.revision().unwrap();
        let refusal = declare(&mut writer, request.declaration).unwrap_err();
        assert_eq!(refusal.code(), expected);
        assert_eq!(writer.revision().unwrap(), before);
        assert!(
            writer
                .find_request(&fixture.scope, &run.request_key)
                .unwrap()
                .is_none()
        );

        let metadata = writer
            .declare_metadata_fixture(&fixture.scope, input, run)
            .unwrap();
        let after_metadata = writer.revision().unwrap();
        assert!(matches!(
            writer.claim_conflicts(&run.id, &keys),
            Err(StoreError::Conflict)
        ));
        assert!(matches!(
            writer.record_step(
                &run.id,
                &RunStep {
                    number: 1,
                    step: "unvalidated".parse().unwrap(),
                    request_digest: Sha256Digest::of(b"unvalidated step"),
                    flow_id_floor: None,
                    instrument_reference: None,
                    effects: None,
                    flows: Vec::new(),
                }
            ),
            Err(StoreError::Conflict)
        ));
        assert_eq!(
            writer
                .reopen_request(&fixture.scope, &run.request_key, input)
                .unwrap(),
            metadata
        );
        assert_eq!(writer.revision().unwrap(), after_metadata);
    }
}

#[test]
fn passive_refusal_leaves_the_declared_run_without_execution_history() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let services = fake_for(&fixture, &run);
    *services.refusal.lock().unwrap() = Some(ServiceRefusal::Gate(
        GateRefusalReason::EditSurfaceUnestablished,
    ));
    let request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let mut writer = fixture.store.borrow_mut();
    let declared = declare(&mut writer, request.declaration).unwrap();
    let accepted = declared.acceptance().clone();
    let result = prepare_declared(&mut writer, &fixture.locks, declared, || {
        let mut observer = Store::open(&fixture.path).unwrap();
        assert!(observer.conflicts_held(&run.id).unwrap());
        assert!(matches!(
            observer.reconcile_recorded_step(
                &run.id,
                &RunStep {
                    number: 1,
                    step: "round.1.I1".parse().unwrap(),
                    request_digest: Sha256Digest::of(b"never dispatched"),
                    flow_id_floor: None,
                    instrument_reference: None,
                    effects: None,
                    flows: Vec::new(),
                }
            ),
            Err(StoreError::Conflict)
        ));
        Ok((&services, request.pass))
    });
    assert!(matches!(result, Err(PreflightError::Gate(_))));
    assert!(!writer.conflicts_held(&run.id).unwrap());
    assert!(writer.recover_cleanup(&run.id).unwrap().is_empty());
    assert_eq!(
        writer
            .find_request(&fixture.scope, &run.request_key)
            .unwrap(),
        Some(accepted)
    );
    assert_eq!(services.calls.lock().unwrap().as_slice(), ["admit"]);
}

#[test]
fn live_execution_rejects_swapped_or_unregistered_accounting_before_effects() {
    for missing_registration in [false, true] {
        let fixture = Fixture::new();
        let effects = ExecutionEffects::default();
        let teapot = bound_teapot(
            "engine-admitted",
            fixture.engagement.settings().instrument.project.as_str(),
            "/tmp/scourge-admitted-project",
        )
        .observe_execution_effects(effects.clone());
        let evidence = Evidence::inert_fixture(None);
        let mut prepared = live_prepared(&fixture, &teapot, &evidence, !missing_registration);
        if !missing_registration {
            let binding = AccountingBinding {
                run_id: "R-swapped-accounting".parse().unwrap(),
                request_key: "rk_swapped_accounting".parse().unwrap(),
                pass_id: "fixture-pass".parse().unwrap(),
                pass_digest: fixture.engagement.pass_digest().clone(),
                pass_file: fixture.pass_file.clone(),
            };
            prepared.admission.accounting = AccountingCapture::verification_fixture(
                &teapot,
                binding,
                prepared.execution_plan().required_requests,
                true,
            );
        }
        assert_public_execution_rejection(&fixture, prepared, &teapot, &evidence, &effects);
    }
}

#[test]
fn execution_effect_witnesses_observe_each_local_boundary() {
    let effects = ExecutionEffects::default();
    let artifact = Artifact {
        artifact_id: "art_execution_probe".parse().unwrap(),
        digest: Sha256Digest::of(b"execution probe artifact"),
    };
    let evidence = Evidence::execution_probe(artifact.clone(), effects.clone());
    assert_eq!(
        evidence.describe(&artifact.artifact_id).unwrap().reference,
        artifact
    );
    let run: crate::ids::RunId = "R-execution-probe".parse().unwrap();
    let capture = evidence.capture(&run).unwrap();
    evidence.attach(&capture, 1, "probe", b"probe").unwrap();
    evidence
        .finalize(&capture, Some(1), Completion::Complete, &["probe"])
        .unwrap();

    let teapot = bound_teapot(
        "engine-probe",
        "project.teapot.probe",
        "/tmp/scourge-probe-project",
    )
    .observe_execution_effects(effects.clone());
    assert!(teapot.describe().is_err());

    assert_eq!(
        effects.snapshot(),
        ExecutionEffectsSnapshot {
            store_writer: 0,
            evidence_access: 1,
            evidence_capture: 1,
            evidence_attachment: 1,
            evidence_finalize: 1,
            teapot_process: 1,
        }
    );
}

#[test]
fn live_execution_rejects_a_different_teapot_project_and_engine_before_effects() {
    let fixture = Fixture::new();
    let effects = ExecutionEffects::default();
    let admitted = bound_teapot(
        "engine-admitted",
        fixture.engagement.settings().instrument.project.as_str(),
        "/tmp/scourge-admitted-project",
    )
    .observe_execution_effects(effects.clone());
    let other = bound_teapot(
        "engine-other",
        "project.teapot.other",
        "/tmp/scourge-other-project",
    )
    .observe_execution_effects(effects.clone());
    let evidence = Evidence::inert_fixture(None);
    let prepared = live_prepared(&fixture, &admitted, &evidence, true);
    assert_public_execution_rejection(&fixture, prepared, &other, &evidence, &effects);
}

#[test]
fn live_execution_refreezes_experiment_and_recompiles_exact_sessions_before_effects() {
    let fixture = Fixture::new();
    let effects = ExecutionEffects::default();
    let teapot = bound_teapot(
        "engine-admitted",
        fixture.engagement.settings().instrument.project.as_str(),
        "/tmp/scourge-admitted-project",
    )
    .observe_execution_effects(effects.clone());
    let evidence = Evidence::inert_fixture(None);
    let mut changed_experiment = live_prepared(&fixture, &teapot, &evidence, true);
    changed_experiment
        .experiment
        .principals
        .values_mut()
        .next()
        .unwrap()
        .verifier_session = Some("session.unadmitted".parse().unwrap());
    assert_public_execution_rejection(&fixture, changed_experiment, &teapot, &evidence, &effects);

    let fixture = Fixture::new();
    let effects = ExecutionEffects::default();
    let teapot = bound_teapot(
        "engine-admitted",
        fixture.engagement.settings().instrument.project.as_str(),
        "/tmp/scourge-admitted-project-plan",
    )
    .observe_execution_effects(effects.clone());
    let evidence = Evidence::inert_fixture(None);
    let mut changed_plan = live_prepared(&fixture, &teapot, &evidence, true);
    changed_plan.execution_plan.dispatches[0].session = "unadmitted".parse().unwrap();
    assert_public_execution_rejection(&fixture, changed_plan, &teapot, &evidence, &effects);
}

#[test]
fn compiled_budget_binds_n_rounds_and_refuses_zero_or_overflow_before_admission() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let services = fake_for(&fixture, &run);
    let mut request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let three_rounds = verify_input(&fixture.claim.lead, 3);
    request.declaration.input = &three_rounds;
    let prepared = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &services,
        request,
    )
    .unwrap();
    assert_eq!(prepared.execution_plan().round_count, 3);
    assert_eq!(prepared.execution_plan().requests_per_round, 35);
    assert_eq!(prepared.execution_plan().required_requests, 105);
    let passive = registered_execution_plan(prepared.experiment(), &fixture.engagement, 3).unwrap();
    assert_eq!(&passive, prepared.execution_plan());
    assert_eq!(
        passive
            .dispatches
            .iter()
            .map(|step| step.flow)
            .collect::<Vec<_>>(),
        [
            "I1", "I2", "P", "P2", "F0", "F1", "F2", "F3", "F4", "I3", "I4", "C"
        ]
    );
    assert_eq!(passive.dispatches.last().unwrap().actions, 2);
    drop(prepared);

    let max_admitted_rounds = crate::json_input::MAX_SAFE_INTEGER / 35;
    assert_eq!(max_admitted_rounds, 257_348_550_135_456);
    let fixture = Fixture::new();
    let run = fixture.run();
    let services = fake_for(&fixture, &run);
    let mut request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    let max_rounds = verify_input(&fixture.claim.lead, max_admitted_rounds);
    request.declaration.input = &max_rounds;
    let prepared = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &services,
        request,
    )
    .unwrap();
    assert_eq!(prepared.execution_plan().round_count, max_admitted_rounds);
    assert_eq!(
        prepared.execution_plan().required_requests,
        max_admitted_rounds * 35
    );
    assert_eq!(
        prepared.execution_plan().required_requests,
        9_007_199_254_740_960
    );
    assert!(prepared.execution_plan().required_requests <= crate::json_input::MAX_SAFE_INTEGER);
    assert!(prepared.execution_plan().required_requests + 35 > crate::json_input::MAX_SAFE_INTEGER);
    for round_count in [0, crate::json_input::MAX_SAFE_INTEGER + 1, u64::MAX] {
        let error =
            registered_execution_plan(prepared.experiment(), &fixture.engagement, round_count)
                .unwrap_err();
        assert!(matches!(error, PreflightError::RoundCount));
        assert_eq!(error.code(), ErrorCode::UsageError);
    }
    drop(prepared);

    let too_many_rounds = verify_input(&fixture.claim.lead, max_admitted_rounds + 1);
    let run = fixture.run();
    let services = fake_for(&fixture, &run);
    let mut request = fixture.request(&run, PassState::Active(fixture.engagement.pass_digest()));
    request.declaration.input = &too_many_rounds;
    let error = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &services,
        request,
    )
    .unwrap_err();
    assert!(matches!(error, PreflightError::RoundCount));
    assert_eq!(error.code(), ErrorCode::UsageError);
    assert!(services.calls.lock().unwrap().is_empty());
    assert!(
        fixture
            .store
            .borrow()
            .find_request(&fixture.scope, &run.request_key)
            .unwrap()
            .is_none()
    );
}

#[test]
fn pass_and_session_conflicts_serialize_without_adapter_overlap_and_release() {
    let fixture = Fixture::new();
    let first = fixture.run();
    let first_services = fake_for(&fixture, &first);
    let prepared = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &first_services,
        fixture.request(&first, PassState::Active(fixture.engagement.pass_digest())),
    )
    .unwrap();

    let second = fixture.run();
    let second_services = fake_for(&fixture, &second);
    let error = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &second_services,
        fixture.request(&second, PassState::Active(fixture.engagement.pass_digest())),
    )
    .unwrap_err();
    assert!(matches!(error, PreflightError::Lock(LockError::Busy)));
    assert_eq!(error.code(), ErrorCode::ConflictingRun);
    assert!(second_services.calls.lock().unwrap().is_empty());

    drop(prepared);
    let resumed = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &second_services,
        fixture.request(&second, PassState::Active(fixture.engagement.pass_digest())),
    )
    .unwrap();
    drop(resumed);

    // Different pass locks still conflict on one shared instrument session.
    let common = "session:project:shared".to_owned();
    let one = BTreeSet::from(["pass:one".to_owned(), common.clone()]);
    let two = BTreeSet::from([common, "pass:two".to_owned()]);
    let held = fixture.locks.acquire(&one).unwrap();
    assert!(matches!(fixture.locks.acquire(&two), Err(LockError::Busy)));
    drop(held);
    let released = fixture.locks.acquire(&two).unwrap();
    drop(released);
}

#[test]
fn stale_key_replays_at_exhausted_cap_but_live_resume_checks_the_current_head() {
    let source = one_run_source();
    let stale = Fixture::with_manifest(manifest_from_source(source.as_bytes()), &pass_digest());
    let run = stale.run();
    let acceptance = stale.accept(&run);
    assert_eq!(acceptance.engagement_revision, 1);
    let manifest = stale
        .engagement
        .amend(
            EngagementDraft::parse_toml(source.as_bytes()).unwrap(),
            PassPin {
                reference: &stale.engagement.settings().pass_ref,
                digest: stale.engagement.pass_digest(),
            },
        )
        .unwrap();
    let amended = Artifact {
        artifact_id: "art_manifest_amended".parse().unwrap(),
        digest: manifest.digest().clone(),
    };
    stale
        .store
        .borrow_mut()
        .append_manifest(
            &stale.scope.engagement,
            &amended,
            stale.engagement.pass_digest(),
        )
        .unwrap();

    let before = stale.store.borrow().revision().unwrap();
    let request = || stale.request(&run, PassState::Active(stale.engagement.pass_digest()));
    let original = declare(&mut stale.store.borrow_mut(), request().declaration).unwrap();
    assert_eq!(original.acceptance(), &acceptance);
    let mut current = request().declaration;
    current.engagement = &manifest;
    current.manifest_artifact = &amended;
    // The original claim's engagement pin conflicts with the amended
    // manifest, so resolving it before replay would refuse this request.
    let same_key = declare(&mut stale.store.borrow_mut(), current).unwrap();
    assert_eq!(same_key.acceptance(), &acceptance);
    assert_eq!(stale.store.borrow().revision().unwrap(), before);

    let services = fake_for(&stale, &run);
    let error = prepare(
        &mut stale.store.borrow_mut(),
        &stale.locks,
        &services,
        stale.request(&run, PassState::Active(stale.engagement.pass_digest())),
    )
    .unwrap_err();
    assert!(matches!(
        &error,
        PreflightError::Store(StoreError::RevisionConflict)
    ));
    assert_eq!(error.code(), ErrorCode::RevisionConflict);
    assert!(services.calls.lock().unwrap().is_empty());
    assert!(!stale.store.borrow().conflicts_held(&run.id).unwrap());
    assert_eq!(stale.store.borrow().revision().unwrap(), before);
}

#[test]
fn active_claim_pins_engagement_head() {
    // The opposite writer ordering is also closed: once admission has checked
    // the current head and installed the durable claim in one transaction, an
    // amendment cannot pass the admitted run before execution/reconciliation.
    let pinned = Fixture::new();
    let amended = Artifact {
        artifact_id: "art_manifest_amended".parse().unwrap(),
        digest: Sha256Digest::of(b"amended engagement"),
    };
    let pinned_run = pinned.run();
    let pinned_services = fake_for(&pinned, &pinned_run);
    let prepared = prepare(
        &mut pinned.store.borrow_mut(),
        &pinned.locks,
        &pinned_services,
        pinned.request(
            &pinned_run,
            PassState::Active(pinned.engagement.pass_digest()),
        ),
    )
    .unwrap();
    assert!(prepared.holds_locks());
    pinned
        .store
        .borrow_mut()
        .record_step(
            &pinned_run.id,
            &RunStep {
                number: 1,
                step: "started.before.amendment".parse().unwrap(),
                request_digest: Sha256Digest::of(b"started before amendment"),
                flow_id_floor: None,
                instrument_reference: Some("started-owner".parse().unwrap()),
                effects: Some(Effect::Unknown),
                flows: Vec::new(),
            },
        )
        .unwrap();
    assert!(matches!(
        pinned.store.borrow_mut().append_manifest(
            &pinned.scope.engagement,
            &amended,
            pinned.engagement.pass_digest(),
        ),
        Err(StoreError::RevisionConflict)
    ));
}

#[test]
fn prepared_abandon_and_drop_reclaim_only_before_the_first_step() {
    let dropped = Fixture::new();
    let dropped_run = dropped.run();
    let services = fake_for(&dropped, &dropped_run);
    let prepared = prepare(
        &mut dropped.store.borrow_mut(),
        &dropped.locks,
        &services,
        dropped.request(
            &dropped_run,
            PassState::Active(dropped.engagement.pass_digest()),
        ),
    )
    .unwrap();
    let mut recovery = Store::open(&dropped.path).unwrap();
    assert!(matches!(
        recovery.reconcile_run(&dropped.scope, &dropped_run.id),
        Err(StoreError::Conflict)
    ));
    drop(prepared);
    assert!(
        dropped
            .store
            .borrow()
            .conflicts_held(&dropped_run.id)
            .unwrap()
    );
    let amended = Artifact {
        artifact_id: "art_after_prepared_drop".parse().unwrap(),
        digest: Sha256Digest::of(b"amend after prepared drop"),
    };
    dropped
        .store
        .borrow_mut()
        .append_manifest(
            &dropped.scope.engagement,
            &amended,
            dropped.engagement.pass_digest(),
        )
        .unwrap();
    assert!(
        !dropped
            .store
            .borrow()
            .conflicts_held(&dropped_run.id)
            .unwrap()
    );

    let abandoned = Fixture::new();
    let abandoned_run = abandoned.run();
    let services = fake_for(&abandoned, &abandoned_run);
    let prepared = prepare(
        &mut abandoned.store.borrow_mut(),
        &abandoned.locks,
        &services,
        abandoned.request(
            &abandoned_run,
            PassState::Active(abandoned.engagement.pass_digest()),
        ),
    )
    .unwrap();
    prepared.abandon(&mut abandoned.store.borrow_mut()).unwrap();
    assert!(
        !abandoned
            .store
            .borrow()
            .conflicts_held(&abandoned_run.id)
            .unwrap()
    );
}

#[test]
fn reconciled_capture_only_run_cannot_reprepare_or_open_adapters() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let initial_services = fake_for(&fixture, &run);
    let prepared = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &initial_services,
        fixture.request(&run, PassState::Active(fixture.engagement.pass_digest())),
    )
    .unwrap();
    let handle: crate::evidence::CaptureHandle = "handle_12345678-1234-4234-8234-123456789abc"
        .parse()
        .unwrap();
    fixture
        .store
        .borrow_mut()
        .execution_store(&prepared.authority)
        .unwrap()
        .record_capture_handle(&run.id, &handle)
        .unwrap();
    drop(prepared);

    let reconciled = fixture
        .store
        .borrow_mut()
        .reconcile_run(&fixture.scope, &run.id)
        .unwrap();
    assert!(reconciled.committed);
    assert_eq!(reconciled.effects, Effect::Unknown);
    assert!(fixture.store.borrow().conflicts_held(&run.id).unwrap());

    let retry_services = fake_for(&fixture, &run);
    let before = fixture.store.borrow().revision().unwrap();
    let result = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &retry_services,
        fixture.request(&run, PassState::Active(fixture.engagement.pass_digest())),
    );
    assert!(matches!(result, Err(PreflightError::Replay)));
    assert!(retry_services.calls.lock().unwrap().is_empty());
    assert_eq!(fixture.store.borrow().revision().unwrap(), before);
    assert!(fixture.store.borrow().conflicts_held(&run.id).unwrap());
}

#[test]
fn stop_amendment_retains_active_and_unknown_claims_and_marks_cancellation() {
    for effect in [Effect::Observed, Effect::Unknown] {
        let fixture = Fixture::new();
        let run = fixture.run();
        let services = fake_for(&fixture, &run);
        let prepared = prepare(
            &mut fixture.store.borrow_mut(),
            &fixture.locks,
            &services,
            fixture.request(&run, PassState::Active(fixture.engagement.pass_digest())),
        )
        .unwrap();
        let active_step = RunStep {
            number: 1,
            step: "active.before.stop".parse().unwrap(),
            request_digest: Sha256Digest::of(b"active before stop"),
            flow_id_floor: None,
            instrument_reference: Some("active-owner".parse().unwrap()),
            effects: Some(effect),
            flows: Vec::new(),
        };
        fixture
            .store
            .borrow_mut()
            .record_step(&run.id, &active_step)
            .unwrap();
        let stopped = Artifact {
            artifact_id: format!("art_stop_{effect:?}")
                .to_lowercase()
                .parse()
                .unwrap(),
            digest: Sha256Digest::of(format!("stop {effect:?}").as_bytes()),
        };
        fixture
            .store
            .borrow_mut()
            .append_stop_manifest(
                &fixture.scope.engagement,
                &stopped,
                fixture.engagement.pass_digest(),
            )
            .unwrap();
        assert!(fixture.store.borrow().conflicts_held(&run.id).unwrap());
        let stored = fixture
            .store
            .borrow()
            .find_request(&fixture.scope, &run.request_key)
            .unwrap()
            .unwrap();
        assert!(stored.run.flags.contains(&RunFlag::CancelRequested));

        // A worker may have loaded its run metadata before the stop revision.
        // Its later reconciliation cannot erase the monotonic cancellation
        // intent while recording the already-started effect.
        let mut stale_update = prepared.acceptance().run.clone();
        stale_update.state = RunState::Running;
        stale_update.effects = effect;
        stale_update.steps.push(active_step);
        fixture
            .store
            .borrow_mut()
            .record_run(&stale_update, Some(prepared.acceptance().receipt))
            .unwrap();
        let reconciled = fixture
            .store
            .borrow()
            .find_request(&fixture.scope, &run.request_key)
            .unwrap()
            .unwrap();
        assert!(reconciled.run.flags.contains(&RunFlag::CancelRequested));
        assert!(matches!(
            fixture.store.borrow_mut().append_manifest(
                &fixture.scope.engagement,
                &Artifact {
                    artifact_id: "art_ordinary_while_stopping".parse().unwrap(),
                    digest: Sha256Digest::of(b"ordinary while stopping"),
                },
                fixture.engagement.pass_digest(),
            ),
            Err(StoreError::RevisionConflict)
        ));
        drop(prepared);
    }

    // If the stop revision wins before claim acquisition, the old accepted
    // request is stale and refuses before any adapter instead.
    let stopped_first = Fixture::new();
    let run = stopped_first.run();
    let acceptance = stopped_first.accept(&run);
    stopped_first
        .store
        .borrow_mut()
        .append_stop_manifest(
            &stopped_first.scope.engagement,
            &Artifact {
                artifact_id: "art_stop_first".parse().unwrap(),
                digest: Sha256Digest::of(b"stop first"),
            },
            stopped_first.engagement.pass_digest(),
        )
        .unwrap();
    assert_eq!(
        stopped_first
            .store
            .borrow_mut()
            .reopen_request(&stopped_first.scope, &run.request_key, &stopped_first.input,)
            .unwrap(),
        acceptance
    );
    let services = fake_for(&stopped_first, &run);
    let error = prepare(
        &mut stopped_first.store.borrow_mut(),
        &stopped_first.locks,
        &services,
        stopped_first.request(
            &run,
            PassState::Active(stopped_first.engagement.pass_digest()),
        ),
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::RevisionConflict);
    assert!(services.calls.lock().unwrap().is_empty());
}

#[test]
fn stop_fence_refuses_new_and_preaccepted_admission_until_explicit_resume() {
    let stopped = Fixture::new();
    stopped
        .store
        .borrow_mut()
        .append_stop_manifest(
            &stopped.scope.engagement,
            &Artifact {
                artifact_id: "art_durable_stop".parse().unwrap(),
                digest: Sha256Digest::of(b"durable stop"),
            },
            stopped.engagement.pass_digest(),
        )
        .unwrap();

    // A request minted after the stop would bind the stop revision itself, so
    // revision equality alone is insufficient. The durable fence refuses it
    // before a row, conflict claim, adapter, or target effect exists.
    let first = stopped.run();
    let services = fake_for(&stopped, &first);
    let error = prepare(
        &mut stopped.store.borrow_mut(),
        &stopped.locks,
        &services,
        stopped.request(&first, PassState::Active(stopped.engagement.pass_digest())),
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::RevisionConflict);
    assert!(services.calls.lock().unwrap().is_empty());
    assert!(
        stopped
            .store
            .borrow()
            .find_request(&stopped.scope, &first.request_key)
            .unwrap()
            .is_none()
    );

    // An ordinary amendment does not silently resume admission.
    stopped
        .store
        .borrow_mut()
        .append_manifest(
            &stopped.scope.engagement,
            &Artifact {
                artifact_id: "art_while_stopped".parse().unwrap(),
                digest: Sha256Digest::of(b"ordinary while stopped"),
            },
            stopped.engagement.pass_digest(),
        )
        .unwrap();
    let still_stopped = stopped.run();
    assert!(matches!(
        stopped.store.borrow_mut().declare_metadata_fixture(
            &stopped.scope,
            &stopped.input,
            &still_stopped
        ),
        Err(StoreError::RevisionConflict)
    ));

    // Only the named lifecycle transition clears the fence. A new request can
    // then accept the resumed head and acquire its exact durable claim.
    let mut resumed_manifest = stopped.engagement.clone();
    for _ in 0..3 {
        resumed_manifest = resumed_manifest
            .amend(
                EngagementDraft::parse_toml(ENGAGEMENT).unwrap(),
                PassPin {
                    reference: &stopped.engagement.settings().pass_ref,
                    digest: stopped.engagement.pass_digest(),
                },
            )
            .unwrap();
    }
    let manifest_artifact = Artifact {
        artifact_id: "art_explicit_resume".parse().unwrap(),
        digest: resumed_manifest.digest().clone(),
    };
    stopped
        .store
        .borrow_mut()
        .append_resume_manifest(
            &stopped.scope.engagement,
            &manifest_artifact,
            stopped.engagement.pass_digest(),
        )
        .unwrap();
    let mut resumed_claim = stopped.claim.clone();
    resumed_claim.engagement = EngagementPin {
        revision: resumed_manifest.revision(),
        digest: resumed_manifest.digest().clone(),
    };
    let experiment_digest = Templates::resolve(&resumed_claim, &resumed_manifest)
        .unwrap()
        .ready()
        .unwrap()
        .freeze()
        .unwrap()
        .1;
    let resumed = Run::declare(stopped.scope.engagement.clone(), experiment_digest);
    declare(
        &mut stopped.store.borrow_mut(),
        PreflightDeclaration {
            scope: &stopped.scope,
            input: &stopped.input,
            run: &resumed,
            claim: &resumed_claim,
            lead_revision: 1,
            engagement: &resumed_manifest,
            manifest_artifact: &manifest_artifact,
        },
    )
    .unwrap();
    stopped
        .store
        .borrow_mut()
        .claim_conflicts(
            &resumed.id,
            &BTreeSet::from(["resource:resumed".to_owned()]),
        )
        .unwrap();

    // The opposite ordering shares the same rule: an acceptance committed
    // before stop cannot claim afterward even if the caller skips prepare.
    let preaccepted = Fixture::new();
    let run = preaccepted.run();
    preaccepted.accept(&run);
    preaccepted
        .store
        .borrow_mut()
        .append_stop_manifest(
            &preaccepted.scope.engagement,
            &Artifact {
                artifact_id: "art_stop_before_claim".parse().unwrap(),
                digest: Sha256Digest::of(b"stop before claim"),
            },
            preaccepted.engagement.pass_digest(),
        )
        .unwrap();
    assert!(matches!(
        preaccepted
            .store
            .borrow_mut()
            .claim_conflicts(&run.id, &BTreeSet::from(["resource:late-claim".to_owned()])),
        Err(StoreError::RevisionConflict)
    ));
    assert!(!preaccepted.store.borrow().conflicts_held(&run.id).unwrap());
}

#[test]
fn errors_and_unwinding_release_locks_and_retry_preflight_idempotently() {
    let fixture = Fixture::new();
    let keys = BTreeSet::from(["pass:panic".to_owned(), "session:panic".to_owned()]);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lease = fixture.locks.acquire(&keys).unwrap();
        panic!("simulated worker crash");
    }));
    assert!(unwound.is_err());
    assert!(fixture.locks.acquire(&keys).is_ok());

    let run = fixture.run();
    let corrupt = fake_for(&fixture, &run);
    corrupt.mutate_readback.store(true, Ordering::SeqCst);
    let error = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &corrupt,
        fixture.request(&run, PassState::Active(fixture.engagement.pass_digest())),
    )
    .unwrap_err();
    assert!(matches!(error, PreflightError::EvidenceMismatch));
    assert_eq!(error.code(), ErrorCode::IntegrityFailure);

    corrupt.mutate_readback.store(false, Ordering::SeqCst);
    let prepared = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &corrupt,
        fixture.request(&run, PassState::Active(fixture.engagement.pass_digest())),
    )
    .unwrap();
    assert_eq!(corrupt.artifacts.lock().unwrap().len(), 1);
    drop(prepared);

    // A persisted step intent is the local start boundary. The same key can
    // no longer re-enter adapters, so recovery cannot repeat target work.
    fixture
        .store
        .borrow_mut()
        .record_step(
            &run.id,
            &RunStep {
                number: 1,
                step: "probe.owner.first".parse().unwrap(),
                request_digest: Sha256Digest::of(b"step intent"),
                flow_id_floor: None,
                instrument_reference: None,
                effects: None,
                flows: Vec::new(),
            },
        )
        .unwrap();
    let quiet = FakeServices::default();
    let replay = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &quiet,
        fixture.request(&run, PassState::Active(fixture.engagement.pass_digest())),
    )
    .unwrap_err();
    assert!(matches!(replay, PreflightError::Replay));
    assert_eq!(replay.code(), ErrorCode::ConflictingRun);
    assert!(quiet.calls.lock().unwrap().is_empty());
}

#[test]
fn typed_refusals_precede_all_adapters() {
    let fixture = Fixture::new();
    let run = fixture.run();
    let services = fake_for(&fixture, &run);
    let error = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &services,
        fixture.request(&run, PassState::Changed),
    )
    .unwrap_err();
    assert!(matches!(error, PreflightError::Pass(PassRefusal::Changed)));
    assert_eq!(error.code(), ErrorCode::AuthorityRequired);
    assert!(services.calls.lock().unwrap().is_empty());

    let mut incomplete = fixture.claim.clone();
    incomplete.lead_slots.clear();
    let arbitrary = Run::declare(
        fixture.scope.engagement.clone(),
        Sha256Digest::of(b"incomplete"),
    );
    let mut request = fixture.request(
        &arbitrary,
        PassState::Active(fixture.engagement.pass_digest()),
    );
    request.declaration.claim = &incomplete;
    let quiet = FakeServices::default();
    let error = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &quiet,
        request,
    )
    .unwrap_err();
    assert!(matches!(error, PreflightError::MissingSlots(_)));
    assert_eq!(error.code(), ErrorCode::SlotsIncomplete);
    assert!(quiet.calls.lock().unwrap().is_empty());
}

#[test]
fn authority_refusals_are_driven_through_preflight_with_exact_codes() {
    #[derive(Clone, Copy, Debug)]
    enum Case {
        Changed,
        Expired,
        Revoked,
        ActiveWrongDigest,
        WrongReference,
    }
    for (case, expected) in [
        (Case::Changed, ErrorCode::AuthorityRequired),
        (Case::Expired, ErrorCode::AuthorityRequired),
        (Case::Revoked, ErrorCode::AuthorityRequired),
        (Case::ActiveWrongDigest, ErrorCode::AuthorityRequired),
        (Case::WrongReference, ErrorCode::ScopeRefused),
    ] {
        let fixture = Fixture::new();
        let run = fixture.run();
        let services = fake_for(&fixture, &run);
        let wrong_digest = Sha256Digest::of(b"wrong current pass");
        let state = match case {
            Case::Changed | Case::WrongReference => PassState::Changed,
            Case::Expired => PassState::Expired,
            Case::Revoked => PassState::Revoked,
            Case::ActiveWrongDigest => PassState::Active(&wrong_digest),
        };
        let mut request = fixture.request(&run, state);
        let wrong_reference: PassRef = "pass.other".parse().unwrap();
        if matches!(case, Case::WrongReference) {
            request.pass.pass_reference = &wrong_reference;
            request.pass.pass_state = PassState::Active(fixture.engagement.pass_digest());
        }
        let error = prepare(
            &mut fixture.store.borrow_mut(),
            &fixture.locks,
            &services,
            request,
        )
        .unwrap_err();
        assert_eq!(error.code(), expected, "{case:?}");
        assert!(services.calls.lock().unwrap().is_empty());
        assert!(!fixture.store.borrow().conflicts_held(&run.id).unwrap());
    }
}

#[test]
fn reachable_adapter_refusals_are_table_driven_and_release_unstarted_claims() {
    use GateRefusalReason as Gate;

    let cases = [
        (
            ServiceRefusal::Gate(Gate::EngineUnestablished),
            ErrorCode::EnforcementUnavailable,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Gate(Gate::EnforcementUnestablished),
            ErrorCode::EnforcementUnavailable,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Gate(Gate::EnforcementRequired),
            ErrorCode::EnforcementUnavailable,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Gate(Gate::PassNotEnforceable),
            ErrorCode::EnforcementUnavailable,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Gate(Gate::EditSurfaceUnestablished),
            ErrorCode::InstrumentEditsActive,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Gate(Gate::ActiveRule),
            ErrorCode::InstrumentEditsActive,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Gate(Gate::ActiveIntercept),
            ErrorCode::InstrumentEditsActive,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Gate(Gate::ActiveScriptHook),
            ErrorCode::InstrumentEditsActive,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Gate(Gate::SessionBehavior),
            ErrorCode::InstrumentEditsActive,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Gate(Gate::EditableConfiguration),
            ErrorCode::InstrumentEditsActive,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Accounting(AccountingRefusal::CeilingUnknown),
            ErrorCode::AccountingUnestablished,
            &["admit"][..],
        ),
        (
            ServiceRefusal::Accounting(AccountingRefusal::CeilingExceeded),
            ErrorCode::BudgetRefused,
            &["admit"][..],
        ),
        (
            ServiceRefusal::EvidenceRecordMissing,
            ErrorCode::EvidenceIncomplete,
            &["admit", "record"][..],
        ),
        (
            ServiceRefusal::EvidenceRecordUnavailable,
            ErrorCode::DependencyUnavailable,
            &["admit", "record"][..],
        ),
        (
            ServiceRefusal::EvidenceReadIntegrity,
            ErrorCode::IntegrityFailure,
            &["admit", "record", "read"][..],
        ),
    ];
    for (refusal, expected, calls) in cases {
        let fixture = Fixture::new();
        let run = fixture.run();
        let mut services = fake_for(&fixture, &run);
        services.refusal = Mutex::new(Some(refusal));
        let error = prepare(
            &mut fixture.store.borrow_mut(),
            &fixture.locks,
            &services,
            fixture.request(&run, PassState::Active(fixture.engagement.pass_digest())),
        )
        .unwrap_err();
        assert_eq!(error.code(), expected, "{refusal:?}");
        assert_eq!(services.calls.lock().unwrap().as_slice(), calls);
        assert!(!fixture.store.borrow().conflicts_held(&run.id).unwrap());
    }
}

#[test]
fn stable_pass_and_global_resource_keys_cover_revision_and_project_changes() {
    let fixture = Fixture::new();
    let first_experiment = Templates::resolve(&fixture.claim, &fixture.engagement)
        .unwrap()
        .ready()
        .unwrap();

    let changed_digest = Sha256Digest::of(b"amended pass bytes");
    let changed_pass =
        manifest_with_route("project.teapot.development", &pass_ref(), &changed_digest);
    let mut changed_claim = fixture.claim.clone();
    changed_claim.engagement = EngagementPin {
        revision: changed_pass.revision(),
        digest: changed_pass.digest().clone(),
    };
    let changed_experiment = Templates::resolve(&changed_claim, &changed_pass)
        .unwrap()
        .ready()
        .unwrap();
    let (_, first_keys) = lock_inputs(&first_experiment, &fixture.engagement).unwrap();
    let (_, changed_keys) = lock_inputs(&changed_experiment, &changed_pass).unwrap();
    assert_eq!(first_keys, changed_keys);
    assert!(first_keys.contains("pass:pass.development-fixture"));

    let other_pass: PassRef = "pass.other-fixture".parse().unwrap();
    let other = manifest_with_route(
        "project.teapot.other",
        &other_pass,
        &Sha256Digest::of(b"other pass"),
    );
    let mut other_claim = fixture.claim.clone();
    other_claim.engagement = EngagementPin {
        revision: other.revision(),
        digest: other.digest().clone(),
    };
    let other_experiment = Templates::resolve(&other_claim, &other)
        .unwrap()
        .ready()
        .unwrap();
    let (_, other_keys) = lock_inputs(&other_experiment, &other).unwrap();
    let shared = first_keys
        .intersection(&other_keys)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        shared,
        BTreeSet::from(["resource:resource.orders".to_owned()])
    );
    assert!(
        first_keys
            .iter()
            .any(|key| key == "session:project.teapot.development:alice")
    );
    assert!(
        other_keys
            .iter()
            .any(|key| key == "session:project.teapot.other:alice")
    );

    let held = fixture.locks.acquire(&first_keys).unwrap();
    assert!(matches!(
        fixture.locks.acquire(&other_keys),
        Err(LockError::Busy)
    ));
    drop(held);
}

#[test]
fn durable_claims_are_atomic_and_release_only_after_resolved_terminal_state() {
    let fixture = Fixture::new();
    let owner = fixture.run();
    let owner_acceptance = fixture.accept(&owner);
    let blocked = BTreeSet::from(["resource:blocked".to_owned()]);
    fixture
        .store
        .borrow_mut()
        .claim_conflicts(&owner.id, &blocked)
        .unwrap();
    let mut intent = RunStep {
        number: 1,
        step: "plant.first".parse().unwrap(),
        request_digest: Sha256Digest::of(b"durable intent"),
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        flows: Vec::new(),
    };
    fixture
        .store
        .borrow_mut()
        .record_step(&owner.id, &intent)
        .unwrap();

    let contender = fixture.run();
    fixture.accept(&contender);
    let partial = BTreeSet::from([
        "resource:available".to_owned(),
        "resource:blocked".to_owned(),
    ]);
    assert!(matches!(
        fixture
            .store
            .borrow_mut()
            .claim_conflicts(&contender.id, &partial),
        Err(StoreError::Conflict)
    ));
    assert!(
        !fixture
            .store
            .borrow()
            .conflicts_held(&contender.id)
            .unwrap()
    );

    let independent = fixture.run();
    fixture.accept(&independent);
    fixture
        .store
        .borrow_mut()
        .claim_conflicts(
            &independent.id,
            &BTreeSet::from(["resource:available".to_owned()]),
        )
        .unwrap();

    intent.effects = Some(Effect::None);
    fixture
        .store
        .borrow_mut()
        .record_step(&owner.id, &intent)
        .unwrap();
    let mut settled = owner_acceptance.run;
    settled.state = RunState::Finalized;
    settled.effects = Effect::None;
    fixture
        .store
        .borrow_mut()
        .record_run(&settled, Some(owner_acceptance.receipt))
        .unwrap();
    assert!(!fixture.store.borrow().conflicts_held(&owner.id).unwrap());
    fixture
        .store
        .borrow_mut()
        .claim_conflicts(&contender.id, &blocked)
        .unwrap();
}

#[test]
fn durable_started_claim_survives_owner_sigkill_while_dispatched_job_continues() {
    let fixture = Fixture::new();
    let owner = fixture.run();
    fixture.accept(&owner);
    let experiment = Templates::resolve(&fixture.claim, &fixture.engagement)
        .unwrap()
        .ready()
        .unwrap();
    let (_, keys) = lock_inputs(&experiment, &fixture.engagement).unwrap();

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener
        .set_nonblocking(false)
        .expect("owned positive-control sink is blocking");
    let target = listener.local_addr().unwrap();
    let mut owner_process = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "preflight::tests::durable_claim_owner_child",
            "--ignored",
            "--nocapture",
        ])
        .env("SCOURGE_CONFLICT_CHILD_DB", &fixture.path)
        .env("SCOURGE_CONFLICT_CHILD_ROOT", fixture._dir.path())
        .env("SCOURGE_CONFLICT_CHILD_RUN", owner.id.as_str())
        .env(
            "SCOURGE_CONFLICT_CHILD_KEYS",
            serde_json::to_string(&keys).unwrap(),
        )
        .env("SCOURGE_CONFLICT_CHILD_TARGET", target.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let ready = BufReader::new(owner_process.stdout.take().unwrap())
        .lines()
        .map(|line| line.unwrap())
        .find(|line| line.contains("conflict-owner-ready"))
        .expect("owner claimed and persisted its start intent");
    assert!(ready.contains(owner.id.as_str()));
    owner_process.kill().unwrap();
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(owner_process.wait().unwrap().signal(), Some(9));

    listener
        .set_nonblocking(false)
        .expect("positive-control sink stays connected");
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = String::new();
    stream.read_to_string(&mut request).unwrap();
    assert_eq!(request, "started effect from surviving job");

    let contender = fixture.run();
    let services = fake_for(&fixture, &contender);
    let refusal = prepare(
        &mut fixture.store.borrow_mut(),
        &fixture.locks,
        &services,
        fixture.request(
            &contender,
            PassState::Active(fixture.engagement.pass_digest()),
        ),
    )
    .unwrap_err();
    assert!(matches!(
        refusal,
        PreflightError::Store(StoreError::Conflict)
    ));
    assert_eq!(refusal.code(), ErrorCode::ConflictingRun);
    assert!(services.calls.lock().unwrap().is_empty());
}

#[test]
fn durable_unstarted_claim_after_sigkill_is_reclaimed_by_ordered_amendment() {
    let fixture = Fixture::new();
    let owner = fixture.run();
    fixture.accept(&owner);
    let experiment = Templates::resolve(&fixture.claim, &fixture.engagement)
        .unwrap()
        .ready()
        .unwrap();
    let (_, keys) = lock_inputs(&experiment, &fixture.engagement).unwrap();
    let mut owner_process = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "preflight::tests::durable_claim_owner_child",
            "--ignored",
            "--nocapture",
        ])
        .env("SCOURGE_CONFLICT_CHILD_DB", &fixture.path)
        .env("SCOURGE_CONFLICT_CHILD_ROOT", fixture._dir.path())
        .env("SCOURGE_CONFLICT_CHILD_RUN", owner.id.as_str())
        .env(
            "SCOURGE_CONFLICT_CHILD_KEYS",
            serde_json::to_string(&keys).unwrap(),
        )
        .env("SCOURGE_CONFLICT_CHILD_UNSTARTED", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    BufReader::new(owner_process.stdout.take().unwrap())
        .lines()
        .map(|line| line.unwrap())
        .find(|line| line.contains("conflict-owner-ready"))
        .expect("owner durably claimed before its first step");
    owner_process.kill().unwrap();
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(owner_process.wait().unwrap().signal(), Some(9));
    assert!(fixture.store.borrow().conflicts_held(&owner.id).unwrap());
    assert!(
        fixture
            .store
            .borrow()
            .find_request(&fixture.scope, &owner.request_key)
            .unwrap()
            .unwrap()
            .run
            .steps
            .is_empty()
    );

    let amended = Artifact {
        artifact_id: "art_after_unstarted_sigkill".parse().unwrap(),
        digest: Sha256Digest::of(b"amend after unstarted sigkill"),
    };
    fixture
        .store
        .borrow_mut()
        .append_manifest(
            &fixture.scope.engagement,
            &amended,
            fixture.engagement.pass_digest(),
        )
        .unwrap();
    assert!(!fixture.store.borrow().conflicts_held(&owner.id).unwrap());
    assert!(matches!(
        fixture.store.borrow_mut().record_step(
            &owner.id,
            &RunStep {
                number: 1,
                step: "late.start".parse().unwrap(),
                request_digest: Sha256Digest::of(b"late start"),
                flow_id_floor: None,
                instrument_reference: None,
                effects: None,
                flows: Vec::new(),
            },
        ),
        Err(StoreError::Conflict)
    ));
}

#[test]
#[ignore = "subprocess helper for durable conflict ownership"]
fn durable_claim_owner_child() {
    let Some(database) = std::env::var_os("SCOURGE_CONFLICT_CHILD_DB") else {
        return;
    };
    let root = Path::new(
        std::env::var_os("SCOURGE_CONFLICT_CHILD_ROOT")
            .unwrap()
            .as_os_str(),
    )
    .to_path_buf();
    let run: crate::ids::RunId = std::env::var("SCOURGE_CONFLICT_CHILD_RUN")
        .unwrap()
        .parse()
        .unwrap();
    let keys: BTreeSet<String> =
        serde_json::from_str(&std::env::var("SCOURGE_CONFLICT_CHILD_KEYS").unwrap()).unwrap();
    let unstarted = std::env::var_os("SCOURGE_CONFLICT_CHILD_UNSTARTED").is_some();
    let locks = RunLocks::open(&root).unwrap();
    let _lease = locks.acquire(&keys).unwrap();
    let mut store = Store::open(database).unwrap();
    store.claim_conflicts(&run, &keys).unwrap();
    if !unstarted {
        store
            .record_step(
                &run,
                &RunStep {
                    number: 1,
                    step: "plant.first".parse().unwrap(),
                    request_digest: Sha256Digest::of(b"started effect"),
                    flow_id_floor: None,
                    instrument_reference: Some("surviving-job".parse().unwrap()),
                    effects: Some(Effect::Unknown),
                    flows: Vec::new(),
                },
            )
            .unwrap();
        let surviving_job = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "preflight::tests::durable_job_child",
                "--ignored",
                "--nocapture",
            ])
            .env(
                "SCOURGE_CONFLICT_JOB_TARGET",
                std::env::var("SCOURGE_CONFLICT_CHILD_TARGET").unwrap(),
            )
            .env_remove("SCOURGE_CONFLICT_CHILD_DB")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // This job models an already-dispatched target effect. It deliberately
        // outlives the verifier so the parent can prove that SIGKILL releases
        // the kernel lease without releasing the durable conflict claim.
        std::mem::forget(surviving_job);
    }
    println!("conflict-owner-ready {}", run.as_str());
    std::io::stdout().flush().unwrap();
    let mut wait = Vec::new();
    std::io::stdin().read_to_end(&mut wait).unwrap();
}

#[test]
#[ignore = "subprocess helper for durable conflict ownership"]
fn durable_job_child() {
    let Some(target) = std::env::var_os("SCOURGE_CONFLICT_JOB_TARGET") else {
        return;
    };
    thread::sleep(Duration::from_millis(250));
    let mut stream = TcpStream::connect(target.to_str().unwrap()).unwrap();
    stream
        .write_all(b"started effect from surviving job")
        .unwrap();
}

#[test]
fn registered_error_mapping_and_unsafe_lock_namespace_fail_closed() {
    assert_eq!(
        PreflightError::Pass(PassRefusal::Expired).code(),
        ErrorCode::AuthorityRequired
    );
    assert_eq!(
        PreflightError::AccountingPreflight(AccountingRefusal::CeilingExceeded).code(),
        ErrorCode::BudgetRefused
    );
    assert_eq!(
        PreflightError::AccountingPreflight(AccountingRefusal::CeilingUnknown).code(),
        ErrorCode::AccountingUnestablished
    );
    assert_eq!(
        PreflightError::Evidence(EvidenceError::Missing).code(),
        ErrorCode::EvidenceIncomplete
    );
    assert_eq!(
        PreflightError::Evidence(EvidenceError::UnqualifiedInvestigation).code(),
        ErrorCode::DependencyUnavailable
    );

    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o777),
    )
    .unwrap();
    assert!(matches!(RunLocks::open(dir.path()), Err(LockError::Unsafe)));
}
