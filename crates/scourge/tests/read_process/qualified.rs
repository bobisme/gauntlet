use super::*;
use scourge_core::{
    engagement::{EngagementDraft, ManifestRevision, PassPin},
    evidence::{Completion, Evidence, RecordKind, RecordRequest},
    ids::RunId,
    rounds::TargetOrigin,
    teapot::BoundEngine,
    verification::{
        coherent_read::{self, Freshness},
        status::{Audience, Status},
    },
    workspace::{
        self, Authority, BoundWorkspace, InvestigationAuthority, ManifestArtifactKind,
        ManifestArtifactPin, ManifestAuthority, PassAuthority, TeapotProjectAuthority,
        VerifierRuntimeAuthority,
    },
};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

fn manifest() -> ManifestRevision {
    let draft = EngagementDraft::parse_toml(DECLARATION).unwrap();
    let pass = draft.settings().pass_ref.clone();
    draft
        .accept(PassPin {
            reference: &pass,
            digest: &Sha256Digest::of(b"archived fixture pass"),
        })
        .unwrap()
}

fn investigation(root: &Path, executable: PathBuf) -> InvestigationAuthority {
    let investigation = InvestigationAuthority {
        executable,
        case_root: root.join("cases"),
        workspace_root: root.join("cases/archive"),
        import_root: root.join("import"),
        scratch_root: root.join("scratch"),
    };
    fs::create_dir(&investigation.case_root).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&investigation.scratch_root)
        .unwrap();
    investigation
}

fn bind(
    root: &Path,
    investigation: InvestigationAuthority,
    manifest: &ManifestRevision,
    pin: ManifestArtifactPin,
) -> BoundWorkspace {
    let runtime = VerifierRuntimeAuthority {
        manifest: ManifestAuthority {
            revision: manifest.revision(),
            digest: manifest.digest().clone(),
            canonical_bytes: manifest.canonical_bytes().to_vec(),
            artifact: pin,
        },
        pass: PassAuthority {
            path: root.join("unused pass file"),
            digest: manifest.pass_digest().clone(),
        },
        teapot: TeapotProjectAuthority {
            executable: root.join("unused Teapot executable"),
            project: root.join("unused Teapot project"),
            home: root.join("unused Teapot home"),
            config_home: None,
            data_home: None,
            state_home: None,
            cache_home: None,
            runtime_dir: None,
            wrapper: false,
        },
        engine: BoundEngine {
            instance: "fixture".parse().unwrap(),
            project_id: "fixture".parse().unwrap(),
            enforced: true,
            policy_locked: true,
        },
        investigation,
        target: manifest.target_version().clone(),
        origin: TargetOrigin::parse("http://fixture.invalid").unwrap(),
        environment_kind: scourge_core::wire::EnvironmentKind::Simulated,
        custody: scourge_core::wire::Custody::Shared,
        target_isolation: scourge_core::wire::TargetIsolation::SeparatePrincipalsUnconfined,
        principal_slots: Default::default(),
    };
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    workspace::init(
        &root.join("workspace"),
        &state,
        SCOPE,
        DECLARATION,
        Authority {
            verifier_runtime: [(SCOPE.into(), runtime)].into(),
            ..Authority::default()
        },
    )
    .unwrap()
}

fn publish(
    root: &Path,
    bound: &BoundWorkspace,
    manifest: &Artifact,
    pass: &Sha256Digest,
    evidence: Option<&Evidence>,
) {
    let mut store = bound.open_coordination_writer().unwrap();
    let engagement = SCOPE.parse().unwrap();
    store.append_manifest(&engagement, manifest, pass).unwrap();
    seed_lead(&mut store, SCOPE, "L-linked", 1);
    seed_lead(&mut store, SCOPE, "L-local", 1);
    let mut run = Run::declare(engagement.clone(), manifest.digest.clone());
    run.state = RunState::Finalized;
    historical_run::seed(&root.join("workspace/.scourge/state.sqlite3"), &run);
    let (_, head) = store.checkpoint(&engagement).unwrap();
    let mut index = VerificationIndex {
        engagement: engagement.clone(),
        sequence: head.sequence + 1,
        record_id: "V-fixture".parse().unwrap(),
        run_id: run.id.clone(),
        lead_id: "L-linked".parse().unwrap(),
        record: manifest.clone(),
    };
    let bytes = verification_bytes(&index, &run, head.record_digest.as_ref());
    let inputs = std::slice::from_ref(manifest);
    let artifact = evidence.map_or_else(
        || Artifact {
            artifact_id: "local-record".parse().unwrap(),
            digest: Sha256Digest::of(&bytes),
        },
        |evidence| {
            evidence
                .record(RecordRequest {
                    key: "fixture verification record",
                    kind: RecordKind::VerificationRecord,
                    bytes: &bytes,
                    inputs,
                    transformation: "evaluate compiled oracle and build verification record",
                    version: "scourge.verification.v1",
                })
                .unwrap()
                .reference
        },
    );
    index.record = artifact.clone();
    let intent = PublicationIntentV1 {
        schema: PublicationIntentV1Tag::PublicationIntentV1,
        intent_id: "P-fixture".parse().unwrap(),
        run_id: run.id,
        engagement,
        expected_head: head,
        record_id: index.record_id.clone(),
        record_digest: artifact.digest.clone(),
        state: PublicationState::Pending,
        artifact_id: None,
    };
    // This integration fixture restores a completed historical receipt
    // directly. Production publication is evaluator-owned and deliberately
    // exposes neither staging bytes nor a low-level completion API.
    historical_run::seed_linked_record(
        &root.join("workspace/.scourge/state.sqlite3"),
        &intent,
        &index,
        Some(&bytes),
    );
}

fn stock(root: &Path, args: &[&str], code: Option<ErrorCode>) -> ResponseV1 {
    let output = stock_command(&root.join("workspace"), &root.join("state"))
        .args(["--engagement", SCOPE, "--json"])
        .args(args)
        .output()
        .unwrap();
    let view = response(&output, code.map_or(0, |code| i32::from(code.exit_code()))).0;
    assert_eq!(view.error.as_ref().map(|error| error.code), code);
    view
}

fn passive_reads_stay_local() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut investigation = investigation(&root, root.join("unavailable executable"));
    investigation.workspace_root = root.join("outside approved case root");
    let manifest = manifest();
    let pin = ManifestArtifactPin {
        kind: ManifestArtifactKind::EngagementManifest,
        reference: Artifact {
            artifact_id: "art_10000000-0000-4000-8000-000000000001".parse().unwrap(),
            digest: manifest.digest().clone(),
        },
        revision: 1,
        size_bytes: manifest.canonical_bytes().len(),
        source_id: "src_10000000-0000-4000-8000-000000000001".parse().unwrap(),
    };
    let bound = bind(&root, investigation, &manifest, pin.clone());
    publish(&root, &bound, &pin.reference, manifest.pass_digest(), None);
    for args in [
        &["doctor"][..],
        &["list", "findings"],
        &["show", "L-local", "--depth", "full"],
        &["show", "L-linked", "--depth", "summary"],
        &["show", "finding:L-linked", "--depth", "title"],
        &["show", "V-fixture", "--depth", "full"],
    ] {
        assert!(stock(&root, args, None).ok);
    }
    for id in ["L-linked", "finding:L-linked"] {
        stock(
            &root,
            &["show", id, "--depth", "full"],
            Some(ErrorCode::IntegrityFailure),
        );
    }
    assert_eq!(root.join("scratch").read_dir().unwrap().count(), 0);
}

fn qualified_backend(binary: PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let paths = investigation(&root, binary);
    let evidence =
        Evidence::initialize(&paths.executable, &paths.workspace_root, &paths.import_root).unwrap();
    let capture = evidence.capture(&RunId::generate()).unwrap();
    evidence
        .attach(&capture, 1, "description", b"fixture manifest origin")
        .unwrap();
    let original = evidence
        .finalize(&capture, Some(1), Completion::Complete, &["description"])
        .unwrap()
        .original_artifacts
        .remove(0)
        .artifact;
    let manifest = manifest();
    let retained = evidence
        .record(RecordRequest {
            key: "fixture acceptance",
            kind: RecordKind::EngagementManifest,
            bytes: manifest.canonical_bytes(),
            inputs: &[original],
            transformation: "accept local declaration",
            version: "1",
        })
        .unwrap();
    let pin = ManifestArtifactPin {
        kind: ManifestArtifactKind::EngagementManifest,
        reference: retained.reference,
        revision: retained.revision,
        size_bytes: retained.size_bytes,
        source_id: retained.source_id.parse().unwrap(),
    };
    let scratch = paths.scratch_root.clone();
    let bound = bind(&root, paths, &manifest, pin.clone());
    let qualified = bound
        .open_verifier_evidence(&SCOPE.parse().unwrap())
        .unwrap();
    let staged: Vec<_> = scratch
        .read_dir()
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(staged.len(), 1);
    assert_eq!(
        staged[0].metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(staged[0].join("investigation").is_file());
    assert_eq!(qualified.evidence().case_id(), evidence.case_id());

    publish(
        &root,
        &bound,
        &pin.reference,
        manifest.pass_digest(),
        Some(&evidence),
    );
    let coherent = coherent_read::read_qualified(
        &bound.open_coordination().unwrap(),
        &qualified,
        &"L-linked".parse().unwrap(),
        Audience::Internal,
        3,
    )
    .unwrap();
    assert_eq!(coherent.freshness, Freshness::Current);
    assert!(matches!(coherent.computed.status, Status::Lead { .. }));
    drop(qualified);
    assert_eq!(scratch.read_dir().unwrap().count(), 0);

    let args = ["show", "finding:L-linked", "--depth", "full"];
    // The retained outcome is invalid, so a coherent read cannot award a badge.
    assert_eq!(
        stock(&root, &args, None).blockers,
        [ErrorCode::CapabilityUnavailable]
    );

    // Change only the indexed pass. The manifest artifact and revision remain
    // unchanged, so a read must independently compare the pass digest.
    let mut writer = bound.open_coordination_writer().unwrap();
    let db = rusqlite::Connection::open(root.join("workspace/.scourge/state.sqlite3")).unwrap();
    let set_pass = |digest: &Sha256Digest| {
        let changed = db.execute(
            "UPDATE engagement_revisions SET pass_digest=? WHERE engagement_id=? AND revision=1",
            [digest.as_str(), SCOPE],
        ).unwrap();
        assert_eq!(changed, 1);
    };
    set_pass(&Sha256Digest::of(b"another pass"));
    stock(&root, &args, Some(ErrorCode::IntegrityFailure));
    set_pass(manifest.pass_digest());
    assert_eq!(
        db.execute(
            "DELETE FROM engagement_revisions WHERE engagement_id=? AND revision=1",
            [SCOPE],
        )
        .unwrap(),
        1
    );
    stock(&root, &args, Some(ErrorCode::IntegrityFailure));
    drop(db);
    writer
        .append_manifest(
            &SCOPE.parse().unwrap(),
            &pin.reference,
            manifest.pass_digest(),
        )
        .unwrap();
    assert_eq!(
        stock(&root, &args, None).blockers,
        [ErrorCode::CapabilityUnavailable]
    );

    // The original retained bytes still validate, but the newer indexed
    // manifest revision does not match the operator's accepted pin.
    writer
        .append_manifest(
            &SCOPE.parse().unwrap(),
            &pin.reference,
            manifest.pass_digest(),
        )
        .unwrap();
    stock(&root, &args, Some(ErrorCode::IntegrityFailure));
    assert_eq!(scratch.read_dir().unwrap().count(), 0);
}

pub(super) fn cases() {
    passive_reads_stay_local();
    if let Some(binary) = env::var_os("SCOURGE_INVESTIGATION_BIN") {
        qualified_backend(binary.into());
    }
}
