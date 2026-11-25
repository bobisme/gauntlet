//! Non-skipping owned-loopback qualification for `web.private-object-read.v1`.

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    str::FromStr,
    thread,
    time::Duration,
};

use scourge_core::{
    canonical::{JsonError, Sha256Digest},
    domain::{LeadOrigin, LeadRevision, Run},
    engagement::{EngagementDraft, ManifestRevision, OperationRef, PassPin, PassState},
    evidence::{Completion, Evidence},
    ids::{EngagementId, LeadId, RunId, SessionName, WireText},
    policy::{Access, Policy, PolicyContext, PolicyDecision, PolicyRule},
    preflight::{
        LiveServices, PreflightDeclaration, PreflightPass, PreflightRequest, RunLocks, prepare,
    },
    request::{Invocation, NormalizedInput},
    rounds::{TargetOrigin, execute_live},
    store::{RequestScope, Store},
    teapot::{BoundEngine, Environment, ExecutableKind, SendOptions, Teapot},
    template::{
        Claim, ClaimClass, EngagementPin, Method, OperationMethods, ResolveError, SlotName,
        SlotValue, Templates, guard_lead_read,
    },
    wire::{
        AbsolutePath, Completeness, EnvironmentKind, ErrorCode, Exposure, OracleResult,
        PolicyRule as RecordedPolicyRule, RunState,
    },
    workspace::{
        InvestigationAuthority, ManifestArtifactKind, ManifestArtifactPin, ManifestAuthority,
        PassAuthority, TeapotProjectAuthority, VerifierRuntimeAuthority,
    },
};
use scourge_verify::{
    StoredVerification, VerificationContext, VerificationRecordOptions, evaluate_and_store,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const ADMIN_SECRET: &str = "oracle-qualification-admin";
const ALICE_PASSWORD: &str = "oracle-alice-password";
const BOB_PASSWORD: &str = "oracle-bob-password";
const EXPECTED_TEAPOT: &str = include_str!("../../contracts/manifest.json");
const ENGAGEMENT: &[u8] = include_bytes!("../../target/schema-examples/engagement.toml");

fn main() {
    let mut args = env::args_os().skip(1).map(PathBuf::from);
    let teapot_path = required_path(args.next(), "TEAPOT");
    let investigation_path = required_path(args.next(), "INVESTIGATION");
    assert!(
        args.next().is_none(),
        "usage: scourge-oracle-fixtures TEAPOT INVESTIGATION"
    );
    qualify_teapot(&teapot_path);

    let target = DevelopmentTarget::start();
    let mut project = PinnedProject::new(&teapot_path, target.address());
    let (teapot, engine) = project.start();
    project.create_sessions();
    project.login(
        &teapot,
        target.origin(),
        "alice_verify",
        "alice-verify",
        ALICE_PASSWORD,
    );
    project.login(
        &teapot,
        target.origin(),
        "bob_verify",
        "bob-verify",
        BOB_PASSWORD,
    );

    let state_parent = env::current_dir()
        .expect("qualification current directory")
        .join("target/oracle-tmp");
    fs::create_dir_all(&state_parent).expect("qualification state parent");
    let root = tempfile::tempdir_in(state_parent).expect("create qualification root");
    let investigation = InvestigationAuthority {
        executable: investigation_path,
        case_root: root.path().to_owned(),
        workspace_root: root.path().join("evidence"),
        import_root: root.path().join("import"),
        scratch_root: root.path().join("scratch"),
    };
    for directory in [
        &investigation.workspace_root,
        &investigation.import_root,
        &investigation.scratch_root,
    ] {
        fs::create_dir(directory).expect("create private Investigation directory");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("private Investigation mode");
    }
    let evidence = Evidence::initialize_qualified(&investigation)
        .expect("the exact qualified Investigation binary is required");
    let manifest = manifest(project.pass_digest());
    let manifest_capture = evidence
        .capture(&RunId::generate())
        .expect("open manifest capture");
    evidence
        .attach(
            &manifest_capture,
            1,
            "engagement",
            manifest.canonical_bytes(),
        )
        .expect("attach fixture manifest");
    let manifest_artifact = evidence
        .finalize(
            &manifest_capture,
            Some(1),
            Completion::Complete,
            &["engagement"],
        )
        .expect("retain fixture manifest")
        .original_artifacts
        .remove(0)
        .artifact;
    assert_eq!(manifest_artifact.digest, *manifest.digest());

    let retained_manifest = evidence
        .read_json(&manifest_artifact.artifact_id)
        .expect("read retained fixture manifest metadata")
        .artifact;
    let runtime = VerifierRuntimeAuthority {
        manifest: ManifestAuthority {
            revision: manifest.revision(),
            digest: manifest.digest().clone(),
            canonical_bytes: manifest.canonical_bytes().to_vec(),
            artifact: ManifestArtifactPin {
                kind: ManifestArtifactKind::EngagementManifest,
                reference: retained_manifest.reference,
                revision: retained_manifest.revision,
                size_bytes: retained_manifest.size_bytes,
                source_id: retained_manifest
                    .source_id
                    .parse()
                    .expect("manifest source ID"),
            },
        },
        pass: PassAuthority {
            path: project.pass_file().as_str().into(),
            digest: project.pass_digest().clone(),
        },
        teapot: TeapotProjectAuthority {
            executable: teapot_path,
            project: project.project.clone(),
            home: project.root.path().to_owned(),
            config_home: None,
            data_home: None,
            state_home: None,
            cache_home: None,
            runtime_dir: Some(project.root.path().join("runtime")),
            wrapper: false,
        },
        engine,
        investigation,
        target: manifest.target_version().clone(),
        origin: target.origin(),
        environment_kind: scourge_core::wire::EnvironmentKind::Simulated,
        custody: scourge_core::wire::Custody::Shared,
        target_isolation: scourge_core::wire::TargetIsolation::SeparatePrincipalsUnconfined,
        principal_slots: BTreeMap::new(),
    };

    let mut harness = Harness::new(
        root,
        evidence,
        manifest,
        manifest_artifact,
        project.pass_file().clone(),
        runtime,
        teapot,
        target.address(),
    );
    let mut passed = 0_u64;
    macro_rules! live {
        ($id:expr, $property:expr, $result:expr, $exposure:expr, $reasons:expr, $extra:expr) => {{
            let reasons: &[&str] = $reasons;
            let stored = harness.run($id, $property, "alice", "bob", $extra);
            expect(&stored, $result, $exposure, reasons);
            passed += 1;
            println!("case {} result={:?} reasons={:?}", $id, $result, reasons);
            stored
        }};
    }

    // Non-vacuity: the same real route shape can produce both false and true.
    let negative = live!(
        "CONTROL-FALSE",
        "invoices",
        OracleResult::False,
        None,
        &[],
        json!({})
    );
    let vulnerable = live!(
        "F-36",
        "private_reports",
        OracleResult::True,
        Some(Exposure::Unauthenticated),
        &[],
        json!({})
    );
    assert_eq!(
        negative.record.cleanup,
        scourge_core::wire::Cleanup::Complete
    );
    assert_eq!(
        vulnerable.record.cleanup,
        scourge_core::wire::Cleanup::Complete
    );
    assert_ne!(negative.artifact.digest, vulnerable.artifact.digest);

    harness.login("bob_verify", "alice-verify", ALICE_PASSWORD);
    live!(
        "F-01",
        "invoices",
        OracleResult::Invalid,
        None,
        &["SAME_SUBJECT"],
        json!({})
    );
    harness.login("bob_verify", "bob-verify", BOB_PASSWORD);

    let recorded_policy = RecordedPolicyRule {
        id: "policy.catalog-public"
            .to_owned()
            .try_into()
            .expect("policy ID"),
        revision: 1,
        digest: Sha256Digest::of(b"catalog is public"),
    };
    let f02_rule = harness.run_with_policy(
        "F-02-RULE",
        "catalog",
        "alice",
        "bob",
        json!({}),
        Some(recorded_policy.clone()),
    );
    expect(
        &f02_rule,
        OracleResult::True,
        Some(Exposure::Unauthenticated),
        &[],
    );
    passed += 1;
    println!("case F-02-RULE result=True policy=allowed");
    let f02_none = live!(
        "F-02-NO-RULE",
        "catalog",
        OracleResult::True,
        Some(Exposure::Unauthenticated),
        &[],
        json!({})
    );
    assert_eq!(f02_rule.record.result, f02_none.record.result);
    assert_eq!(f02_rule.record.policy_rule, Some(recorded_policy));
    assert_eq!(f02_none.record.policy_rule, None);
    assert_eq!(
        catalog_policy(&harness.manifest, true),
        PolicyDecision::Allowed
    );
    assert_eq!(
        catalog_policy(&harness.manifest, false),
        PolicyDecision::NoRule
    );

    harness.set_mode(Some("login_page"));
    live!(
        "F-03",
        "login_reports",
        OracleResult::Invalid,
        None,
        &["OBSERVER_INVALID"],
        json!({})
    );
    harness.set_mode(None);
    live!(
        "F-05",
        "forbidden_reports",
        OracleResult::True,
        Some(Exposure::Unauthenticated),
        &[],
        json!({})
    );

    harness.set_mode(Some("stale_prior"));
    live!(
        "F-06",
        "stale_reports",
        OracleResult::False,
        None,
        &[],
        json!({})
    );
    harness.set_mode(None);

    harness.set_mode(Some("session_switch"));
    live!(
        "F-07",
        "expiring_reports",
        OracleResult::Invalid,
        None,
        &["SESSION_DRIFT"],
        json!({})
    );
    harness.set_mode(None);
    harness.login("alice_verify", "alice-verify", ALICE_PASSWORD);

    live!(
        "F-08",
        "echo_reports",
        OracleResult::Invalid,
        None,
        &["CANARY_NOT_SPECIFIC"],
        json!({})
    );
    check_scope_leads();

    let prior = live!(
        "F-09-CONTROL",
        "orders",
        OracleResult::True,
        Some(Exposure::CrossPrincipal),
        &[],
        json!({})
    );
    let prior_flow_ids = prior.record.rounds[0]
        .flows
        .iter()
        .filter_map(|flow| flow.flow_id)
        .collect::<Vec<_>>();
    assert_agent_evidence_rejected("L-f-09", json!({"flow_ids": prior_flow_ids}));
    harness.set_mode(Some("prior_run"));
    let stale = live!("F-09", "orders", OracleResult::False, None, &[], json!({}));
    assert_ne!(
        prior.record.rounds[0].canaries,
        stale.record.rounds[0].canaries
    );
    harness.set_mode(None);

    let injected = 9_000_000_000_u64;
    assert_agent_evidence_rejected(
        "L-f-10",
        json!({"flow_ids": [injected], "observations": [{"result": "false"}]}),
    );
    let f10 = live!(
        "F-10",
        "orders",
        OracleResult::True,
        Some(Exposure::CrossPrincipal),
        &[],
        json!({})
    );
    assert!(
        f10.record.rounds[0]
            .flows
            .iter()
            .all(|flow| flow.flow_id != Some(injected))
    );

    let f37 = live!(
        "F-37",
        "cached_reports",
        OracleResult::True,
        Some(Exposure::Unauthenticated),
        &[],
        json!({})
    );
    assert!(f37.record.rounds[0].after_owner_read);

    let adapter_failure = harness.teapot.read_flow(9_000_000_000, None);
    let f14 = scourge_verify::evaluate_instrument(adapter_failure, |_| unreachable!());
    assert_eq!(f14.result, scourge_verify::Verdict::Error);
    assert_eq!(
        f14.fault,
        Some(scourge_verify::FaultCause::InstrumentUnavailable)
    );
    passed += 1;
    println!("case F-14 result=Error source=real-adapter-failure");

    for (id, mode, result, reasons) in [
        (
            "F-11-TRUNCATED",
            "window_truncated",
            OracleResult::Invalid,
            &["EVIDENCE_INCOMPLETE"][..],
        ),
        ("F-42-GZIP", "gzip", OracleResult::True, &[][..]),
        ("F-42-DEFLATE", "deflate", OracleResult::True, &[][..]),
        ("F-42-ESCAPED", "escaped_json", OracleResult::True, &[][..]),
        (
            "F-42-OVERSIZED",
            "oversized",
            OracleResult::Invalid,
            &["EVIDENCE_INCOMPLETE"][..],
        ),
        (
            "F-42-TRUNCATED",
            "window_truncated",
            OracleResult::Invalid,
            &["EVIDENCE_INCOMPLETE"][..],
        ),
    ] {
        harness.set_mode(Some(mode));
        let stored = live!(
            id,
            "orders",
            result,
            (result == OracleResult::True).then_some(Exposure::CrossPrincipal),
            reasons,
            json!({})
        );
        if id == "F-11-TRUNCATED" {
            assert!(stored.record.rounds[0].flows.iter().any(|flow| {
                flow.completeness == Completeness::Partial && flow.original.is_some()
            }));
        }
        harness.set_mode(None);
    }

    passed += pretraffic_cases(&harness.manifest, target.address()) as u64;
    assert_eq!(
        passed, 25,
        "the frozen case catalog must stay machine-counted"
    );
    println!(
        "{}",
        json!({"schema":"scourge.oracle-fixture-qualification.v1","passed":passed,"failed":0,"external_target_requests":0})
    );
}

fn required_path(path: Option<PathBuf>, label: &str) -> PathBuf {
    let path = path.unwrap_or_else(|| panic!("missing required {label} executable path"));
    let path =
        fs::canonicalize(path).unwrap_or_else(|error| panic!("invalid {label} path: {error}"));
    assert!(path.is_file(), "{label} is not a regular file");
    path
}

fn qualify_teapot(path: &Path) {
    let contract: Value = serde_json::from_str(EXPECTED_TEAPOT).expect("Teapot pin manifest");
    let bytes = fs::read(path).expect("read Teapot binary");
    assert_eq!(
        Sha256Digest::of(&bytes).as_str(),
        contract["binary_sha256"]
            .as_str()
            .expect("Teapot digest pin"),
        "Teapot binary does not match the frozen adapter pin"
    );
}

fn manifest(pass_digest: &Sha256Digest) -> ManifestRevision {
    EngagementDraft::parse_toml(ENGAGEMENT)
        .expect("fixture engagement")
        .accept(PassPin {
            reference: &"pass.development-fixture".parse().expect("pass reference"),
            digest: pass_digest,
        })
        .expect("accepted fixture engagement")
}

fn absolute(path: &Path) -> AbsolutePath {
    fs::canonicalize(path)
        .expect("canonical path")
        .to_str()
        .expect("UTF-8 path")
        .parse()
        .expect("absolute path")
}

struct DevelopmentTarget {
    address: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<thread::JoinHandle<()>>,
}

impl DevelopmentTarget {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind owned loopback target");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("target address");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("target runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("Tokio listener");
                let app = scourge_fixture::app_with_verifier_passwords(
                    ADMIN_SECRET.to_owned(),
                    [ALICE_PASSWORD.to_owned(), BOB_PASSWORD.to_owned()],
                );
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .expect("fixture server");
            });
        });
        Self {
            address,
            stop: Some(stop),
            task: Some(task),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn origin(&self) -> TargetOrigin {
        TargetOrigin::parse(&format!("http://{}", self.address)).expect("loopback origin")
    }
}

impl Drop for DevelopmentTarget {
    fn drop(&mut self) {
        let _ = self.stop.take().expect("target stop").send(());
        if let Some(task) = self.task.take() {
            let result = task.join();
            if !thread::panicking() {
                result.expect("target thread");
            }
        }
    }
}

struct PinnedProject {
    binary: PathBuf,
    project: PathBuf,
    environment: Environment,
    root: TempDir,
    pass_file: AbsolutePath,
    pass_digest: Sha256Digest,
    started: bool,
}

impl PinnedProject {
    fn new(binary: &Path, target: SocketAddr) -> Self {
        // Teapot's Unix control socket has a 107-byte platform limit. Keep
        // only its small disposable project under the short system temp path;
        // Evidence and the coordination store live under the workspace target.
        let root = tempfile::tempdir_in("/tmp").expect("project root");
        let runtime = root.path().join("runtime");
        fs::create_dir(&runtime).expect("runtime directory");
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).expect("runtime mode");
        let project = root.path().join("project");
        fs::create_dir(&project).expect("project directory");
        let pass = format!(
            "format = 1\nid = \"pass.development-fixture\"\nname = \"Oracle qualification\"\n\n[approval]\nowner = \"Scourge\"\nreference = \"bn-36n\"\noperator = \"Scourge oracle qualification\"\nvalid_from = \"2026-01-01T00:00:00Z\"\nvalid_until = \"2030-01-01T00:00:00Z\"\nrevoked = false\n\n[[destination]]\nlabel = \"owned-loopback\"\naddress = \"127.0.0.1\"\nprotocol = \"tcp\"\nports = [{}]\n\n[ceilings]\nrequests = 2000\n",
            target.port()
        );
        let pass_path = root.path().join("qualification.pass.toml");
        fs::write(&pass_path, pass.as_bytes()).expect("write pass");
        let pass_digest = Sha256Digest::of(pass.as_bytes());
        let pass_file = absolute(&pass_path);
        let environment = Environment {
            home: absolute(root.path()),
            config_home: None,
            data_home: None,
            state_home: None,
            cache_home: None,
            runtime_dir: Some(absolute(&runtime)),
        };
        let mut this = Self {
            binary: binary.to_owned(),
            project: fs::canonicalize(project).expect("project path"),
            environment,
            root,
            pass_file,
            pass_digest,
            started: false,
        };
        this.run(&["projects", "init"]);
        this.install_macros(target);
        this
    }

    fn command(&self, words: &[&str]) -> Output {
        Command::new(&self.binary)
            .env_clear()
            .env("HOME", self.environment.home.as_str())
            .env(
                "XDG_RUNTIME_DIR",
                self.environment
                    .runtime_dir
                    .as_ref()
                    .expect("runtime")
                    .as_str(),
            )
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .arg("--project")
            .arg(&self.project)
            .arg("--json")
            .args(words)
            .stdin(Stdio::null())
            .output()
            .expect("run Teapot")
    }

    fn run(&self, words: &[&str]) -> Value {
        let output = self.command(words);
        assert!(
            output.status.success(),
            "Teapot {words:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("Teapot JSON")
    }

    fn install_macros(&mut self, target: SocketAddr) {
        let directory = self.project.join(".teapot/macros");
        fs::create_dir_all(&directory).expect("macro directory");
        for name in [
            "order",
            "invoice",
            "tenant-note",
            "bulletin",
            "catalog-entry",
            "private-report",
            "cached-report",
            "login-report",
            "stale-report",
            "forbidden-report",
            "echo-report",
            "expiring-report",
        ] {
            let file = directory.join(format!("create-{name}.toml"));
            let body = format!(
                "format = 1\n\n[[steps]]\nstate_changing = true\n[steps.request]\nmethod = \"POST\"\nurl = \"http://{target}/app/api/orders\"\n"
            );
            fs::write(file, body).expect("write fixture macro");
        }
    }

    fn start(&mut self) -> (Teapot, BoundEngine) {
        let pass = self.pass_file.as_str().to_owned();
        let started = self.run(&[
            "proxy",
            "start",
            "--listen",
            "127.0.0.1:0",
            "--detach",
            "--pass",
            &pass,
            "--no-enforce",
        ]);
        self.started = true;
        let engine = &started["proxy"]["engine"];
        let bound = BoundEngine {
            instance: engine["instance"]
                .as_str()
                .expect("engine instance")
                .parse()
                .expect("instance"),
            project_id: engine["project_id"]
                .as_str()
                .expect("project id")
                .parse()
                .expect("project id"),
            enforced: engine["enforced"].as_bool().expect("engine enforcement"),
            policy_locked: engine["policy_locked"]
                .as_bool()
                .expect("engine policy lock"),
        };
        let teapot = Teapot::new(
            absolute(&self.binary),
            ExecutableKind::Native,
            absolute(&self.project),
            self.environment.clone(),
            bound.clone(),
        );
        (teapot, bound)
    }

    fn create_sessions(&self) {
        self.run(&["scope", "add", "127.0.0.1"]);
        for session in [
            "alice",
            "alice_verify",
            "bob",
            "bob_verify",
            "scourge_anonymous",
        ] {
            self.run(&["sessions", "create", session]);
        }
    }

    fn login(
        &self,
        _teapot: &Teapot,
        origin: TargetOrigin,
        session: &str,
        username: &str,
        password: &str,
    ) {
        let url = format!("{}/app/login", origin.as_str());
        let body = json!({"username": username, "password": password}).to_string();
        let login = self.run(&[
            "requests",
            "send",
            "POST",
            &url,
            "--session",
            session,
            "--header",
            "Content-Type: application/json",
            "--body",
            &body,
        ]);
        assert_eq!(
            login["sent"]["status"], 200,
            "fixture verifier login failed: {login}"
        );
    }

    fn pass_file(&self) -> &AbsolutePath {
        &self.pass_file
    }
    fn pass_digest(&self) -> &Sha256Digest {
        &self.pass_digest
    }
}

impl Drop for PinnedProject {
    fn drop(&mut self) {
        if self.started {
            let output = self.command(&["proxy", "stop"]);
            if !thread::panicking() {
                assert!(output.status.success(), "stop Teapot proxy");
            }
        }
        let _ = self.root.path();
    }
}

struct Harness {
    _root: TempDir,
    evidence: Evidence,
    manifest: ManifestRevision,
    manifest_artifact: scourge_core::wire::Artifact,
    pass_file: AbsolutePath,
    runtime: VerifierRuntimeAuthority,
    teapot: Teapot,
    address: SocketAddr,
    store: Store,
    locks: RunLocks,
    scope: RequestScope,
    sequence: u64,
}

impl Harness {
    #[allow(clippy::too_many_arguments)]
    fn new(
        root: TempDir,
        evidence: Evidence,
        manifest: ManifestRevision,
        manifest_artifact: scourge_core::wire::Artifact,
        pass_file: AbsolutePath,
        runtime: VerifierRuntimeAuthority,
        teapot: Teapot,
        address: SocketAddr,
    ) -> Self {
        let state = root.path().join("state.sqlite3");
        let mut store = Store::open(&state).expect("coordination store");
        let engagement: EngagementId = "oracle-qualification".parse().expect("engagement ID");
        store
            .append_manifest(&engagement, &manifest_artifact, manifest.pass_digest())
            .expect("append manifest");
        let scope = RequestScope::new(
            engagement,
            "workspace:oracle-qualification"
                .parse()
                .expect("workspace digest"),
        );
        let locks = RunLocks::open(root.path()).expect("run locks");
        Self {
            _root: root,
            evidence,
            manifest,
            manifest_artifact,
            pass_file,
            runtime,
            teapot,
            address,
            store,
            locks,
            scope,
            sequence: 0,
        }
    }

    fn login(&self, session: &str, username: &str, password: &str) {
        let url: WireText = format!("{}/app/login", self.runtime.origin.as_str())
            .try_into()
            .expect("login URL");
        let session: SessionName = session.parse().expect("session");
        let body = json!({"username": username, "password": password}).to_string();
        let header = "Content-Type: application/json".to_owned();
        let login = self
            .teapot
            .send(
                Method::Post,
                &url,
                &session,
                SendOptions {
                    headers: std::slice::from_ref(&header),
                    body: Some(&body),
                    ..SendOptions::default()
                },
            )
            .expect("fixture relogin");
        assert_eq!(login.value.status, Some(200));
    }

    fn set_mode(&self, mode: Option<&str>) {
        let body = serde_json::to_string(&json!({"mode": mode})).expect("mode JSON");
        let response = http_request(
            self.address,
            "POST",
            "/app/_oracle-mode",
            &format!(
                "X-Fixture-Admin-Secret: {ADMIN_SECRET}\r\nContent-Type: application/json\r\n"
            ),
            &body,
        );
        assert!(
            response.starts_with("HTTP/1.1 204 "),
            "oracle mode: {response:?}"
        );
    }

    fn run(
        &mut self,
        case: &str,
        property: &str,
        owner: &str,
        other: &str,
        extra: Value,
    ) -> StoredVerification {
        self.run_with_policy(case, property, owner, other, extra, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with_policy(
        &mut self,
        case: &str,
        property: &str,
        owner: &str,
        other: &str,
        extra: Value,
        policy_rule: Option<RecordedPolicyRule>,
    ) -> StoredVerification {
        self.sequence += 1;
        let lead: LeadId = format!("L-{}", case.to_ascii_lowercase())
            .parse()
            .expect("lead ID");
        self.store
            .append_lead_revision(
                &self.scope.engagement,
                &LeadRevision {
                    lead_id: lead.clone(),
                    revision: 1,
                    text: format!("runnable oracle fixture {case}")
                        .parse()
                        .expect("lead text"),
                    class: Some("web-authz/private-object-read".parse().expect("class")),
                    property: Some(property.parse().expect("property")),
                    slots: BTreeMap::from([
                        ("owner".parse().expect("owner slot"), json!(owner)),
                        ("other".parse().expect("other slot"), json!(other)),
                    ]),
                    proposed_policy: None,
                    origin: LeadOrigin::Local,
                    source_ref: None,
                    endpoint: None,
                    flow_ids: Vec::new(),
                    producer_confidence: None,
                },
            )
            .expect("append lead");
        let claim = Claim {
            class: ClaimClass::from_str("web-authz/private-object-read").expect("claim class"),
            engagement: EngagementPin {
                revision: self.manifest.revision(),
                digest: self.manifest.digest().clone(),
            },
            lead: lead.clone(),
            property: Some(property.parse().expect("property")),
            lead_slots: vec![slot("owner", owner), slot("other", other)],
            overrides: Vec::new(),
        };
        let experiment = Templates::resolve(&claim, &self.manifest)
            .expect("resolve fixture claim")
            .ready()
            .expect("complete fixture claim");
        let run = Run::declare(
            self.scope.engagement.clone(),
            experiment.freeze().expect("freeze experiment").1,
        );
        let mut arguments = json!({"lead_id": lead.as_str(), "rounds": 1});
        if let Some(object) = extra.as_object() {
            arguments
                .as_object_mut()
                .expect("arguments")
                .extend(object.clone());
        }
        let input: NormalizedInput = Invocation::new("verify", arguments)
            .normalize()
            .expect("normalize input");
        let services = LiveServices::new(&self.teapot, &self.evidence, &self.runtime)
            .expect("same operator runtime for both fixture adapters");
        let prepared = prepare(
            &mut self.store,
            &self.locks,
            &services,
            PreflightRequest {
                declaration: PreflightDeclaration {
                    scope: &self.scope,
                    input: &input,
                    run: &run,
                    claim: &claim,
                    lead_revision: 1,
                    engagement: &self.manifest,
                    manifest_artifact: &self.manifest_artifact,
                },
                pass: PreflightPass {
                    pass_reference: &self.manifest.settings().pass_ref,
                    pass_state: PassState::Active(self.manifest.pass_digest()),
                    pass_file: &self.pass_file,
                },
            },
        )
        .expect("prepare live fixture run");
        let receipt = prepared.acceptance().receipt;
        let execution = execute_live(
            &mut self.store,
            prepared,
            &self.manifest,
            &self.teapot,
            &self.evidence,
            &self.runtime.origin,
        )
        .expect("execute live fixture run");
        let retained = execution
            .capture()
            .original_artifacts
            .iter()
            .map(|original| &original.artifact)
            .collect::<Vec<_>>();
        for flow in execution.rounds().iter().flat_map(|round| &round.flows) {
            if let Some(original) = &flow.reference.original {
                assert!(
                    retained.contains(&original),
                    "{} original {} is absent from the finalized run capture",
                    flow.reference.step.as_str(),
                    original.artifact_id.as_str()
                );
            }
        }
        for round in execution.rounds() {
            for cleanup in &round.cleanup {
                for flow in &cleanup.flows {
                    assert!(
                        round.flows.iter().any(|candidate| candidate.contract
                            == scourge_core::rounds::RoundFlow::C
                            && candidate.reference == *flow),
                        "cleanup {:?} flow {} {:?} is absent from acquired C flows {:?}",
                        cleanup.object,
                        flow.step.as_str(),
                        flow.original
                            .as_ref()
                            .map(|artifact| artifact.artifact_id.as_str()),
                        round
                            .flows
                            .iter()
                            .filter(|candidate| candidate.contract
                                == scourge_core::rounds::RoundFlow::C)
                            .map(|candidate| (
                                candidate.reference.step.as_str(),
                                candidate
                                    .reference
                                    .original
                                    .as_ref()
                                    .map(|artifact| artifact.artifact_id.as_str())
                            ))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        let context = VerificationContext::from_execution(
            &execution,
            VerificationRecordOptions {
                sequence: self.sequence,
                prev_record_digest: None,
                policy_rule,
                environment_kind: EnvironmentKind::Simulated,
            },
        )
        .expect("derive fixture context from execution");
        let verification = evaluate_and_store(&self.evidence, &execution, context)
            .expect("evaluate and retain fixture record");
        let mut settled = execution.settlement().1.clone();
        settled.state = RunState::Finalized;
        settled.effects = verification.record.effects;
        self.store
            .record_run(&settled, Some(receipt))
            .expect("finalize fixture run");
        verification
    }
}

fn slot(name: &str, value: &str) -> SlotValue {
    SlotValue {
        name: SlotName::from_str(name).expect("slot"),
        value: value.to_owned().try_into().expect("slot value"),
    }
}

fn assert_agent_evidence_rejected(lead_id: &str, extra: Value) {
    let mut arguments = json!({"lead_id": lead_id});
    arguments
        .as_object_mut()
        .expect("verify arguments")
        .extend(extra.as_object().expect("injected evidence object").clone());
    assert!(matches!(
        Invocation::new("verify", arguments).normalize(),
        Err(JsonError::InvalidShape)
    ));
}

fn expect(
    stored: &StoredVerification,
    result: OracleResult,
    exposure: Option<Exposure>,
    reasons: &[&str],
) {
    assert_eq!(stored.record.result, result);
    assert_eq!(stored.record.exposure, exposure);
    assert_eq!(stored.record.rounds.len(), 1);
    assert_eq!(stored.record.rounds[0].result, result);
    assert_eq!(
        stored.record.rounds[0]
            .reason_codes
            .iter()
            .map(|reason| reason.as_str())
            .collect::<Vec<_>>(),
        reasons
    );
    assert!(
        !stored.record.rounds[0].flows.is_empty(),
        "fixture must retain real flows"
    );
}

fn http_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &str,
    body: &str,
) -> String {
    let timeout = Duration::from_secs(5);
    let mut stream = TcpStream::connect_timeout(&address, timeout).expect("connect owned target");
    stream
        .set_read_timeout(Some(timeout))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(timeout))
        .expect("write timeout");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len(),
    )
    .expect("send fixture control");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read fixture control");
    response
}

fn catalog_policy(manifest: &ManifestRevision, admitted: bool) -> PolicyDecision {
    let property = "catalog".parse().expect("property label");
    let declaration = json!({
        "schema_version": "scourge.policy-rule.v1",
        "property": "catalog",
        "target_version": "version.fixture.v1",
        "readers": "public",
        "source": {
            "kind": "operator",
            "statement": {
                "artifact_id": "artifact.oracle-fixture-policy",
                "sha256": Sha256Digest::of(b"catalog is public").as_str()
            },
            "admission": {
                "actor": "operator.oracle-fixture",
                "recorded_at": "2026-11-24T00:00:00Z",
                "identity": "attributed"
            }
        }
    });
    let rule = PolicyRule::parse_json(&serde_json::to_vec(&declaration).expect("policy JSON"))
        .expect("catalog policy rule");
    let admitted_rule = admitted.then(|| {
        rule.admit(manifest, |candidate, exact| {
            candidate == &rule && exact == manifest
        })
        .expect("admit policy")
    });
    let resource = &manifest.properties()[&property].resource;
    Policy::allows(
        admitted_rule.as_ref(),
        Exposure::Unauthenticated,
        PolicyContext {
            manifest,
            property: &property,
            resource,
            target_version: manifest.target_version(),
            access: Access::Read,
            owner: &"alice".parse().expect("owner"),
            actor: None,
        },
    )
}

fn check_scope_leads() {
    use scourge_verify::scope::{Dispatch, dispatch};
    for class in ["web-authz/collection-disclosure", "web-authz/existence"] {
        let plan = dispatch(class);
        assert_eq!(plan.result_code(), Some("ORACLE_UNAVAILABLE"));
        assert!(matches!(
            plan,
            Dispatch::OracleUnavailable {
                timing: "before target traffic",
                ..
            }
        ));
    }
}

struct DeleteMethod;

impl OperationMethods for DeleteMethod {
    fn method(&self, _: &OperationRef) -> Option<Method> {
        Some(Method::Delete)
    }
}

fn pretraffic_cases(manifest: &ManifestRevision, sink: SocketAddr) -> usize {
    let listener = TcpListener::bind((sink.ip(), 0)).expect("bind zero-hit loopback sink");
    listener.set_nonblocking(true).expect("nonblocking sink");
    let pin = EngagementPin {
        revision: manifest.revision(),
        digest: manifest.digest().clone(),
    };
    let claim = |lead_slots: Vec<SlotValue>, overrides: Vec<SlotValue>| Claim {
        class: ClaimClass::from_str("web-authz/private-object-read").expect("claim class"),
        engagement: pin.clone(),
        lead: "L-pretraffic".parse().expect("lead"),
        property: Some("orders".parse().expect("property")),
        lead_slots,
        overrides,
    };
    let principals = vec![slot("owner", "alice"), slot("other", "bob")];
    for candidate in [
        claim(
            [
                principals.clone(),
                vec![slot("plant", "operation.orders.create")],
            ]
            .concat(),
            Vec::new(),
        ),
        claim(
            principals.clone(),
            vec![slot("read", "operation.orders.read")],
        ),
        claim(
            [
                principals.clone(),
                vec![slot("read", "operation.orders.delete")],
            ]
            .concat(),
            Vec::new(),
        ),
    ] {
        let error = Templates::resolve(&candidate, manifest).expect_err("property slot conflict");
        assert_eq!(error.code(), ErrorCode::SlotConflict);
    }
    let delete: OperationRef = "operation.orders.delete".parse().expect("operation");
    assert!(matches!(
        guard_lead_read(&delete, &DeleteMethod),
        Err(ResolveError::MethodRefused { .. })
    ));
    assert_eq!(
        guard_lead_read(&delete, &DeleteMethod)
            .expect_err("unsafe method")
            .code(),
        ErrorCode::MethodRefused
    );
    assert_eq!(
        listener
            .accept()
            .expect_err("pre-traffic checks must not connect")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    println!("case F-38 x2 result=SLOT_CONFLICT sink_hits=0");
    println!("case F-39 x2 result=SLOT_CONFLICT,METHOD_REFUSED sink_hits=0");
    4
}
