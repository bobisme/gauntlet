use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, symlink},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

use rusqlite::Connection;
use scourge_core::{
    canonical::{self, Sha256Digest},
    domain::{LeadRevision, Run, VerificationIndex},
    ids::EngagementId,
    response::Context,
    store::{
        Store, StoreError,
        checks::{RecordedCheck, Stage},
        entry::{TeapotObservation, teapot_route_digest},
    },
    verification::registry,
    wire::{
        self, Action, Artifact, Checkpoint, Cleanup, DiagnosticCode, Effect, ErrorCode,
        PublicationIntentV1, PublicationIntentV1Tag, PublicationState, ResponseV1, TransportKind,
    },
    workspace::{self, Authority},
};
use tempfile::TempDir;

#[path = "fixtures/historical_run.rs"]
mod historical_run;

const DECLARATION: &[u8] =
    include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");
const LEAD_BODY: &str = "hostile lead body\nNext  unexpected-action\u{1b}[2J";
const OBSERVED: &str = "2026-11-24T16:00:00Z";
static ACTION_TRACE: AtomicUsize = AtomicUsize::new(0);

struct TestWorkspace {
    temporary: TempDir,
    root: PathBuf,
    state: PathBuf,
    action_path: PathBuf,
    declaration: PathBuf,
    unrelated: PathBuf,
    id: EngagementId,
}

impl TestWorkspace {
    fn from(temporary: TempDir, authority: Authority) -> Self {
        let root = temporary.path().join("bound workspace");
        let state = temporary.path().join("operator state");
        let action_path = temporary.path().join("action path with spaces");
        let declaration = temporary.path().join("catalog engagement.toml");
        let unrelated = temporary.path().join("unrelated directory with spaces");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&action_path).unwrap();
        fs::create_dir(&unrelated).unwrap();
        fs::write(&declaration, DECLARATION).unwrap();
        let launcher =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/action-launcher.sh");
        symlink(launcher, action_path.join("scourge")).unwrap();
        let id: EngagementId = "orders".parse().unwrap();
        workspace::init(&root, &state, id.as_str(), DECLARATION, authority).unwrap();
        Self {
            temporary,
            root,
            state,
            action_path,
            declaration,
            unrelated,
            id,
        }
    }

    fn new() -> Self {
        Self::from(tempfile::tempdir().unwrap(), Authority::default())
    }

    fn database(&self) -> PathBuf {
        self.root.join(".scourge/state.sqlite3")
    }

    fn store(&self) -> Store {
        Store::open(self.database()).unwrap()
    }

    fn call(&self, args: &[&str]) -> Output {
        launch(&self.root, &self.state, args)
    }

    fn follow(&self, action: &Action) -> ResponseV1 {
        assert_eq!(action.argv[0].as_str(), "scourge");
        machine(self.launch_action(action))
    }

    fn launch_action(&self, action: &Action) -> Output {
        let argv = action
            .argv
            .iter()
            .map(|word| word.as_str())
            .collect::<Vec<_>>();
        assert_eq!(argv.first().copied(), Some("scourge"));
        assert!(
            argv.windows(2).any(|pair| pair == ["--format", "json"]),
            "suggested argv must select JSON explicitly: {argv:?}"
        );
        let trace = self.temporary.path().join(format!(
            "action-trace-{}",
            ACTION_TRACE.fetch_add(1, Ordering::Relaxed)
        ));
        let output = Command::new(argv[0])
            .args(&argv[1..])
            .current_dir(&self.unrelated)
            .env_clear()
            .env("PATH", &self.action_path)
            .env("HOME", &self.state)
            .env("XDG_STATE_HOME", &self.state)
            .env("SCOURGE_ACTION_BINARY", env!("CARGO_BIN_EXE_scourge"))
            .env("SCOURGE_ACTION_TRACE", &trace)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        let trace = fs::read(trace).expect("the PATH-resolved launcher must record the process");
        let mut fields = trace.split(|byte| *byte == 0);
        assert_eq!(
            fields.next().unwrap(),
            self.unrelated.as_os_str().as_encoded_bytes(),
            "suggested action must run from the unrelated directory"
        );
        assert_eq!(
            fields.next().unwrap(),
            b"",
            "FORMAT must be absent from the launched process"
        );
        assert_eq!(
            fields.next().unwrap(),
            (argv.len() - 1).to_string().as_bytes()
        );
        for expected in &argv[1..] {
            assert_eq!(fields.next().unwrap(), expected.as_bytes());
        }
        assert_eq!(fields.next(), Some(&b""[..]));
        assert_eq!(fields.next(), None);
        output
    }
}

fn launch(cwd: &Path, state: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scourge"))
        .current_dir(cwd)
        .env_remove("FORMAT")
        .env("XDG_STATE_HOME", state)
        .env("HOME", state)
        .env("PATH", cwd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let timeout = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= timeout {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("scourge {args:?} did not exit");
        }
        thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

fn machine(output: Output) -> ResponseV1 {
    assert!(output.status.success(), "{output:?}");
    let result = envelope(&output);
    assert!(result.ok);
    assert_eq!(result.effects, Effect::None);
    result
}

fn envelope(output: &Output) -> ResponseV1 {
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
        1
    );
    assert!(output.stdout.ends_with(b"\n"));
    wire::from_slice(&output.stdout).unwrap()
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ActionScope {
    workspace: Option<String>,
    engagement: Option<String>,
}

impl ActionScope {
    fn from_response(response: &ResponseV1) -> Self {
        Self {
            workspace: response
                .workspace
                .as_ref()
                .map(|path| path.as_str().to_owned()),
            engagement: response
                .engagement
                .as_ref()
                .map(|id| id.as_str().to_owned()),
        }
    }

    fn from_argv(argv: &[String]) -> Self {
        let mut scope = Self {
            workspace: None,
            engagement: None,
        };
        let mut words = argv.iter().peekable();
        while let Some(word) = words.next() {
            match word.as_str() {
                "--workspace" => scope.workspace = words.next().cloned(),
                "--engagement" => scope.engagement = words.next().cloned(),
                value if value.starts_with("--workspace=") => {
                    scope.workspace = value.split_once('=').map(|(_, value)| value.to_owned());
                }
                value if value.starts_with("--engagement=") => {
                    scope.engagement = value.split_once('=').map(|(_, value)| value.to_owned());
                }
                _ => {}
            }
        }
        scope
    }

    fn preserved_by(&self, response: &ResponseV1) -> bool {
        *self == Self::from_response(response)
    }
}

#[derive(Default)]
struct ActionHarness {
    emitted: BTreeMap<Vec<String>, ActionScope>,
    launched: BTreeSet<Vec<String>>,
    responses: usize,
}

impl ActionHarness {
    fn collect(&mut self, response: &ResponseV1) {
        self.responses += 1;
        let response_scope = ActionScope::from_response(response);
        for action in response
            .next
            .iter()
            .chain(response.transport.iter().map(|transport| &transport.action))
        {
            assert_eq!(action.effects, scourge_core::wire::ActionEffect::None);
            let argv = action
                .argv
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(argv.first().map(String::as_str), Some("scourge"));
            assert!(argv.windows(2).any(|pair| pair == ["--format", "json"]));
            let action_scope = ActionScope::from_argv(&argv);
            let required_scope = if argv.iter().any(|word| word == "--help" || word == "-h") {
                ActionScope::default()
            } else {
                response_scope.clone()
            };
            assert_eq!(
                action_scope, required_scope,
                "an action must encode its exact required scope: {argv:?}"
            );
            if let Some(previous) = self.emitted.insert(argv.clone(), action_scope.clone()) {
                assert_eq!(
                    previous, action_scope,
                    "one argv cannot carry two implicit scopes"
                );
            }
        }
    }

    fn launch_all(&mut self, fixture: &TestWorkspace) {
        while let Some(argv) = self
            .emitted
            .keys()
            .find(|argv| !self.launched.contains(*argv))
            .cloned()
        {
            assert!(
                self.launched.len() < 128,
                "suggested action graph did not converge"
            );
            let scope = self.emitted[&argv].clone();
            let action = Action {
                effects: scourge_core::wire::ActionEffect::None,
                argv: argv.iter().map(|word| word.parse().unwrap()).collect(),
            };
            self.launched.insert(argv);
            let response = machine(fixture.launch_action(&action));
            assert!(
                scope.preserved_by(&response),
                "launcher-started response dropped or changed its encoded scope: {action:?}"
            );
            self.collect(&response);
        }
        assert!(
            !self.launched.is_empty(),
            "positive action control is required"
        );
        assert!(self.complete(), "every emitted action must be exercised");
    }

    fn complete(&self) -> bool {
        self.emitted.keys().collect::<BTreeSet<_>>()
            == self.launched.iter().collect::<BTreeSet<_>>()
    }
}

fn expand_seed(seed: &[String], fixture: &TestWorkspace) -> Vec<Vec<String>> {
    let mut expanded = vec![Vec::new()];
    for word in seed {
        let values: Vec<String> = match word.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some("ID") => vec!["L-00000".into(), "L-absent".into()],
            Some("STATUS") => vec!["open".into(), "not-a-status".into()],
            Some("LIMIT") => vec!["5".into()],
            Some("OFFSET") => vec!["1".into()],
            Some("PATH") => vec![fixture.root.to_str().unwrap().into()],
            Some("FILE") => vec![fixture.declaration.to_str().unwrap().into()],
            Some("NAME") => vec!["catalog-extra".into()],
            Some("TEXT") => vec!["catalog lead".into()],
            Some("SOURCE") => vec!["teapot:finding:1".into()],
            Some("CLASS") => vec!["web-authz/private-object-read".into()],
            Some("PROPERTY") => vec!["orders".into()],
            Some("NAME=VALUE") => vec!["owner=alice".into()],
            Some("ACTOR") => vec!["catalog-agent".into()],
            Some("LEAD") => vec!["L-00000".into(), "L-absent".into()],
            Some("ROUNDS") => vec!["2".into()],
            Some("RUN") => vec!["R-absent".into()],
            Some("KEY") => vec!["rk_absent".into()],
            Some(name) => panic!("new CLI fixture value {name:?} needs an explicit safe seed"),
            None => vec![word.clone()],
        };
        expanded = expanded
            .into_iter()
            .flat_map(|prefix| {
                values.iter().map(move |value| {
                    let mut seed = prefix.clone();
                    seed.push(value.clone());
                    seed
                })
            })
            .collect();
    }
    expanded
}

fn seed_lead(store: &mut Store, engagement: &EngagementId, id: usize, body: &str) {
    store
        .append_lead_revision(
            engagement,
            &LeadRevision {
                lead_id: format!("L-{id:05}").parse().unwrap(),
                revision: 1,
                text: body.parse().unwrap(),
                class: None,
                property: None,
                slots: BTreeMap::new(),
                proposed_policy: None,
                origin: scourge_core::domain::LeadOrigin::Local,
                source_ref: None,
                endpoint: None,
                flow_ids: Vec::new(),
                producer_confidence: None,
            },
        )
        .unwrap();
}

fn verification_bytes(
    index: &VerificationIndex,
    run: &Run,
    predecessor: Option<&Sha256Digest>,
) -> Vec<u8> {
    let mut record = canonical::parse(include_bytes!(
        "../../../fixtures/contracts/scourge-v1/verification-record.json"
    ))
    .unwrap();
    record["record_id"] = serde_json::json!(index.record_id);
    record["engagement"] = serde_json::json!(index.engagement);
    record["sequence"] = serde_json::json!(index.sequence);
    record["prev_record_digest"] =
        predecessor.map_or(serde_json::Value::Null, |digest| serde_json::json!(digest));
    record["lead_id"] = serde_json::json!(index.lead_id);
    record["lead_revision"] = serde_json::json!(1);
    record["engagement_revision"] = serde_json::json!(1);
    record["run_id"] = serde_json::json!(index.run_id);
    record["experiment_digest"] = serde_json::json!(run.experiment_digest);
    record["oracle"]["digest"] = serde_json::json!(registry::oracle_digest());
    record["limitations"] = serde_json::json!(registry::KNOWN_MISSES);
    canonical::to_vec(&record).unwrap()
}

fn text(output: Output) -> String {
    assert!(output.status.success(), "{output:?}");
    assert!(
        output.stdout.len() <= 2048,
        "{} output bytes",
        output.stdout.len()
    );
    let output = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("Next  "))
            .count(),
        1
    );
    output
}

fn content(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .flat_map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                content(&path).into_iter().collect::<Vec<_>>()
            } else {
                vec![(path.clone(), fs::read(path).unwrap())]
            }
        })
        .collect()
}

#[test]
fn every_suggested_argv_runs_exactly_from_an_unrelated_process() {
    let fixture = TestWorkspace::new();
    workspace::add_engagement(&fixture.root, None, &fixture.state, "second", DECLARATION).unwrap();
    let mut store = fixture.store();
    for id in 0..25 {
        seed_lead(&mut store, &fixture.id, id, LEAD_BODY);
    }
    drop(store);

    let mut harness = ActionHarness::default();
    let catalog = scourge::cli_action_discovery_seeds();
    assert!(!catalog.is_empty());
    // The catalog now includes valid local lead mutations. Those may change
    // only the coordination store; operator binding and workspace selection
    // metadata remain immutable under action discovery.
    let binding_before = content(&fixture.state);
    let config_before = fs::read(fixture.root.join("scourge.toml")).unwrap();
    for seed in &catalog {
        for seed in expand_seed(seed, &fixture) {
            let mut scoped = vec![
                "--json".to_owned(),
                "--engagement".to_owned(),
                fixture.id.as_str().to_owned(),
            ];
            scoped.extend(seed);
            let args = scoped.iter().map(String::as_str).collect::<Vec<_>>();
            let output = fixture.call(&args);
            let response = envelope(&output);
            assert_eq!(response.effects, Effect::None, "{args:?}");
            harness.collect(&response);
        }
    }

    let outside = fixture.temporary.path().join("unbound caller with spaces");
    fs::create_dir(&outside).unwrap();
    for seed in &catalog {
        for seed in expand_seed(seed, &fixture) {
            let mut args = vec!["--json".to_owned()];
            args.extend(seed);
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();
            let output = launch(&outside, &fixture.state, &args);
            let response = envelope(&output);
            assert_eq!(response.effects, Effect::None, "{args:?}");
            harness.collect(&response);
        }
    }
    assert_eq!(
        content(&fixture.state),
        binding_before,
        "catalog discovery changed operator authority"
    );
    assert_eq!(
        fs::read(fixture.root.join("scourge.toml")).unwrap(),
        config_before,
        "catalog discovery changed workspace selection"
    );

    harness.launch_all(&fixture);
    assert!(harness.responses > catalog.len());
    assert!(
        harness
            .launched
            .iter()
            .all(|argv| argv.windows(2).any(|pair| pair == ["--format", "json"]))
    );
}

#[test]
fn launcher_scope_check_rejects_missing_values() {
    let expected = ActionScope {
        workspace: Some("/workspace with spaces".into()),
        engagement: Some("orders".into()),
    };
    let mut response = Context::for_command("status").success("bound");
    assert!(!expected.preserved_by(&response));
    response.workspace = Some("/workspace with spaces".parse().unwrap());
    assert!(!expected.preserved_by(&response));
    response.engagement = Some("orders".parse().unwrap());
    assert!(expected.preserved_by(&response));
}

#[test]
fn newly_emitting_catalog_command_is_incomplete_until_launched() {
    let mut response = Context::for_command("version").success("version");
    response.next.push(Context::default().action(
        scourge_core::wire::ActionEffect::None,
        ["--help".parse().unwrap()],
    ));
    let mut harness = ActionHarness::default();
    harness.collect(&response);
    assert!(
        !harness.complete(),
        "an emitted action is incomplete until a launcher process exercises it"
    );
}

#[test]
fn outside_aliases_are_equivalent_and_create_nothing() {
    let workspace = tempfile::tempdir().unwrap();
    let state = workspace.path().join("state never created");
    let bare = launch(workspace.path(), &state, &[]);
    let normal = text(bare);
    assert!(normal.contains("scourge init PATH --engagement FILE"));
    assert!(normal.contains("Verification requires independent controls"));
    let expected = machine(launch(workspace.path(), &state, &["--json"]));
    assert_eq!(expected.blockers, [ErrorCode::WorkspaceUnbound]);
    assert_eq!(expected.next.len(), 1);
    let next = expected.next[0]
        .argv
        .iter()
        .skip(1)
        .map(|word| word.as_str())
        .collect::<Vec<_>>();
    let help = machine(launch(workspace.path(), &state, &next));
    assert_eq!(help.command.unwrap().as_str(), "init");
    assert_eq!(help.result.unwrap().as_str(), "help");
    for alias in ["status", "tldr", "brief", "onboard"] {
        assert_eq!(text(launch(workspace.path(), &state, &[alias])), normal);
        assert_eq!(
            machine(launch(workspace.path(), &state, &[alias, "--json"])),
            expected
        );
    }
    assert!(!state.exists());
    assert_eq!(fs::read_dir(workspace.path()).unwrap().count(), 0);
}

#[test]
fn compact_entry_measures_zero_ten_and_ten_thousand_leads_without_mutation() {
    let fixture = TestWorkspace::new();
    let mut store = None;
    let long_claim = LEAD_BODY.repeat(1000);
    let mut prior = 0;
    for total in [0, 10, 10_000] {
        for id in prior..total {
            seed_lead(
                store.get_or_insert_with(|| fixture.store()),
                &fixture.id,
                id,
                if id == 0 { &long_claim } else { LEAD_BODY },
            );
        }
        prior = total;
        let before = (content(&fixture.root), content(&fixture.state));
        for args in [
            &[][..],
            &["status"],
            &["--format", "text", "status"],
            &["--format", "pretty", "status"],
        ] {
            let output = text(fixture.call(args));
            assert!(
                output.contains(&format!("{total} recorded leads,")),
                "{output}"
            );
            assert!(output.contains(&format!("{total} leads via scourge list leads")));
            assert!(
                output.contains("Shared custody allows the same account to alter its local state.")
            );
            assert!(
                output.contains("Pass validity and current findings require separate evidence.")
            );
            assert!(output.contains("alice, bob"));
            assert!(output.contains("web-authz/private-object-read"));
            assert!(!output.contains("hostile lead body"));
            assert!(!output.contains('\u{1b}'));
        }
        for args in [&["--json"][..], &["status", "--format", "json"]] {
            let output = fixture.call(args);
            assert!(output.stdout.len() <= 2048, "{} bytes", output.stdout.len());
            let response = machine(output);
            assert_eq!(response.next.len(), 1);
            assert_eq!(response.extensions["counts"]["leads"], total);
            assert_eq!(response.extensions["counts"]["leads_omitted"], total);
            assert!(response.finding.is_none());
            assert_eq!(
                fixture.follow(&response.next[0]).engagement,
                Some(fixture.id.clone())
            );
        }
        assert_eq!((content(&fixture.root), content(&fixture.state)), before);
    }
}

#[test]
fn selects_one_engagement_and_follows_scoped_argv_from_another_directory() {
    let fixture = TestWorkspace::new();
    workspace::add_engagement(&fixture.root, None, &fixture.state, "second", DECLARATION).unwrap();
    let mut store = fixture.store();
    seed_lead(&mut store, &fixture.id, 1, LEAD_BODY);
    let ambiguous = machine(fixture.call(&["--json"]));
    assert_eq!(ambiguous.engagement, None);
    assert!(ambiguous.blockers.contains(&ErrorCode::EngagementRequired));
    assert_eq!(
        ambiguous.extensions["engagements"],
        serde_json::json!(["orders", "second"])
    );
    let first = fixture.follow(&ambiguous.next[0]);
    assert_eq!(first.engagement, None);
    assert_eq!(
        first.extensions["engagements"],
        ambiguous.extensions["engagements"]
    );
    for (id, count) in [("orders", 1), ("second", 0)] {
        let chosen = machine(fixture.call(&["--json", "--engagement", id, "brief"]));
        assert_eq!(chosen.engagement.as_ref().unwrap().as_str(), id);
        assert_eq!(chosen.extensions["counts"]["leads"], count);
        assert_eq!(
            fixture.follow(&chosen.next[0]).engagement.unwrap().as_str(),
            id
        );
    }
}

#[test]
fn uncertain_effects_then_cleanup_then_broken_chain_win_next() {
    let fixture = TestWorkspace::new();
    let mut store = fixture.store();
    seed_lead(&mut store, &fixture.id, 1, LEAD_BODY);
    let mut unknown = Run::declare(fixture.id.clone(), Sha256Digest::of(b"experiment"));
    unknown.id = "R-effects".parse().unwrap();
    unknown.effects = Effect::Unknown;
    let unknown_revision = historical_run::seed(&fixture.database(), &unknown);
    let mut cleanup = Run::declare(fixture.id.clone(), Sha256Digest::of(b"experiment"));
    cleanup.id = "R-cleanup".parse().unwrap();
    cleanup.cleanup = Cleanup::Partial;
    let cleanup_revision = historical_run::seed(&fixture.database(), &cleanup);
    let raw = Connection::open(fixture.database()).unwrap();
    raw.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    raw.execute(
        "UPDATE engagements SET head_sequence=1, head_digest=?",
        [Sha256Digest::of(b"missing record").as_str()],
    )
    .unwrap();

    let check = |blocker, expected: &[&str], caveat| {
        let response = machine(fixture.call(&["--json", "status"]));
        assert!(response.blockers.contains(&blocker));
        assert_eq!(response.next.len(), 1);
        let argv = response.next[0]
            .argv
            .iter()
            .map(|arg| arg.as_str())
            .collect::<Vec<_>>();
        assert!(argv.ends_with(expected), "{argv:?}");
        assert!(text(fixture.call(&[])).contains(caveat));
        assert_eq!(
            fixture.follow(&response.next[0]).engagement,
            Some(fixture.id.clone())
        );
    };
    check(
        ErrorCode::EffectUnknown,
        &["show", "R-effects"],
        "Effects are unknown.",
    );
    unknown.effects = Effect::None;
    store.record_run(&unknown, Some(unknown_revision)).unwrap();
    check(
        ErrorCode::ConflictingRun,
        &["show", "R-cleanup"],
        "Cleanup remains owed.",
    );
    cleanup.cleanup = Cleanup::Complete;
    store.record_run(&cleanup, Some(cleanup_revision)).unwrap();
    check(
        ErrorCode::IntegrityFailure,
        &["status", "--details", "records"],
        "The local record chain is broken.",
    );
    let status = machine(fixture.call(&["--json"]));
    let chain = fixture.follow(&status.next[0]);
    assert_eq!(chain.extensions["local_chain"]["head_sequence"], 1);
    assert_eq!(chain.extensions["local_chain"]["linked_records"], 0);
}

#[test]
fn linked_record_ids_are_inspectable_with_finding_claims_withheld() {
    let fixture = TestWorkspace::new();
    let mut store = fixture.store();
    seed_lead(&mut store, &fixture.id, 1, LEAD_BODY);
    let mut run = Run::declare(fixture.id.clone(), Sha256Digest::of(b"experiment"));
    let revision = historical_run::seed(&fixture.database(), &run);
    run.state = scourge_core::wire::RunState::Finalized;
    store.record_run(&run, Some(revision)).unwrap();
    let mut index = VerificationIndex {
        engagement: fixture.id.clone(),
        sequence: 1,
        record_id: "V-local".parse().unwrap(),
        run_id: run.id.clone(),
        lead_id: "L-00001".parse().unwrap(),
        record: Artifact {
            artifact_id: "artifact.pointer".parse().unwrap(),
            digest: Sha256Digest::of(b"only a coordination pointer"),
        },
    };
    let record_bytes = verification_bytes(&index, &run, None);
    index.record.digest = Sha256Digest::of(&record_bytes);
    let intent = PublicationIntentV1 {
        schema: PublicationIntentV1Tag::PublicationIntentV1,
        intent_id: "P-local".parse().unwrap(),
        engagement: fixture.id.clone(),
        run_id: index.run_id.clone(),
        record_id: index.record_id.clone(),
        record_digest: index.record.digest.clone(),
        expected_head: Checkpoint {
            engagement: fixture.id.clone(),
            sequence: 0,
            record_digest: None,
        },
        state: PublicationState::Pending,
        artifact_id: None,
    };
    historical_run::seed_linked_record(&fixture.database(), &intent, &index, Some(&record_bytes));
    let status = machine(fixture.call(&["--json"]));
    assert_eq!(status.extensions["counts"]["linked_records"], 1);
    assert!(status.extensions["counts"]["verified_findings"].is_null());
    assert!(!status.blockers.contains(&ErrorCode::IntegrityFailure));
    let details = machine(fixture.call(&["status", "--details", "records", "--json"]));
    assert_eq!(
        details.extensions["local_chain"]["record_ids"],
        serde_json::json!(["V-local"])
    );
    assert_eq!(
        fixture.follow(&details.next[0]).extensions["record"]["id"],
        "V-local"
    );
}

#[test]
fn bound_transport_observations_are_typed_and_status_touches_no_capability() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let marker = root.join("subprocess-marker");
    let executable = root.join("teapot");
    let fixture_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/entry-subprocess");
    symlink(fixture_script, &executable).unwrap();
    assert!(Command::new(&executable).status().unwrap().success());
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();

    let socket = root.join("teapot-socket");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    drop(UnixStream::connect(&socket).unwrap());
    drop(listener.accept().unwrap());

    let credential = root.join("credential-source");
    assert!(
        Command::new("mkfifo")
            .arg(&credential)
            .status()
            .unwrap()
            .success()
    );
    let mut witness = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(2048)
        .open(&credential)
        .unwrap();
    witness.write_all(b"positive").unwrap();
    let mut positive = [0_u8; 8];
    witness.read_exact(&mut positive).unwrap();
    assert_eq!(&positive, b"positive");
    witness.write_all(b"untouched secret").unwrap();

    let fixture = TestWorkspace::from(
        temporary,
        Authority {
            executables: BTreeMap::from([("teapot".into(), executable)]),
            sockets: BTreeMap::from([("teapot".into(), socket.clone())]),
            credential_sources: BTreeMap::from([(
                "session".into(),
                credential.to_str().unwrap().into(),
            )]),
            ..Authority::default()
        },
    );
    let route = teapot_route_digest(
        TransportKind::TeapotProject,
        socket.to_str().unwrap(),
        "project.teapot.development",
    );
    let unobserved = machine(fixture.call(&["--json"]));
    assert!(!unobserved.extensions.contains_key("teapot"));
    let transport = unobserved.transport.unwrap();
    assert_eq!(transport.kind, TransportKind::TeapotProject);
    assert_eq!(transport.endpoint.as_str(), socket.to_str().unwrap());
    assert_eq!(
        fixture.follow(&transport.action).command.unwrap().as_str(),
        "doctor"
    );

    let mut store = fixture.store();
    let evidence_digest = Sha256Digest::of(b"inventory snapshot");
    store
        .record_teapot_observation(
            &fixture.id,
            &route,
            &TeapotObservation {
                observed_at: OBSERVED.parse().unwrap(),
                evidence_digest: evidence_digest.clone(),
                unrecorded_findings: Some(3),
                unrecorded_leads: None,
            },
        )
        .unwrap();
    let delayed = TeapotObservation {
        observed_at: "2026-11-24T15:00:00Z".parse().unwrap(),
        evidence_digest: Sha256Digest::of(b"older inventory snapshot"),
        unrecorded_findings: Some(44),
        unrecorded_leads: Some(8),
    };
    assert!(matches!(
        store.record_teapot_observation(&fixture.id, &route, &delayed),
        Err(StoreError::Conflict)
    ));
    let response = machine(fixture.call(&["--json", "onboard"]));
    assert_eq!(
        response.extensions["teapot"]["evidence_digest"],
        evidence_digest.as_str()
    );
    assert_eq!(response.extensions["teapot"]["unrecorded_findings"], 3);
    assert!(response.extensions["teapot"]["unrecorded_leads"].is_null());
    let human = text(fixture.call(&[]));
    assert!(human.contains("Teapot finding count 3, Teapot lead count unavailable"));
    assert!(human.contains("A Teapot finding or Teapot lead is a discovery input."));

    for (code, native_exit) in [
        (DiagnosticCode::WrongListener, Some(0)),
        (DiagnosticCode::ToolUnavailable, None),
    ] {
        store
            .record_check(
                &fixture.id,
                &RecordedCheck {
                    stage: Stage::Describe,
                    observed_at: OBSERVED.parse().unwrap(),
                    code: Some(code),
                    native_exit,
                    wrapper_exit: Some(0),
                    run_id: None,
                },
            )
            .unwrap();
        let output = fixture.call(&["--json", "tldr"]);
        assert!(output.stdout.len() <= 2048, "{} bytes", output.stdout.len());
        let typed: wire::DiagnosticV1 = wire::from_slice(&output.stderr).unwrap();
        let status = machine(output);
        assert!(status.blockers.contains(&ErrorCode::DependencyUnavailable));
        assert_eq!(
            status.diagnostics.as_slice(),
            std::slice::from_ref(&typed.diagnostic)
        );
        assert_eq!(typed.diagnostic.code, code);
        assert_eq!(typed.diagnostic.wrapper_exit, Some(0));
        let doctor = fixture.follow(&status.transport.unwrap().action);
        assert_eq!(doctor.diagnostics[0].code, code);
    }
    assert!(!marker.exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let mut remaining = Vec::new();
    Read::by_ref(&mut witness)
        .take(16)
        .read_to_end(&mut remaining)
        .unwrap();
    assert_eq!(remaining, b"untouched secret");
}
