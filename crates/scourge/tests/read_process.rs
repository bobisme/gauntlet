//! Stock binary witnesses for binding and local reads. A separate fixed-clock
//! child exercises the same SQLite projection for age and storage edge cases.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{self, Command, Output},
};

use scourge::BoundReads;
use scourge_core::{
    canonical::{self, Sha256Digest},
    domain::{LeadRevision, Run, RunStep, VerificationIndex},
    store::{Store, read::ReadStore},
    verification::registry,
    wire::{
        self, Artifact, Cleanup, Completeness, Effect, ErrorCode, Flow, OracleResult,
        PublicationIntentV1, PublicationIntentV1Tag, PublicationState, Reproduction, ResponseV1,
        RunFlag, RunState,
    },
};
use serde_json::{Value, json};

#[path = "read_process/doctor.rs"]
mod doctor;
#[path = "fixtures/historical_run.rs"]
mod historical_run;
#[path = "read_process/qualified.rs"]
mod qualified;
#[path = "read_process/wal.rs"]
mod wal;

const CHILD: &str = "SCOURGE_READ_TEST_CHILD";
const SCOPE: &str = "selected engagement";
const FOREIGN: &str = "foreign engagement";
const SECRET: &str = "seeded-secret-a8FsvJs5";
const FLOW_ID: u64 = u64::MAX;
const DECLARATION: &[u8] =
    include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");

fn main() {
    if let Some(mode) = env::var_os(CHILD) {
        run_child(mode.to_str().unwrap());
    }

    let fixture = Fixture::seed();
    cli_grammar_and_envelope(&fixture);
    views_and_blockers(&fixture);
    absent_and_foreign_are_identical(&fixture);
    list_pages(&fixture);
    store_selection(&fixture);
    one_snapshot(&fixture);
    doctor::cases(&fixture);
    wal::damaged_sidecars(&fixture);
    bound_process(&fixture);
    #[cfg(target_os = "linux")]
    no_native_reads(&fixture);
    doctor::stock_regressions(&fixture);
    qualified::cases();
    staged_record_integrity();
    staged_record_oracle_provenance();
    mutable_legacy_markers_do_not_hide_current_candidate_corruption();
}

fn run_child(mode: &str) -> ! {
    match mode {
        #[cfg(target_os = "linux")]
        "network-witness" => {
            let _ = std::net::TcpStream::connect("127.0.0.1:1");
            process::exit(0);
        }
        #[cfg(target_os = "linux")]
        "process-witness" => {
            let _ = Command::new("/bin/true").status();
            process::exit(0);
        }
        #[cfg(target_os = "linux")]
        "credential-witness" => {
            let _ = fs::read(env::var_os("SCOURGE_READ_TEST_CREDENTIAL").unwrap());
            process::exit(0);
        }
        "read" => {
            let bound = BoundReads::from_resolved_paths(
                env::var("SCOURGE_READ_TEST_WORKSPACE")
                    .unwrap()
                    .parse()
                    .unwrap(),
                env::var("SCOURGE_READ_TEST_STORE")
                    .unwrap()
                    .parse()
                    .unwrap(),
            );
            let exit = scourge::run(
                env::args_os(),
                env::var_os("FORMAT").as_deref(),
                false,
                |invocation| {
                    scourge::dispatch_read_at(
                        invocation,
                        Some(&bound),
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000),
                    )
                },
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            )
            .unwrap();
            process::exit(i32::from(exit));
        }
        _ => panic!("unknown test mode"),
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    working: PathBuf,
    path: PathBuf,
    writer: Store,
}

impl Fixture {
    fn seed() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("scourge paths ")
            .tempdir()
            .unwrap();
        let root = dir.path().join("inspected tree");
        let working = root.join("nested");
        fs::create_dir_all(&working).unwrap();
        let state = dir.path().join("operator state");
        let declaration = dir.path().join(format!("{SCOPE}.toml"));
        fs::write(&declaration, DECLARATION).unwrap();
        let path = root.join(".scourge/state.sqlite3");
        let init = stock_command(dir.path(), &state)
            .args(["--json", "init"])
            .arg(&root)
            .arg("--engagement")
            .arg(&declaration)
            .output()
            .unwrap();
        assert!(response(&init, 0).0.ok);
        let empty_before = stock_command(&working, &state)
            .args(["list", "--json"])
            .output()
            .unwrap();
        let (envelope, json) = response(&empty_before, 0);
        assert_eq!(envelope.engagement.unwrap().as_str(), SCOPE);
        assert_eq!(json["leads"], json!([]));
        let files: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(files, ["state.sqlite3"]);
        let parked = dir.path().join("parked coordination");
        fs::rename(path.parent().unwrap(), &parked).unwrap();
        let legacy = stock_command(&working, &state)
            .args(["doctor", "--json"])
            .output()
            .unwrap();
        let (legacy, _) = response(&legacy, 0);
        assert_eq!(legacy.blockers, [ErrorCode::CapabilityUnavailable]);
        assert!(!path.parent().unwrap().exists());
        fs::rename(parked, path.parent().unwrap()).unwrap();
        let idle_writer = Store::open(&path).unwrap();
        let initial = wal::snapshot_family(&path);
        let empty_with_idle_writer = stock_command(&working, &state)
            .args(["list", "--json"])
            .output()
            .unwrap();
        let (_, json) = response(&empty_with_idle_writer, 0);
        assert_eq!(json["leads"], json!([]));
        assert_eq!(wal::snapshot_family(&path), initial);
        let before_first_write = idle_writer.revision().unwrap();
        drop(idle_writer);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.revision().unwrap(), before_first_write);
        drop(reopened);
        let closed_family = wal::snapshot_family(&path);
        let after_close = stock_command(&working, &state)
            .args(["list", "--json"])
            .output()
            .unwrap();
        assert_eq!(response(&after_close, 0).1["leads"], json!([]));
        assert_eq!(wal::snapshot_family(&path), closed_family);
        for engagement in [FOREIGN, "empty"] {
            let add = stock_command(&working, &state)
                .args(["--json", "engagement", "add"])
                .arg(&declaration)
                .args(["--name", engagement])
                .output()
                .unwrap();
            assert!(response(&add, 0).0.ok);
        }
        let mut writer = Store::open(&path).unwrap();
        let digest = Sha256Digest::of(b"seeded manifest");
        for engagement in [SCOPE, FOREIGN, "empty"] {
            writer
                .append_manifest(
                    &engagement.parse().unwrap(),
                    &Artifact {
                        artifact_id: SECRET.parse().unwrap(),
                        digest: digest.clone(),
                    },
                    &digest,
                )
                .unwrap();
        }
        for number in (0..305).rev() {
            seed_lead(&mut writer, SCOPE, &format!("L-{number:04}"), 1);
        }
        seed_lead(&mut writer, FOREIGN, "L-foreign", 1);
        for (engagement, label, lead, flow_id) in [
            (SCOPE, "local", "L-0000", FLOW_ID),
            (FOREIGN, "foreign", "L-foreign", 88),
        ] {
            let engagement = engagement.parse().unwrap();
            let mut run = Run::declare(engagement, digest.clone());
            run.id = format!("R-{label}").parse().unwrap();
            run.request_key = format!("rk_{label}").parse().unwrap();
            run.state = RunState::Finalized;
            run.effects = Effect::Unknown;
            run.flags = vec![RunFlag::ReconciliationRequired];
            run.oracle_result = Some(OracleResult::Invalid);
            run.reproduction = Reproduction::NotReproduced;
            run.cleanup = Cleanup::Unknown;
            run.steps.push(RunStep {
                number: 1,
                step: SECRET.parse().unwrap(),
                request_digest: digest.clone(),
                flow_id_floor: None,
                instrument_reference: Some(SECRET.parse().unwrap()),
                effects: Some(run.effects),
                flows: vec![Flow {
                    step: SECRET.parse().unwrap(),
                    flow_id: Some(flow_id),
                    original: Some(Artifact {
                        artifact_id: SECRET.parse().unwrap(),
                        digest: digest.clone(),
                    }),
                    completeness: Completeness::Partial,
                    decoder: None,
                }],
            });
            historical_run::seed(&path, &run);
            let (_, head) = writer.checkpoint(&run.engagement).unwrap();
            let record_id: scourge_core::ids::VerificationId =
                format!("V-{label}").parse().unwrap();
            let mut index = VerificationIndex {
                engagement: run.engagement.clone(),
                sequence: head.sequence + 1,
                record_id: record_id.clone(),
                run_id: run.id.clone(),
                lead_id: lead.parse().unwrap(),
                record: Artifact {
                    artifact_id: format!("artifact-{label}").parse().unwrap(),
                    digest: digest.clone(),
                },
            };
            let record_bytes = verification_bytes(&index, &run, head.record_digest.as_ref());
            index.record.digest = Sha256Digest::of(&record_bytes);
            let intent = PublicationIntentV1 {
                schema: PublicationIntentV1Tag::PublicationIntentV1,
                intent_id: format!("P-{label}").parse().unwrap(),
                run_id: run.id.clone(),
                engagement: run.engagement.clone(),
                expected_head: head,
                record_id,
                record_digest: index.record.digest.clone(),
                state: PublicationState::Pending,
                artifact_id: None,
            };
            historical_run::seed_linked_record(&path, &intent, &index, Some(&record_bytes));
        }
        doctor::seed(&mut writer);
        Self {
            dir,
            root,
            state,
            working,
            path,
            writer,
        }
    }

    fn configure(&self, command: &mut Command) {
        command
            .current_dir(&self.working)
            .env_remove("FORMAT")
            .env(CHILD, "read")
            .env("SCOURGE_READ_TEST_WORKSPACE", &self.root)
            .env("SCOURGE_READ_TEST_STORE", &self.path);
    }

    fn child(&self) -> Command {
        let mut cmd = Command::new(env::current_exe().unwrap());
        self.configure(&mut cmd);
        cmd
    }

    fn stock(&self) -> Command {
        stock_command(&self.working, &self.state)
    }

    fn read(&self, args: &[&str]) -> Output {
        self.child()
            .args(["--engagement", SCOPE])
            .args(args)
            .output()
            .unwrap()
    }

    fn json(&self, args: &[&str], code: i32) -> (ResponseV1, Value) {
        let output = self.read(&[args, &["--format=json"]].concat());
        response(&output, code)
    }
}

fn stock_command(cwd: &Path, state: &Path) -> Command {
    let mut process = Command::new(env!("CARGO_BIN_EXE_scourge"));
    process
        .current_dir(cwd)
        .env("XDG_STATE_HOME", state)
        .env_remove("FORMAT");
    process
}

fn seed_lead(store: &mut Store, engagement: &str, id: &str, revision: u64) {
    store
        .append_lead_revision(
            &engagement.parse().unwrap(),
            &LeadRevision {
                lead_id: id.parse().unwrap(),
                revision,
                text: format!("{SECRET}\n\u{1b}[2J{}", "oversize".repeat(1024))
                    .parse()
                    .unwrap(),
                class: Some(SECRET.parse().unwrap()),
                property: None,
                slots: [(SECRET.parse().unwrap(), json!(SECRET))].into(),
                proposed_policy: Some(json!({"credentials": SECRET})),
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
    record["record_id"] = json!(index.record_id);
    record["engagement"] = json!(index.engagement);
    record["sequence"] = json!(index.sequence);
    record["prev_record_digest"] = predecessor.map_or(Value::Null, |digest| json!(digest));
    record["lead_id"] = json!(index.lead_id);
    record["lead_revision"] = json!(1);
    record["engagement_revision"] = json!(1);
    record["run_id"] = json!(index.run_id);
    record["experiment_digest"] = json!(run.experiment_digest);
    record["oracle"]["digest"] = json!(registry::oracle_digest());
    record["limitations"] = json!(registry::KNOWN_MISSES);
    canonical::to_vec(&record).unwrap()
}

fn response(output: &Output, code: i32) -> (ResponseV1, Value) {
    assert!(output.stderr.is_empty(), "{output:?}");
    envelope(output, code)
}

fn envelope(output: &Output, code: i32) -> (ResponseV1, Value) {
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    assert!(output.stdout.ends_with(b"\n"));
    assert_eq!(output.stdout.iter().filter(|&&b| b == b'\n').count(), 1);
    assert_redacted(output);
    let envelope: ResponseV1 = wire::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope.effects, Effect::None);
    (envelope, serde_json::from_slice(&output.stdout).unwrap())
}

fn assert_redacted(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = str::from_utf8(bytes).unwrap();
        assert!(!text.contains(SECRET));
        assert!(!text.contains('\u{1b}'));
    }
}

fn cli_grammar_and_envelope(fixture: &Fixture) {
    for args in [
        &["show"][..],
        &["show", "last"],
        &["show", "L-0001", "R-local"],
        &["show", "L-0001", "--depth", SECRET],
        &["show", "finding:R-1"],
        &["show", "teapot:flow:+1"],
        &["show", "teapot:flow:18446744073709551616"],
        &["list", "records"],
        &["list", "leads", "--status", "finalized"],
        &["list", "runs", "--limit", "0"],
        &["list", "runs", "--limit", "101"],
        &["list", "runs", "--offset", "-1"],
    ] {
        let (envelope, _) = fixture.json(args, 2);
        assert_eq!(envelope.error.unwrap().code, ErrorCode::UsageError);
        assert!(envelope.workspace.is_none());
    }
    for command in ["show", "list"] {
        let (envelope, json) = fixture.json(&[command, "--help"], 0);
        assert_eq!(envelope.command.unwrap().as_str(), command);
        assert!(json["help"].as_str().unwrap().contains("Examples:"));
    }
    let output = fixture.child().args(["list", "--json"]).output().unwrap();
    let (envelope, json) = response(&output, 3);
    assert_eq!(envelope.error.unwrap().code, ErrorCode::EngagementRequired);
    assert!(envelope.engagement.is_none());
    assert_eq!(json["engagements"], json!(["empty", FOREIGN, SCOPE]));
}

fn views_and_blockers(fixture: &Fixture) {
    let (envelope, json) = fixture.json(&["show", "L-0001", "--depth", "full"], 0);
    assert_eq!(envelope.engagement.unwrap().as_str(), SCOPE);
    assert_eq!(
        envelope.workspace.unwrap().as_str(),
        fixture.root.to_str().unwrap()
    );
    assert_eq!(json["result"], "shown");
    assert_eq!(
        json["lead"],
        json!({
            "id": "L-0001", "revision": 1, "has_records": false, "text_withheld": true
        })
    );
    assert!(json["transport"].is_null());
    assert_eq!(json["diagnostics"], json!([]));

    let text = fixture.read(&["show", "L-0001", "--format", "text"]);
    assert_redacted(&text);
    assert_eq!(text.stdout, b"L-0001  lead  rev 1  text withheld\n");
    let pretty = fixture.read(&["show", "L-0001", "--format", "pretty"]);
    assert_redacted(&pretty);
    assert_eq!(
        str::from_utf8(&pretty.stdout).unwrap(),
        "L-0001  │  lead  │  rev 1  │  text withheld\n"
    );

    let (envelope, json) = fixture.json(&["show", "R-local", "--depth", "full"], 0);
    assert_eq!(envelope.request_key.unwrap().as_str(), "rk_local");
    assert_eq!(
        json["run"],
        json!({
            "id": "R-local", "state": "finalized", "flags": ["reconciliation_required"],
            "oracle_result": "invalid", "reproduction": "not_reproduced", "cleanup": "unknown"
        })
    );
    assert_eq!(json["run_effects"], "unknown");
    assert_eq!(json["experiment_digest"].as_str().unwrap().len(), 64);
    let run = fixture.read(&["list", "runs", "--format", "text"]);
    assert_eq!(
        run.stdout,
        b"R-local  run  finalized  invalid  not_reproduced  unknown  reconciliation_required  effects=unknown\n"
    );
    let run = fixture.read(&["list", "runs", "--format", "pretty"]);
    assert_eq!(
        str::from_utf8(&run.stdout).unwrap(),
        "R-local  │  run  │  finalized  │  invalid  │  not_reproduced  │  unknown  │  reconciliation_required  │  effects=unknown\n"
    );

    let (_, json) = fixture.json(&["show", "V-local"], 0);
    assert_eq!(json["record"]["run_id"], "R-local");
    assert_eq!(json["record"]["sequence"], 1);
    assert!(json["record"]["oracle_guide"].is_null());
    assert!(json["record"]["known_misses"].is_null());
    let record_text = fixture.read(&["show", "V-local", "--format", "text"]);
    assert_eq!(
        record_text.stdout,
        b"V-local  record  seq 1  R-local  L-0000\n"
    );
    let record_title = fixture.read(&["show", "V-local", "--depth", "title", "--format", "text"]);
    assert_eq!(record_title.stdout, b"V-local  record\n");
    let (_, title_json) = fixture.json(&["show", "V-local", "--depth", "title"], 0);
    assert!(title_json["record"]["oracle_guide"].is_null());
    assert!(title_json["record"]["known_misses"].is_null());
    let (_, full_json) = fixture.json(&["show", "V-local", "--depth", "full"], 0);
    assert_eq!(
        full_json["record"]["oracle_guide"],
        "docs/oracles/web.private-object-read.v1.md"
    );
    assert_eq!(
        full_json["record"]["known_misses"],
        json!(registry::KNOWN_MISSES)
    );
    let full = fixture.read(&["show", "V-local", "--depth", "full", "--format", "text"]);
    let full = String::from_utf8(full.stdout).unwrap();
    let misses = registry::KNOWN_MISSES
        .iter()
        .map(|miss| format!("V-local  known miss  {miss}\n"))
        .collect::<String>();
    assert_eq!(
        full,
        format!(
            "V-local  record  seq 1  R-local  L-0000\nV-local  record digest  {}\nV-local  oracle guide  docs/oracles/web.private-object-read.v1.md\n{misses}",
            json["record"]["record_digest"].as_str().unwrap()
        )
    );
    let (_, json) = fixture.json(&["show", &format!("teapot:flow:{FLOW_ID}")], 0);
    assert_eq!(json["flow"]["flow_id"], FLOW_ID);
    assert_eq!(json["flow"]["run_id"], "R-local");
    assert_eq!(json["flow"]["completeness"], "partial");

    for args in [
        &["show", "finding:L-0000"][..],
        &["show", "L-0000"],
        &["list", "findings", "--status", "verified"],
        &["list", "leads", "--status", "open"],
        &["show", "V-local", "--rederive"],
    ] {
        let (envelope, json) = fixture.json(args, 0);
        assert!(envelope.ok && envelope.error.is_none());
        assert_eq!(json["result"], "blocked");
        assert_eq!(envelope.blockers, [ErrorCode::CapabilityUnavailable]);
        assert!(envelope.finding.is_none());
        assert_eq!(envelope.advice.len(), 1);
    }
}

fn absent_and_foreign_are_identical(fixture: &Fixture) {
    for (foreign, absent) in [
        ("L-foreign", "L-absent"),
        ("R-foreign", "R-absent"),
        ("V-foreign", "V-absent"),
        ("finding:L-foreign", "finding:L-absent"),
        ("teapot:flow:88", "teapot:flow:99"),
    ] {
        let foreign = fixture.read(&["show", foreign, "--json"]);
        let absent = fixture.read(&["show", absent, "--json"]);
        let (envelope, _) = response(&foreign, 3);
        response(&absent, 3);
        assert_eq!(envelope.error.unwrap().code, ErrorCode::ObjectNotFound);
        assert_eq!(envelope.run, None);
        assert_eq!(envelope.request_key, None);
        assert_eq!(foreign.stdout, absent.stdout);
        assert_eq!(foreign.stderr, absent.stderr);
    }
}

fn list_pages(fixture: &Fixture) {
    let (first, json) = fixture.json(&["list"], 0);
    assert_eq!(json["leads"].as_array().unwrap().len(), 20);
    assert_eq!(json["leads"][0]["id"], "L-0000");
    assert_eq!(json["leads"][19]["id"], "L-0019");
    assert_eq!(json["page"]["next_offset"], 20);
    let action = &first.next[0];
    let next = fixture
        .child()
        .args(action.argv[1..].iter().map(|arg| arg.as_str()))
        .output()
        .unwrap();
    let (_, json) = response(&next, 0);
    assert_eq!(json["leads"][0]["id"], "L-0020");
    let (_, json) = fixture.json(&["list", "leads", "--limit", "100", "--offset", "300"], 0);
    assert_eq!(json["leads"].as_array().unwrap().len(), 5);
    assert_eq!(json["leads"][4]["id"], "L-0304");
    assert!(json["page"]["next_offset"].is_null());
    let (_, json) = fixture.json(&["list", "runs", "--status", "finalized"], 0);
    let records = json["runs"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["id"], "R-local");
    let (_, json) = fixture.json(&["list", "runs", "--status", "declared"], 0);
    assert_eq!(json["runs"], json!([]));
    let empty = fixture
        .child()
        .args(["list", "--engagement", "empty", "--json"])
        .output()
        .unwrap();
    let (_, json) = response(&empty, 0);
    assert_eq!(json["leads"], json!([]));
    assert!(json["page"]["next_offset"].is_null());
    assert_eq!(json["next"], json!([]));
}

fn store_selection(fixture: &Fixture) {
    let missing = fixture.dir.path().join("missing coordination.sqlite");
    let output = fixture
        .child()
        .env("SCOURGE_READ_TEST_STORE", &missing)
        .args(["list", "--json"])
        .output()
        .unwrap();
    let (envelope, _) = response(&output, 6);
    assert_eq!(envelope.error.unwrap().code, ErrorCode::IntegrityFailure);
    assert!(!missing.exists());

    let path = fixture.dir.path().join("single engagement.sqlite");
    let mut writer = Store::open(&path).unwrap();
    let digest = Sha256Digest::of(b"manifest");
    writer
        .append_manifest(
            &SCOPE.parse().unwrap(),
            &Artifact {
                artifact_id: SECRET.parse().unwrap(),
                digest: digest.clone(),
            },
            &digest,
        )
        .unwrap();
    drop(writer);
    let output = fixture
        .child()
        .env("SCOURGE_READ_TEST_STORE", &path)
        .args(["list", "--json"])
        .output()
        .unwrap();
    let (envelope, _) = response(&output, 0);
    assert_eq!(envelope.engagement.unwrap().as_str(), SCOPE);
}

fn staged_record_integrity() {
    for tamper in [
        "DROP TRIGGER publication_candidate_no_delete;
         DELETE FROM publication_candidates WHERE intent_id='P-local';",
        "DROP TRIGGER publication_candidate_no_update;
         UPDATE publication_candidates SET record_bytes=x'7b7d' WHERE intent_id='P-local';",
    ] {
        let fixture = Fixture::seed();
        let connection = rusqlite::Connection::open(&fixture.path).unwrap();
        connection.execute_batch(tamper).unwrap();
        drop(connection);
        let (envelope, _) = fixture.json(&["show", "V-local"], 6);
        assert_eq!(
            envelope.error.unwrap().code,
            ErrorCode::IntegrityFailure,
            "required staged bytes that are missing or fail the record digest are not legacy"
        );
    }
}

fn staged_record_oracle_provenance() {
    let mutations = [
        (
            "wrong oracle digest",
            json!({
                "oracle_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        ),
        (
            "unknown limitation",
            json!({
                "limitations": ["unregistered limitation"]
            }),
        ),
        (
            "duplicate limitation",
            json!({
                "limitations": [
                    registry::KNOWN_MISSES[0], registry::KNOWN_MISSES[0],
                    registry::KNOWN_MISSES[1], registry::KNOWN_MISSES[2],
                    registry::KNOWN_MISSES[3], registry::KNOWN_MISSES[4],
                    registry::KNOWN_MISSES[5], registry::KNOWN_MISSES[6]
                ]
            }),
        ),
        ("empty applicable limitations", json!({"limitations": []})),
        (
            "incomplete applicable limitations",
            json!({
                "limitations": [registry::KNOWN_MISSES[0]]
            }),
        ),
        ("malformed limitation", json!({"limitations": [1]})),
    ];

    for (case, mutation) in mutations {
        let fixture = Fixture::seed();
        let connection = rusqlite::Connection::open(&fixture.path).unwrap();
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT record_bytes FROM publication_candidates WHERE intent_id='P-local'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut record = canonical::parse(&bytes).unwrap();
        if let Some(digest) = mutation.get("oracle_digest") {
            record["oracle"]["digest"] = digest.clone();
        }
        if let Some(limitations) = mutation.get("limitations") {
            record["limitations"] = limitations.clone();
        }
        let bytes = canonical::to_vec(&record).unwrap();
        let digest = Sha256Digest::of(&bytes);
        assert_eq!(Sha256Digest::of(&bytes), digest);
        if case != "malformed limitation" {
            canonical::from_digest::<scourge_core::wire::VerificationV1>(&bytes, &digest).unwrap();
        }

        connection
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DROP TRIGGER publication_candidate_no_update;
                 DROP TRIGGER publication_intent_transition;
                 DROP TRIGGER verification_no_update;",
            )
            .unwrap();
        connection
            .execute(
                "UPDATE publication_candidates SET record_bytes=?1 WHERE intent_id='P-local'",
                [&bytes],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE publication_intents SET record_digest=?1 WHERE id='P-local'",
                [digest.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE verifications SET record_digest=?1 WHERE record_id='V-local'",
                [digest.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE engagements SET head_digest=?1 WHERE id=?2",
                (digest.as_str(), SCOPE),
            )
            .unwrap();
        drop(connection);

        let (envelope, json) = fixture.json(&["show", "V-local", "--depth", "full"], 6);
        assert_eq!(
            envelope.error.unwrap().code,
            ErrorCode::IntegrityFailure,
            "{case}: valid outer digest and coordination references cannot authenticate inner oracle provenance: {json}"
        );
        assert!(json["record"].is_null(), "{case}");
    }
}

fn mutable_legacy_markers_do_not_hide_current_candidate_corruption() {
    for tamper in [
        // A v12 schema cannot become historical just because its mutable
        // user_version header was lowered, even when candidate bytes vanish.
        "PRAGMA user_version=11;
         DROP TRIGGER publication_candidate_no_delete;
         DELETE FROM publication_candidates WHERE intent_id='P-local';",
        // A current intent cannot opt into the migration fallback by lowering
        // its mutable flag and deleting the staged bytes.
        "DROP TRIGGER publication_intent_transition;
         UPDATE publication_intents SET candidate_required=0 WHERE id='P-local';
         DROP TRIGGER publication_candidate_no_delete;
         DELETE FROM publication_candidates WHERE intent_id='P-local';",
    ] {
        let fixture = Fixture::seed();
        rusqlite::Connection::open(&fixture.path)
            .unwrap()
            .execute_batch(tamper)
            .unwrap();
        let (envelope, _) = fixture.json(&["show", "V-local"], 6);
        assert_eq!(
            envelope.error.unwrap().code,
            ErrorCode::IntegrityFailure,
            "mutable schema markers cannot route a current record through legacy fallback"
        );
    }
}

fn one_snapshot(fixture: &Fixture) {
    let mut writer = Store::open(&fixture.path).unwrap();
    let reader = ReadStore::open(&fixture.path).unwrap();
    let id = "L-0001".parse().unwrap();
    reader
        .snapshot(|snapshot| {
            let scope = snapshot.scope(SCOPE.parse().unwrap())?;
            assert_eq!(scope.lead(&id)?.revision, 1);
            seed_lead(&mut writer, SCOPE, "L-0001", 2);
            assert_eq!(scope.lead(&id)?.revision, 1);
            Ok(())
        })
        .unwrap();
    reader
        .snapshot(|snapshot| {
            let scope = snapshot.scope(SCOPE.parse().unwrap())?;
            assert_eq!(scope.lead(&id)?.revision, 2);
            Ok(())
        })
        .unwrap();
}

fn bound_process(fixture: &Fixture) {
    let output = fixture.stock().args(["list", "--json"]).output().unwrap();
    let (scope_required, json) = response(&output, 3);
    assert_eq!(
        scope_required.error.unwrap().code,
        ErrorCode::EngagementRequired
    );
    assert_eq!(json["engagements"], json!(["empty", FOREIGN, SCOPE]));

    let show = fixture
        .stock()
        .args(["--engagement", SCOPE, "show", "L-0001", "--json"])
        .output()
        .unwrap();
    let (view, json) = response(&show, 0);
    assert_eq!(
        view.workspace.unwrap().as_str(),
        fixture.root.to_str().unwrap()
    );
    assert_eq!(json["lead"]["revision"], 2);
    let text = fixture
        .stock()
        .args(["--engagement", SCOPE, "show", "L-0001", "--format", "text"])
        .output()
        .unwrap();
    assert_eq!(text.status.code(), Some(0));
    assert_eq!(text.stdout, b"L-0001  lead  rev 2  text withheld\n");
    assert!(text.stderr.is_empty());

    let other = fixture
        .stock()
        .args(["--engagement", FOREIGN, "list", "leads", "--json"])
        .output()
        .unwrap();
    let (_, json) = response(&other, 0);
    assert_eq!(json["leads"].as_array().unwrap().len(), 1);
    assert_eq!(json["leads"][0]["id"], "L-foreign");
    let absent = fixture
        .stock()
        .args(["--engagement", SCOPE, "show", "L-absent", "--json"])
        .output()
        .unwrap();
    let foreign = fixture
        .stock()
        .args(["--engagement", SCOPE, "show", "L-foreign", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        response(&absent, 3).0.error.unwrap().code,
        ErrorCode::ObjectNotFound
    );
    assert_eq!(absent.stdout, foreign.stdout);

    // A row prepared before an interrupted binding publication has no
    // authority until that engagement is in the operator-selected binding.
    let mut writer = Store::open(&fixture.path).unwrap();
    let digest = Sha256Digest::of(b"unpublished binding fixture");
    writer
        .append_manifest(
            &"database-only".parse().unwrap(),
            &Artifact {
                artifact_id: SECRET.parse().unwrap(),
                digest: digest.clone(),
            },
            &digest,
        )
        .unwrap();
    let output = fixture
        .stock()
        .args(["--engagement", "database-only", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        response(&output, 3).0.error.unwrap().code,
        ErrorCode::ObjectNotFound
    );
}

#[cfg(target_os = "linux")]
fn no_native_reads(fixture: &Fixture) {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let guard = fixture.dir.path().join("read guard");
    let compiled = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&guard)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/read_guard.c"))
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");

    let credentials = fixture.dir.path().join(format!("credentials-{SECRET}"));
    let originals = fixture.dir.path().join(format!("evidence-{SECRET}"));
    let original = originals.join("original.json");
    let exposed_path = fixture.working.join("evidence link");
    let teapot = fixture.dir.path().join(format!("teapot-{SECRET}"));
    let investigation = fixture.dir.path().join(format!("inv-{SECRET}"));
    let config = fixture.working.join("scourge.toml");
    let socket = fixture.dir.path().join(format!("engine-{SECRET}.sock"));
    fs::write(&credentials, SECRET).unwrap();
    fs::create_dir(&originals).unwrap();
    fs::write(&original, SECRET).unwrap();
    symlink(&originals, &exposed_path).unwrap();
    for adapter in [&teapot, &investigation] {
        fs::write(adapter, "#!/bin/sh\nexit 121\n").unwrap();
        fs::set_permissions(adapter, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(&config, format!(
        "teapot = {teapot:?}\ninvestigation = {investigation:?}\ncredentials = {credentials:?}\nevidence_root = {exposed_path:?}\nsocket = {socket:?}\ntarget = 'http://127.0.0.1:1/{SECRET}'\n"
    )).unwrap();

    let guarded = |binary: &Path| {
        let mut command = Command::new(&guard);
        command
            .args([&credentials, &originals, &original, &teapot, &investigation])
            .arg("--")
            .arg(binary);
        fixture.configure(&mut command);
        command.env("XDG_STATE_HOME", &fixture.state);
        command
    };
    let child = env::current_exe().unwrap();
    for (witness, code, message) in [
        ("network-witness", 125, "signal"),
        ("process-witness", 125, "signal"),
        ("credential-witness", 126, "watched path"),
    ] {
        let output = guarded(&child)
            .env(CHILD, witness)
            .env("SCOURGE_READ_TEST_CREDENTIAL", &credentials)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        assert!(str::from_utf8(&output.stderr).unwrap().contains(message));
    }

    let revision = fixture.writer.revision().unwrap();
    let db_before = fs::read(&fixture.path).unwrap();
    let wal = fixture.path.with_file_name("state.sqlite3-wal");
    let wal_before = fs::read(&wal).unwrap();
    let shm = fixture.path.with_file_name("state.sqlite3-shm");
    let shm_before = fs::read(&shm).unwrap();
    let evidence_before = fs::read(&original).unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_scourge"));
    let root = fixture.root.to_str().unwrap();
    let flow = format!("teapot:flow:{FLOW_ID}");
    for (args, projection, expected) in [
        (
            &["show", "L-0001", "--depth", "full"][..],
            "/lead/id",
            "L-0001",
        ),
        (&["show", "finding:L-0000"][..], "/finding_id", "L-0000"),
        (&["show", "R-local"][..], "/run/id", "R-local"),
        (
            &["show", "V-local", "--rederive"][..],
            "/record/id",
            "V-local",
        ),
        (&["show", &flow][..], "/flow/id", flow.as_str()),
        (&["list", "leads"][..], "/leads/0/id", "L-0000"),
        (&["list", "runs"][..], "/runs/0/id", "R-local"),
        (
            &["list", "findings"][..],
            "/blockers/0",
            "CAPABILITY_UNAVAILABLE",
        ),
    ] {
        let output = guarded(binary)
            .args(["--workspace", root, "--engagement", SCOPE, "--json"])
            .args(args)
            .output()
            .unwrap();
        let (view, json) = response(&output, 0);
        assert!(view.ok && view.engagement.unwrap().as_str() == SCOPE);
        assert_eq!(
            json.pointer(projection).and_then(Value::as_str),
            Some(expected),
            "{args:?} {json}"
        );
    }
    let populated = guarded(binary)
        .args([
            "--workspace",
            root,
            "doctor",
            "--engagement",
            SCOPE,
            "--json",
        ])
        .output()
        .unwrap();
    doctor::stock_populated(&populated);
    let empty = guarded(binary)
        .args([
            "--workspace",
            root,
            "doctor",
            "--engagement",
            "empty",
            "--json",
        ])
        .output()
        .unwrap();
    doctor::empty(&empty);
    for (args, code) in [
        (&[][..], 0),
        (&["status"][..], 0),
        (&["help"][..], 0),
        (&["show", "L-0001"][..], 3),
        (&["list"][..], 3),
        (&["doctor"][..], 3),
    ] {
        let output = guarded(binary).arg("--json").args(args).output().unwrap();
        let (envelope, _) = response(&output, code);
        assert!(envelope.workspace.is_none());
        assert!(envelope.engagement.is_none());
        if code == 3 {
            assert_eq!(envelope.error.unwrap().code, ErrorCode::WorkspaceUnbound);
        }
    }
    assert_eq!(fixture.writer.revision().unwrap(), revision);
    assert_eq!(fs::read(&fixture.path).unwrap(), db_before);
    assert_eq!(fs::read(wal).unwrap(), wal_before);
    assert_eq!(fs::read(shm).unwrap(), shm_before);
    assert_eq!(fs::read(&original).unwrap(), evidence_before);
    wal::concurrent_doctor(fixture, || guarded(binary));
}
