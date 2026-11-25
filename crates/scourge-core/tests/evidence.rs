use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use scourge_core::{
    canonical::Sha256Digest,
    evidence::{
        CaptureHandle, Completion, Evidence, EvidenceError, RecordKind, RecordRequest, Withdrawal,
    },
    ids::RunId,
    wire::Artifact,
};
use serde_json::{Value, json};
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
    binary: PathBuf,
    evidence: Evidence,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let binary = binary();
        let evidence = Evidence::initialize(
            &binary,
            &root.path().join("evidence"),
            &root.path().join("import"),
        )
        .unwrap();
        Self {
            root,
            binary,
            evidence,
        }
    }

    fn fresh(&self) -> Evidence {
        Evidence::open(
            &self.binary,
            &self.root.path().join("evidence"),
            &self.root.path().join("import"),
        )
        .unwrap()
    }

    fn original(&self, bytes: &[u8]) -> Artifact {
        let capture = self.evidence.capture(&RunId::generate()).unwrap();
        self.evidence.attach(&capture, 1, "flow", bytes).unwrap();
        self.evidence
            .finalize(&capture, Some(1), Completion::Complete, &["flow"])
            .unwrap()
            .original_artifacts
            .remove(0)
            .artifact
    }

    fn native(&self, args: &[&str], payload: Option<Value>) -> Value {
        let mut process = Command::new(&self.binary)
            .env_clear()
            .arg("--workspace")
            .arg(self.root.path().join("evidence"))
            .args([
                "--case",
                self.evidence.case_id(),
                "--format",
                "json",
                "--actor",
                "agent:scourge",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(payload) = payload {
            process
                .stdin
                .take()
                .unwrap()
                .write_all(&serde_json::to_vec(&payload).unwrap())
                .unwrap();
        }
        let output = process.wait_with_output().unwrap();
        let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(output.status.success(), "{reply}");
        reply
    }
}

fn binary() -> PathBuf {
    PathBuf::from(
        std::env::var_os("SCOURGE_INVESTIGATION_BIN")
            .expect("set SCOURGE_INVESTIGATION_BIN to the exact qualified executable"),
    )
}

#[test]
fn refuses_unqualified_executable_before_creating_workspace() {
    let root = tempfile::tempdir().unwrap();
    let wrong = root.path().join("unqualified");
    fs::write(&wrong, "unqualified").unwrap();
    let workspace = root.path().join("evidence");
    let result = Evidence::initialize(&wrong, &workspace, &root.path().join("import"));
    assert!(matches!(
        result,
        Err(EvidenceError::UnqualifiedInvestigation)
    ));
    assert!(!workspace.exists());
}

#[test]
#[ignore = "requires the M0.6 Investigation executable"]
fn capture_read_and_retry_are_bound_to_one_immutable_artifact() {
    let fixture = Fixture::new();
    let evidence = &fixture.evidence;
    let run = RunId::generate();
    let capture = evidence.capture(&run).unwrap();
    let name = "flow";
    let mut bytes = vec![b'z'; 36_000];
    bytes[32_767..32_771].copy_from_slice(&[0xff, 0, b'\r', b'\n']);
    let first = evidence.attach(&capture, 1, name, &bytes).unwrap();
    assert!(matches!(
        evidence.attach(&capture, 1, name, b"other"),
        Err(EvidenceError::Conflict)
    ));
    assert!(matches!(
        evidence.finalize(&capture, Some(1), Completion::Complete, &["other"]),
        Err(EvidenceError::Conflict)
    ));
    let reopened = fixture.fresh();
    assert_eq!(reopened.capture(&run).unwrap(), capture);
    assert_eq!(reopened.attach(&capture, 1, name, &bytes).unwrap(), first);
    assert!(
        reopened
            .recover(&capture.handle)
            .unwrap()
            .finalized
            .is_none()
    );
    let sealed = reopened
        .finalize(&capture, Some(1), Completion::Complete, &[name])
        .unwrap();
    assert_eq!(
        evidence
            .finalize(&capture, Some(1), Completion::Complete, &[name])
            .unwrap(),
        sealed
    );
    assert_eq!(evidence.attach(&capture, 1, name, &bytes).unwrap(), first);
    assert!(matches!(
        evidence.attach(&capture, 2, "late", b"late"),
        Err(EvidenceError::Conflict)
    ));
    let original = &sealed.original_artifacts[0].artifact;
    let read = reopened.read(&original.artifact_id).unwrap();
    assert_eq!(&read.artifact.reference, original);
    assert_eq!(original.digest, Sha256Digest::of(&bytes));
    assert!(read.artifact.lineage.is_empty());
    assert_eq!(read.bytes, bytes);
    assert_eq!(
        reopened
            .read_range(&original.artifact_id, 32_767..32_771)
            .unwrap()
            .bytes,
        [255, 0, 13, 10]
    );
    assert!(matches!(
        reopened.read_range(&original.artifact_id, 0..0),
        Err(EvidenceError::InvalidRange)
    ));
    assert!(matches!(
        reopened.read_range(&original.artifact_id, 0..36_001),
        Err(EvidenceError::InvalidRange)
    ));
    let native = fixture.native(
        &["show", &capture.investigation_run_id, "--depth", "full"],
        None,
    );
    assert_eq!(
        native["record"]["body"]["capture"]["metadata"]["scourge_investigation"],
        serde_json::to_value(evidence.investigation()).unwrap()
    );
}

fn derive<'a>(
    key: &'a str,
    kind: RecordKind,
    bytes: &'a [u8],
    inputs: &'a [Artifact],
) -> RecordRequest<'a> {
    RecordRequest {
        key,
        kind,
        bytes,
        inputs,
        transformation: "scourge-test",
        version: "1",
    }
}

#[test]
#[ignore = "requires the M0.6 Investigation executable"]
fn derivatives_preserve_ordered_lineage_and_strict_structured_input() {
    let fixture = Fixture::new();
    let evidence = &fixture.evidence;
    let original_bytes = b"private\x00\xff\r\n";
    let original = fixture.original(original_bytes);
    let other = fixture.original(b"  { \"control\": true }\r\n");
    let inputs = [original.clone(), other.clone()];
    let redacted = evidence
        .record(derive(
            "redaction",
            RecordKind::Redaction,
            b"[redacted]\r\n",
            &inputs,
        ))
        .unwrap();
    assert_eq!(
        fixture
            .fresh()
            .recover_record("redaction")
            .unwrap()
            .unwrap()
            .reference,
        redacted.reference
    );
    assert!(
        fixture
            .fresh()
            .recover_record("record-shaped-lookalike")
            .unwrap()
            .is_none()
    );
    assert_ne!(redacted.reference, original);
    assert_eq!(
        redacted
            .lineage
            .iter()
            .map(|link| &link.input)
            .collect::<Vec<_>>(),
        vec![&original, &other]
    );
    assert_eq!(redacted.lineage[0].transformation, "scourge-test");
    assert_eq!(redacted.lineage[0].version, "1");
    assert_eq!(
        evidence.read(&original.artifact_id).unwrap().bytes,
        original_bytes
    );
    assert_eq!(
        evidence
            .read(&redacted.reference.artifact_id)
            .unwrap()
            .bytes,
        b"[redacted]\r\n"
    );
    assert_eq!(
        fixture
            .fresh()
            .record(derive(
                "redaction",
                RecordKind::Redaction,
                b"[redacted]\r\n",
                &inputs
            ))
            .unwrap(),
        redacted
    );
    assert!(matches!(
        evidence.record(derive(
            "redaction",
            RecordKind::Redaction,
            b"edited",
            &inputs
        )),
        Err(EvidenceError::Conflict)
    ));
    let structured = b" { \"result\": 0, \"nested\": { \"key\": \"value\" } }\n";
    let invalid: &[&[u8]] = &[
        b"{\"nested\":{\"key\":1,\"key\":2}}",
        b"[] {}",
        b"{\"n\":9007199254740992}",
        b"{\"n\":1e999}",
        b"\xff",
    ];
    for invalid in invalid {
        let raw = fixture.original(invalid);
        assert_eq!(evidence.read(&raw.artifact_id).unwrap().bytes, *invalid);
        assert!(matches!(
            evidence.read_json(&raw.artifact_id),
            Err(EvidenceError::InvalidJson)
        ));
        assert!(matches!(
            evidence.record(derive(
                "structured",
                RecordKind::VerificationRecord,
                invalid,
                &inputs
            )),
            Err(EvidenceError::InvalidJson)
        ));
    }
    let record = evidence
        .record(derive(
            "structured",
            RecordKind::VerificationRecord,
            structured,
            &inputs,
        ))
        .unwrap();
    assert_eq!(
        evidence
            .read_json(&record.reference.artifact_id)
            .unwrap()
            .bytes,
        structured
    );
    assert_eq!(record.reference.digest, Sha256Digest::of(structured));
    assert_eq!(
        evidence.read_json(&other.artifact_id).unwrap().bytes,
        b"  { \"control\": true }\r\n"
    );
    let mut changed = inputs;
    changed[0].digest = Sha256Digest::of(b"different");
    assert!(matches!(
        evidence.record(derive(
            "wrong-digest",
            RecordKind::Experiment,
            structured,
            &changed
        )),
        Err(EvidenceError::Integrity)
    ));
}

#[test]
#[ignore = "requires the M0.6 Investigation executable"]
fn withdrawal_refuses_direct_and_inherited_evidentiary_use() {
    let fixture = Fixture::new();
    let evidence = &fixture.evidence;
    let original = fixture.original(b"capture");
    let other = fixture.original(b"other");
    let redacted = evidence
        .record(derive(
            "derivative",
            RecordKind::Redaction,
            b"derived",
            std::slice::from_ref(&original),
        ))
        .unwrap();
    for (operation, subject, id, scope) in [
        (
            "artifact.withdraw",
            "artifact_ref",
            original.artifact_id.as_str(),
            json!({"extent":"partial","statement":"part of the data"}),
        ),
        (
            "source.withdraw",
            "source_ref",
            evidence
                .describe(&other.artifact_id)
                .unwrap()
                .source_id
                .as_str(),
            json!({"extent":"entire"}),
        ),
    ] {
        fixture.native(
            &["record", "--input", "-"],
            Some(json!({
                "schema_version":"inv.command.v1", "actor":"agent:scourge",
                "case_id":evidence.case_id(), "command_id":operation, "preconditions":[],
                "operations":[{"op":operation, "payload":{
                    (subject):{"id":id,"revision":1}, "scope":scope,
                    "reason":"collection_error", "rationale":"Withdrawal contract fixture",
                    "evidence_refs":[],
                }}],
            })),
        );
    }
    for (artifact, expected) in [
        (&original, Withdrawal::Partial),
        (&redacted.reference, Withdrawal::Partial),
        (&other, Withdrawal::Entire),
    ] {
        assert!(matches!(evidence.read(&artifact.artifact_id),
            Err(EvidenceError::Withdrawn { artifact: id, state }) if id == artifact.artifact_id && state == expected
        ));
        assert!(matches!(
            evidence.record(derive("after-withdrawal", RecordKind::Redaction, b"derived", std::slice::from_ref(artifact))),
            Err(EvidenceError::Withdrawn { state, .. }) if state == expected
        ));
    }
    let native = fixture.native(
        &[
            "evidence",
            "read",
            original.artifact_id.as_str(),
            "--selector-file",
            "-",
        ],
        Some(json!({
            "schema_version":"inv.selector.v1",
            "artifact_digest":format!("sha256:{}", original.digest.as_str()),
            "selector":{"type":"whole"}
        })),
    );
    assert_eq!(native["excerpt"]["text"], "capture");
    assert_eq!(native["evidentiary_use"]["state"], "partially_withdrawn");
}

#[test]
#[ignore = "requires the M0.6 Investigation executable"]
fn withdrawal_beyond_native_lineage_scan_refuses_every_use() {
    let fixture = Fixture::new();
    let evidence = &fixture.evidence;
    let bytes = b"{\"value\":1}\n";
    let original = fixture.original(bytes);
    let digest = format!("sha256:{}", original.digest.as_str());
    fs::write(fixture.root.path().join("import/item"), bytes).unwrap();
    let mut descendant = original.artifact_id.clone();
    // Construct the lineage through the public pinned CLI so the fixture does
    // not depend on the bridge's admission rule or perform repeated full walks.
    for depth in 1..=65 {
        let receipt = fixture.native(
            &["ingest", "--input", "-"],
            Some(json!({
                "schema_version":"inv.ingest.v1", "actor":"agent:scourge",
                "case_id":evidence.case_id(), "command_id":format!("long-chain-{depth}"),
                "source":{"title":"Deep lineage witness","format":"application/json"},
                "paths":["item"], "validate_as":"strict_json",
                "derived_from":{"transformation":"fixture","version":"1","inputs":[
                    {"artifact_ref":{"id":descendant,"revision":1}, "digest":digest},
                ]},
            })),
        );
        descendant = receipt["items"][0]["artifact_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        if depth == 1 {
            assert_eq!(evidence.read_json(&descendant).unwrap().bytes, bytes);
        }
    }
    assert_eq!(evidence.read(&original.artifact_id).unwrap().bytes, bytes);
    assert_eq!(evidence.read(&descendant).unwrap().bytes, bytes);
    assert_eq!(
        evidence.describe(&descendant).unwrap().reference.digest,
        original.digest
    );
    let derivative = Artifact {
        artifact_id: descendant.clone(),
        digest: original.digest,
    };
    for (revision, scope, expected) in [
        (
            1,
            json!({"extent":"partial","statement":"part of the artifact"}),
            Withdrawal::Partial,
        ),
        (2, json!({"extent":"entire"}), Withdrawal::Entire),
    ] {
        fixture.native(
            &["record", "--input", "-"],
            Some(json!({
                "schema_version":"inv.command.v1", "actor":"agent:scourge",
                "case_id":evidence.case_id(), "command_id":format!("deep-withdrawal-{revision}"),
                "preconditions":[], "operations":[{"op":"artifact.withdraw", "payload":{
                    "artifact_ref":{"id":original.artifact_id,"revision":revision}, "scope":scope,
                    "reason":"collection_error", "rationale":"Deep withdrawal contract fixture",
                    "evidence_refs":[],
                }}],
            })),
        );
        let native = fixture.native(&["show", descendant.as_str(), "--depth", "full"], None);
        // The pinned scan visits at most 64 current records, and every level
        // contributes an Artifact and a Source, so the withdrawn ancestor is
        // outside it and the native answer alone is not evidence of use.
        assert_eq!(native["evidentiary_use"]["state"], "in_use");
        assert_eq!(native["evidentiary_use"]["withdrawals"], json!([]));
        assert!(matches!(
            evidence.describe(&descendant),
            Err(EvidenceError::Withdrawn { artifact, state }) if artifact == descendant && state == expected
        ));
        for read in [
            evidence.read(&descendant),
            evidence.read_range(&descendant, 0..1),
            evidence.read_json(&descendant),
        ] {
            assert!(matches!(read,
                Err(EvidenceError::Withdrawn { artifact, state }) if artifact == descendant && state == expected
            ));
        }
        assert!(matches!(
            evidence.read(&original.artifact_id),
            Err(EvidenceError::Withdrawn { artifact, state }) if artifact == original.artifact_id && state == expected
        ));
        assert!(matches!(
            evidence.record(derive("deep-after-withdrawal", RecordKind::Experiment, bytes, std::slice::from_ref(&derivative))),
            Err(EvidenceError::Withdrawn { artifact, state }) if artifact == descendant && state == expected
        ));
    }
}

#[test]
#[ignore = "requires the M0.6 Investigation executable"]
fn killed_producer_recovers_only_acknowledged_prefix() {
    let fixture = Fixture::new();
    let mut producer = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "producer_child", "--ignored", "--nocapture"])
        .env("SCOURGE_EVIDENCE_CHILD_ROOT", fixture.root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = producer.stdout.take().unwrap();
    let handle: CaptureHandle = BufReader::new(stdout)
        .lines()
        .map(|line| line.unwrap())
        .find_map(|line| {
            line.strip_prefix("ready ")
                .map(|handle| handle.parse().unwrap())
        })
        .expect("producer acknowledgement");
    producer.kill().unwrap();
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(producer.wait().unwrap().signal(), Some(9));
    let evidence = fixture.fresh();
    let state = evidence.recover(&handle).unwrap();
    assert_eq!(state.last_position, Some(1));
    assert_eq!(
        state.attachments[0].digest,
        Sha256Digest::of(b"acknowledged")
    );
    assert!(state.finalized.is_none());
    assert!(matches!(
        evidence.finalize(
            &state.capture,
            Some(2),
            Completion::Complete,
            &["first", "missing"]
        ),
        Err(EvidenceError::Conflict)
    ));
    let seal = evidence
        .finalize(
            &state.capture,
            Some(2),
            Completion::Interrupted,
            &["first", "missing"],
        )
        .unwrap();
    assert!(!seal.complete);
    assert_eq!(seal.missing_positions, vec![2]);
    assert_eq!(seal.original_artifacts.len(), 1);
    assert_eq!(
        evidence
            .read(&seal.original_artifacts[0].artifact.artifact_id)
            .unwrap()
            .bytes,
        b"acknowledged"
    );
}

#[test]
#[ignore = "only run as the child of the interrupted capture test"]
fn producer_child() {
    let Some(root) = std::env::var_os("SCOURGE_EVIDENCE_CHILD_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let evidence = Evidence::open(&binary(), &root.join("evidence"), &root.join("import")).unwrap();
    let capture = evidence.capture(&RunId::generate()).unwrap();
    evidence
        .attach(&capture, 1, "first", b"acknowledged")
        .unwrap();
    println!("ready {}", capture.handle.as_str());
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
}
