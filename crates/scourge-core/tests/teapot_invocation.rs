#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use scourge_core::{
    canonical::{self, Sha256Digest},
    engagement::RequiredEnforcement,
    teapot::{
        BoundEngine, EditSurfaceReport, EnforcementStatus, Environment, ExecutableKind,
        GateRefusalReason, InvocationError, RuleStatus, SessionState, Teapot,
        accounting::{
            AccountingBinding, AccountingError, AccountingObservation, AccountingRefusal,
            EvidenceKind, MacroPlan, Phase,
        },
    },
    template::Method,
    wire::{AbsolutePath, Attribution, DiagnosticCode, ErrorCode, Granularity, Unit},
};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn path(path: &Path) -> AbsolutePath {
    path.to_str().unwrap().parse().unwrap()
}

fn environment(root: &Path) -> Environment {
    let runtime = root.join("r");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    Environment {
        home: path(root),
        config_home: None,
        data_home: None,
        state_home: None,
        cache_home: None,
        runtime_dir: Some(path(&runtime)),
    }
}

fn example_engine() -> BoundEngine {
    BoundEngine {
        instance: "example-instance".parse().unwrap(),
        project_id: "example-project".parse().unwrap(),
        enforced: false,
        policy_locked: false,
    }
}

fn check_diagnostic(
    error: &InvocationError,
    code: DiagnosticCode,
    native: Option<i64>,
    wrapper: Option<i64>,
) {
    assert_eq!(error.code(), ErrorCode::DependencyUnavailable);
    assert_eq!(error.code().exit_code(), 7);
    let diagnostic = error.diagnostic().unwrap();
    assert_eq!(diagnostic.code, code);
    assert_eq!(diagnostic.native_exit, native);
    assert_eq!(diagnostic.wrapper_exit, wrapper);
}

fn bound_wrapper(root: &Path, contents: &str) -> Teapot {
    let program = root.join("operator wrapper");
    let project = root.join("test project");
    fs::create_dir(&project).unwrap();
    fs::write(root.join(".scourge-test-script"), format!("{contents}\n")).unwrap();
    let launcher =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-script-launcher.sh");
    symlink(launcher, &program).unwrap();
    Teapot::new(
        path(&program),
        ExecutableKind::Wrapper,
        path(&project),
        environment(root),
        example_engine(),
    )
}

#[test]
fn missing_absolute_executable_is_typed_without_a_native_exit() {
    let root = tempfile::tempdir().unwrap();
    let teapot = Teapot::new(
        path(&root.path().join("not present")),
        ExecutableKind::Native,
        path(root.path()),
        environment(root.path()),
        example_engine(),
    );
    check_diagnostic(
        &teapot.describe().unwrap_err(),
        DiagnosticCode::ToolUnavailable,
        None,
        None,
    );
}

#[test]
fn a_wrapper_cannot_mask_native_wrong_listener() {
    let root = tempfile::tempdir().unwrap();
    let teapot = bound_wrapper(
        root.path(),
        r#"printf '%s\n' '{"error":{"code":2,"reason":"wrong-engine","message":"untrusted detail"},"advice":[]}' >&2
exit 0"#,
    );
    let failure = teapot.describe().unwrap_err();
    check_diagnostic(&failure, DiagnosticCode::WrongListener, Some(2), Some(0));
    let InvocationError::DependencyUnavailable { native_reason, .. } = failure else {
        panic!("expected dependency failure");
    };
    assert_eq!(native_reason.unwrap().as_str(), "wrong-engine");
}

#[test]
fn wrapper_only_failure_retains_wrapper_exit() {
    let root = tempfile::tempdir().unwrap();
    let teapot = bound_wrapper(
        root.path(),
        r#"printf '%s\n' '{"schema":"scourge.diagnostic.v1","workspace":null,"engagement":null,"request_key":null,"run_id":null,"diagnostic":{"code":"TOOL_UNAVAILABLE","stage":"describe","message":"native executable missing","native_exit":null,"wrapper_exit":0}}' >&2
exit 0"#,
    );
    check_diagnostic(
        &teapot.describe().unwrap_err(),
        DiagnosticCode::ToolUnavailable,
        None,
        Some(0),
    );
}

#[test]
fn bound_argv_preserves_spaces_and_output_must_be_one_strict_envelope() {
    let root = tempfile::tempdir().unwrap();
    let version = bound_version(root.path());
    let version = &version["version"];
    let teapot = bound_wrapper(
        root.path(),
        &format!(
            r#"printf '%s\n' "$@" > "$HOME/received"
[ -z "$HTTP_PROXY$RUST_LOG$CARGO_HOME$CARGO_MANIFEST_DIR$LD_PRELOAD" ] || exit 30
/bin/cat <<'REPLY'
{{"advice":[],"version":{version},"advice":[]}}
REPLY"#
        ),
    );
    let expected = vec![
        teapot.version_argv()[0].clone(),
        "--project".to_owned(),
        root.path().join("test project").display().to_string(),
        "--json".to_owned(),
        "version".to_owned(),
    ];
    assert_eq!(teapot.version_argv(), expected);
    check_diagnostic(
        &teapot.describe().unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        None,
        Some(0),
    );
    let received = fs::read_to_string(root.path().join("received")).unwrap();
    assert_eq!(received.lines().collect::<Vec<_>>(), expected[1..]);
}

fn bound_version(root: &Path) -> Value {
    let captured: Value =
        serde_json::from_str(include_str!("../../../fixtures/contracts/describe.json")).unwrap();
    let mut output = captured["output"].clone();
    let engine = &mut output["version"]["engine"];
    engine["instance"] = json!("example-instance");
    engine["project_id"] = json!("example-project");
    engine["project"] = json!(root.join("test project"));
    output
}

#[test]
fn jobs_rejects_oversized_pages_duplicate_ids_and_nonexclusive_cursors() {
    let root = tempfile::tempdir().unwrap();
    let teapot = bound_wrapper(
        root.path(),
        r#"case "$4" in
version) exec /bin/cat "$HOME/version.json" ;;
jobs) exec /bin/cat "$HOME/jobs.json" ;;
*) exit 22 ;;
esac"#,
    );
    fs::write(
        root.path().join("version.json"),
        bound_version(root.path()).to_string(),
    )
    .unwrap();
    let capture: Value =
        serde_json::from_str(include_str!("../../../fixtures/contracts/list-jobs.json")).unwrap();
    let output = capture["output"].clone();
    let write_jobs = |job_ids: &[u64]| {
        let jobs: Vec<_> = job_ids
            .iter()
            .map(|id| {
                let mut job = output["jobs"][0].clone();
                job["id"] = json!(id);
                job
            })
            .collect();
        fs::write(
            root.path().join("jobs.json"),
            json!({"advice": [], "jobs": jobs}).to_string(),
        )
        .unwrap();
    };

    write_jobs(&[8, 7]);
    let accepted = teapot.list_jobs(2, Some(9)).unwrap();
    assert_eq!(
        accepted.value.iter().map(|job| job.id).collect::<Vec<_>>(),
        [8, 7]
    );

    for (ids, limit, before) in [
        ([8, 7], 1, None),
        ([8, 8], 2, None),
        ([8, 7], 2, Some(8)),
        ([9, 7], 2, Some(8)),
    ] {
        write_jobs(&ids);
        check_diagnostic(
            &teapot.list_jobs(limit, before).unwrap_err(),
            DiagnosticCode::InvalidNativeOutput,
            Some(0),
            Some(0),
        );
    }
}

#[test]
fn invalid_positional_arguments_never_invoke_the_executable() {
    let root = tempfile::tempdir().unwrap();
    let teapot = bound_wrapper(root.path(), r#"printf seen > "$HOME/received""#);
    let error = teapot
        .dry_run_macro(&"--dry-run".parse().unwrap(), &"alice".parse().unwrap())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::UsageError);
    assert!(!root.path().join("received").exists());
}

fn accounting_binding(pass_file: &Path, digest: Sha256Digest) -> AccountingBinding {
    AccountingBinding {
        run_id: "R-accounting".parse().unwrap(),
        request_key: "rk_accounting".parse().unwrap(),
        pass_id: "accounting-test".parse().unwrap(),
        pass_digest: digest,
        pass_file: path(pass_file),
    }
}

fn write_json(root: &Path, name: &str, value: &Value) {
    fs::write(root.join(name), format!("{value}\n")).unwrap();
}

struct AccountingWrapper {
    root: tempfile::TempDir,
    teapot: Teapot,
    binding: AccountingBinding,
    job_started: String,
}

impl AccountingWrapper {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let teapot = bound_wrapper(
            root.path(),
            r#"case "$4" in
version) exec /bin/cat "$HOME/version.json" ;;
pass)
    if [ -f "$HOME/replacement.json" ]; then
        /bin/mv "$HOME/replacement.json" "$HOME/version.json"
    fi
    exec /bin/cat "$HOME/pass.json"
    ;;
macros) [ "$9" = "--dry-run" ] || exit 23
    exec /bin/cat "$HOME/plan.json" ;;
jobs)
    if [ -f "$HOME/jobs-error.json" ]; then
        /bin/cat "$HOME/jobs-error.json" >&2
        exit 0
    fi
    exec /bin/cat "$HOME/jobs.json"
    ;;
*) exit 24 ;;
esac"#,
        );
        let binding = accounting_binding(
            &root.path().join("approved pass.toml"),
            Sha256Digest::of(b"approved test fixture"),
        );
        let mut version = bound_version(root.path());
        version["version"]["engine"]["pass"] = json!(binding.pass_file.as_str());
        write_json(root.path(), "version.json", &version);
        Self {
            root,
            teapot,
            binding,
            job_started: OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
        }
    }

    fn pass(&self, ceiling: Option<Value>) -> Value {
        let capture: Value =
            serde_json::from_str(include_str!("../../../fixtures/contracts/units-left.json"))
                .unwrap();
        let mut output = capture["output"].clone();
        let pass = &mut output["pass"];
        pass["id"] = json!(self.binding.pass_id);
        pass["digest"] = json!(format!("sha256:{}", self.binding.pass_digest.as_str()));
        pass["pass_file"] = json!(self.binding.pass_file);
        pass["state"] = json!("bound");
        pass["window"] = json!("valid");
        let ceilings: Vec<_> = ceiling.into_iter().collect();
        pass["ceilings"] = json!(ceilings);
        write_json(self.root.path(), "pass.json", &output);
        output
    }

    fn plan(&self, request_count: u64, left: Option<u64>) {
        let capture: Value =
            serde_json::from_str(include_str!("../../../fixtures/contracts/dry-run.json")).unwrap();
        let mut output = capture["output"].clone();
        output["run"]["name"] = json!("two");
        output["run"]["units"] = json!(request_count);
        output["run"]["units_left"] = json!(left);
        write_json(self.root.path(), "plan.json", &output);
    }

    fn jobs(&self, ids: &[u64]) {
        let capture: Value =
            serde_json::from_str(include_str!("../../../fixtures/contracts/list-jobs.json"))
                .unwrap();
        let jobs: Vec<_> = ids
            .iter()
            .map(|&id| {
                let mut job = capture["output"]["jobs"][0].clone();
                job["id"] = json!(id);
                job["live"] = json!(true);
                job["state"] = json!("running");
                job["started"] = json!(self.job_started);
                job["ended"] = Value::Null;
                job
            })
            .collect();
        write_json(
            self.root.path(),
            "jobs.json",
            &json!({"advice": [], "jobs": jobs}),
        );
    }
}

fn ceiling(total: u64, spent: Option<u64>, left: Option<u64>) -> Value {
    json!({"counter": "requests", "total": total, "spent": spent, "left": left, "unused": 0})
}

fn pass_spent(observation: &AccountingObservation) -> (Option<u64>, Option<u64>) {
    let record = observation.record();
    let spent = |sample: Option<&scourge_core::wire::Counters>| {
        sample
            .and_then(|sample| sample.spent.as_ref())
            .map(|count| count.value)
    };
    (
        spent(record.counters_before.as_ref()),
        spent(record.counters_after.as_ref()),
    )
}

fn assert_unknown_charge(observation: &AccountingObservation) {
    let record = observation.record();
    assert!(record.ledger_debits.is_empty());
    assert!(record.charged.is_none());
    assert!(record.admitted.is_none());
    assert!(record.observed_sent.is_none());
    assert!(record.instrument_job_ids.is_empty());
    assert_eq!(record.attribution, Attribution::Unestablished);
}

#[test]
fn accounting_keeps_plan_and_counter_provenance_without_attributing_jobs_or_blocks() {
    let wrapper = AccountingWrapper::new();
    // The same pass-wide delta could come from two jobs sharing one reserved
    // block, or include a spender invisible to this project. A local job page
    // and a coincident delta cannot distinguish those possibilities.
    for jobs in [&[7][..], &[9, 8, 7][..], &[7][..]] {
        wrapper.jobs(&[7]);
        wrapper.pass(Some(ceiling(100, Some(1), Some(99))));
        wrapper.plan(2, Some(98));
        let capture = wrapper
            .teapot
            .begin_accounting(
                wrapper.binding.clone(),
                Some(MacroPlan {
                    name: &"two".parse().unwrap(),
                    session: &"alice".parse().unwrap(),
                }),
            )
            .unwrap();
        assert_eq!(capture.preflight(false), Ok(()));
        assert_eq!(
            capture.preflight(true).unwrap_err().code(),
            ErrorCode::AccountingUnestablished
        );
        wrapper.jobs(jobs);
        wrapper.pass(Some(ceiling(100, Some(11), Some(89))));
        let observation = capture.finish().unwrap();
        assert_unknown_charge(&observation);
        assert_eq!(pass_spent(&observation), (Some(1), Some(11)));
        let record = observation.record();
        let requested = record.requested.as_ref().unwrap();
        assert_eq!(requested.value, 2);
        assert_eq!(requested.unit, Unit::Requests);
        assert_eq!(requested.granularity, Granularity::RunSummary);
        assert_eq!(record.dry_run_ceiling.as_ref().unwrap().value, 98);
        assert_eq!(observation.within_ceiling(), Some(true));
        let evidence = observation.evidence();
        assert_eq!(evidence.binding().run_id, wrapper.binding.run_id);
        assert_eq!(evidence.binding().request_key, wrapper.binding.request_key);
        assert_eq!(evidence.binding().pass_digest, wrapper.binding.pass_digest);
        assert_eq!(evidence.engine().instance, example_engine().instance);
        assert_eq!(evidence.engine().project_id, example_engine().project_id);
        assert_eq!(
            evidence.project(),
            &path(&wrapper.root.path().join("test project"))
        );
        let to_time = |value: &scourge_core::wire::Timestamp| {
            OffsetDateTime::parse(value.as_str(), &Rfc3339).unwrap()
        };
        let mut last = to_time(&record.window.start);
        for (artifact, reference) in evidence
            .artifacts()
            .iter()
            .zip(&record.attribution_evidence)
        {
            assert_eq!(artifact.reference(), reference);
            assert_eq!(Sha256Digest::of(artifact.stdout()), reference.digest);
            assert_eq!(artifact.exits().native, Some(0));
            assert_eq!(artifact.exits().wrapper, Some(0));
            assert!(to_time(&artifact.window().start) >= last);
            assert!(to_time(&artifact.window().end) >= to_time(&artifact.window().start));
            last = to_time(&artifact.window().end);
        }
        assert_eq!(last, to_time(&record.window.end));
        let job_page = evidence
            .artifacts()
            .iter()
            .find(|artifact| {
                artifact.kind() == EvidenceKind::Jobs && artifact.phase() == Phase::After
            })
            .unwrap();
        let original: Value = serde_json::from_slice(job_page.stdout()).unwrap();
        let original_ids: Vec<_> = original["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_u64().unwrap())
            .collect();
        assert_eq!(original_ids, jobs);
        assert!(canonical::to_vec(record).is_ok());
    }
}

#[test]
fn accounting_preserves_absent_and_null_counters_and_requires_known_capacity() {
    let wrapper = AccountingWrapper::new();
    wrapper.jobs(&[]);
    for (pass, plan_left, expected_left, expected_spent, expected) in [
        (
            None,
            None,
            None,
            None,
            Err(AccountingRefusal::CeilingUnknown),
        ),
        (
            Some(ceiling(10, None, None)),
            None,
            None,
            None,
            Err(AccountingRefusal::CeilingUnknown),
        ),
        (
            Some(ceiling(10, None, Some(7))),
            Some(7),
            Some(7),
            None,
            Err(AccountingRefusal::CeilingUnknown),
        ),
        (
            Some(ceiling(10, Some(0), Some(10))),
            None,
            Some(10),
            Some(0),
            Err(AccountingRefusal::CeilingUnknown),
        ),
        (
            Some(ceiling(10, Some(8), Some(2))),
            Some(2),
            Some(2),
            Some(8),
            Ok(()),
        ),
        (
            Some(ceiling(10, Some(10), Some(0))),
            Some(0),
            Some(0),
            Some(10),
            Err(AccountingRefusal::CeilingExceeded),
        ),
    ] {
        wrapper.pass(pass.clone());
        wrapper.plan(2, plan_left);
        let capture = wrapper
            .teapot
            .begin_accounting(
                wrapper.binding.clone(),
                Some(MacroPlan {
                    name: &"two".parse().unwrap(),
                    session: &"alice".parse().unwrap(),
                }),
            )
            .unwrap();
        assert_eq!(capture.preflight(false), expected);
        let observation = capture.finish().unwrap();
        assert_unknown_charge(&observation);
        let record = observation.record();
        assert_eq!(record.counters_before.is_some(), pass.is_some());
        assert_eq!(record.counters_after.is_some(), pass.is_some());
        assert_eq!(pass_spent(&observation), (expected_spent, expected_spent));
        assert_eq!(
            record
                .counters_before
                .as_ref()
                .and_then(|row| row.left.as_ref())
                .map(|count| count.value),
            expected_left
        );
        assert_eq!(
            record.dry_run_ceiling.as_ref().map(|count| count.value),
            plan_left
        );
        assert_eq!(
            observation.within_ceiling(),
            plan_left.map(|left| 2 <= left)
        );
    }
}

#[test]
fn accounting_preserves_each_counter_endpoint_independently() {
    let wrapper = AccountingWrapper::new();
    for known_phase in [Phase::Before, Phase::After] {
        let write_pass = |phase| {
            if phase == known_phase {
                wrapper.pass(Some(ceiling(100, Some(12), Some(88))))
            } else {
                wrapper.pass(None)
            }
        };
        wrapper.jobs(&[7]);
        write_pass(Phase::Before);
        let capture = wrapper
            .teapot
            .begin_accounting(wrapper.binding.clone(), None)
            .unwrap();
        assert_eq!(
            capture.preflight(true),
            Err(AccountingRefusal::ExactAttributionUnavailable)
        );
        wrapper.jobs(&[8, 7]);
        write_pass(Phase::After);
        let observation = capture.finish().unwrap();
        assert_unknown_charge(&observation);
        let record = observation.record();
        let serialized: Value = canonical::from_slice(&canonical::to_vec(record).unwrap()).unwrap();
        for (phase, field, counters) in [
            (Phase::Before, "counters_before", &record.counters_before),
            (Phase::After, "counters_after", &record.counters_after),
        ] {
            let original = observation
                .evidence()
                .artifacts()
                .iter()
                .find(|artifact| artifact.kind() == EvidenceKind::Pass && artifact.phase() == phase)
                .unwrap();
            let native: Value = serde_json::from_slice(original.stdout()).unwrap();
            assert!(record.attribution_evidence.contains(original.reference()));
            if phase == known_phase {
                let counters = counters.as_ref().unwrap();
                for (key, observed) in [
                    ("spent", &counters.spent),
                    ("left", &counters.left),
                    ("unused", &counters.unused),
                ] {
                    let count = observed.as_ref().unwrap();
                    assert_eq!(
                        native["pass"]["ceilings"][0][key].as_u64(),
                        Some(count.value)
                    );
                    assert_eq!(count.unit, Unit::RequestUnits);
                    assert_eq!(count.granularity, Granularity::Pass);
                    assert_eq!(
                        count.source.as_str(),
                        format!("teapot.pass_show.requests.{key}")
                    );
                    assert_eq!(&count.evidence, original.reference());
                    assert_eq!(&count.window, original.window());
                }
            } else {
                assert!(counters.is_none());
                assert_eq!(serialized[field], Value::Null);
                assert_eq!(native["pass"]["ceilings"], json!([]));
            }
        }
    }
}

#[test]
fn accounting_rejects_malformed_or_mismatched_endpoints_and_ignores_other_granularities() {
    let wrapper = AccountingWrapper::new();
    wrapper.jobs(&[]);
    let mut other_counter = ceiling(100, Some(99), Some(1));
    other_counter["counter"] = json!("bytes");
    other_counter["unit"] = json!("requests");
    other_counter["source"] = json!("teapot.pass_show.requests.spent");
    other_counter["granularity"] = json!("run");
    wrapper.pass(Some(other_counter));
    let capture = wrapper
        .teapot
        .begin_accounting(wrapper.binding.clone(), None)
        .unwrap();
    wrapper.pass(Some(ceiling(100, Some(1), Some(99))));
    let observation = capture.finish().unwrap();
    assert_eq!(pass_spent(&observation), (None, Some(1)));
    assert_unknown_charge(&observation);

    let known = ceiling(100, Some(1), Some(99));
    wrapper.pass(Some(known.clone()));
    let capture = wrapper
        .teapot
        .begin_accounting(wrapper.binding.clone(), None)
        .unwrap();
    let mut wrong_pass = wrapper.pass(None);
    wrong_pass["pass"]["pass_file"] = json!("/wrong/approved.pass.toml");
    write_json(wrapper.root.path(), "pass.json", &wrong_pass);
    assert!(matches!(
        capture.finish().unwrap_err().error(),
        AccountingError::Refusal(AccountingRefusal::PassMismatch)
    ));

    let mut nonnumeric = known.clone();
    nonnumeric["spent"] = json!("1");
    for ceilings in [json!([nonnumeric]), json!([known, known])] {
        wrapper.pass(None);
        let capture = wrapper
            .teapot
            .begin_accounting(wrapper.binding.clone(), None)
            .unwrap();
        let mut invalid = wrapper.pass(None);
        invalid["pass"]["ceilings"] = ceilings;
        write_json(wrapper.root.path(), "pass.json", &invalid);
        let failure = capture.finish().unwrap_err();
        let AccountingError::Invocation(error) = failure.error() else {
            panic!("expected an invalid native counter");
        };
        assert_eq!(
            error.diagnostic().unwrap().code,
            DiagnosticCode::InvalidNativeOutput
        );
        assert_eq!(error.diagnostic().unwrap().wrapper_exit, Some(0));
    }
}

#[test]
fn accounting_refuses_counter_resets_mismatches_and_values_that_cannot_be_published() {
    let wrapper = AccountingWrapper::new();
    wrapper.jobs(&[]);
    for (before, after) in [
        (
            ceiling(100, Some(10), Some(90)),
            ceiling(100, Some(9), Some(90)),
        ),
        (
            ceiling(100, Some(10), Some(90)),
            ceiling(100, Some(10), Some(91)),
        ),
        (
            ceiling(100, Some(10), Some(90)),
            ceiling(101, Some(10), Some(90)),
        ),
    ] {
        wrapper.pass(Some(before));
        let capture = wrapper
            .teapot
            .begin_accounting(wrapper.binding.clone(), None)
            .unwrap();
        wrapper.pass(Some(after));
        let failure = capture.finish().unwrap_err();
        assert!(matches!(
            failure.error(),
            AccountingError::Refusal(AccountingRefusal::CounterDiscontinuity)
        ));
        assert!(
            failure
                .evidence()
                .artifacts()
                .iter()
                .any(|artifact| artifact.phase() == Phase::After
                    && artifact.kind() == EvidenceKind::Pass)
        );
    }
    let mut pass = wrapper.pass(Some(ceiling(100, Some(0), Some(100))));
    pass["pass"]["digest"] = json!(format!(
        "sha256:{}",
        Sha256Digest::of(b"different approval").as_str()
    ));
    write_json(wrapper.root.path(), "pass.json", &pass);
    let failure = wrapper
        .teapot
        .begin_accounting(wrapper.binding.clone(), None)
        .unwrap_err();
    assert!(matches!(
        failure.error(),
        AccountingError::Refusal(AccountingRefusal::PassMismatch)
    ));
    assert!(
        failure
            .evidence()
            .artifacts()
            .iter()
            .any(|artifact| artifact.kind() == EvidenceKind::Pass)
    );

    for value in [1 << 53, u64::MAX] {
        wrapper.pass(Some(ceiling(u64::MAX, Some(value), Some(0))));
        let failure = wrapper
            .teapot
            .begin_accounting(wrapper.binding.clone(), None)
            .unwrap_err();
        assert!(matches!(
            failure.error(),
            AccountingError::Refusal(AccountingRefusal::CountOutOfRange)
        ));
        let pass = failure
            .evidence()
            .artifacts()
            .iter()
            .find(|artifact| artifact.kind() == EvidenceKind::Pass)
            .unwrap();
        let original: Value = serde_json::from_slice(pass.stdout()).unwrap();
        assert_eq!(
            original["pass"]["ceilings"][0]["spent"].as_u64(),
            Some(value)
        );
    }

    let pass = wrapper.pass(Some(ceiling(u64::MAX, Some(u64::MAX), Some(0))));
    fs::write(
        wrapper.root.path().join("pass.json"),
        pass.to_string()
            .replace("18446744073709551615", "18446744073709551616"),
    )
    .unwrap();
    let failure = wrapper
        .teapot
        .begin_accounting(wrapper.binding.clone(), None)
        .unwrap_err();
    let AccountingError::Invocation(error) = failure.error() else {
        panic!("expected a malformed native result");
    };
    check_diagnostic(error, DiagnosticCode::InvalidNativeOutput, None, Some(0));
}

#[test]
fn accounting_refuses_instance_change_after_a_read_and_preserves_prior_evidence() {
    let wrapper = AccountingWrapper::new();
    wrapper.jobs(&[]);
    wrapper.pass(Some(ceiling(100, Some(10), Some(90))));
    let capture = wrapper
        .teapot
        .begin_accounting(wrapper.binding.clone(), None)
        .unwrap();
    let mut changed: Value =
        serde_json::from_slice(&fs::read(wrapper.root.path().join("version.json")).unwrap())
            .unwrap();
    changed["version"]["engine"]["instance"] = json!("replacement");
    write_json(wrapper.root.path(), "replacement.json", &changed);
    let failure = capture.finish().unwrap_err();
    let AccountingError::Invocation(error) = failure.error() else {
        panic!("expected a wrong listener");
    };
    check_diagnostic(error, DiagnosticCode::WrongListener, Some(0), Some(0));
    assert!(
        failure
            .evidence()
            .artifacts()
            .iter()
            .any(|artifact| artifact.kind() == EvidenceKind::Pass
                && artifact.phase() == Phase::After)
    );
    assert_eq!(
        failure.evidence().engine().instance,
        example_engine().instance
    );
}

#[test]
fn accounting_keeps_wrapper_and_native_failure_diagnostics_and_before_artifacts() {
    let wrapper = AccountingWrapper::new();
    wrapper.jobs(&[]);
    wrapper.pass(Some(ceiling(100, Some(0), Some(100))));
    let capture = wrapper
        .teapot
        .begin_accounting(wrapper.binding.clone(), None)
        .unwrap();
    write_json(
        wrapper.root.path(),
        "jobs-error.json",
        &json!({
            "error": {"code": 4, "reason": "engine-stopping", "message": "untrusted detail"}, "advice": []
        }),
    );
    let failure = capture.finish().unwrap_err();
    let AccountingError::Invocation(error) = failure.error() else {
        panic!("expected native failure");
    };
    check_diagnostic(
        error,
        DiagnosticCode::TransportUnavailable,
        Some(4),
        Some(0),
    );
    let InvocationError::DependencyUnavailable { native_reason, .. } = error else {
        panic!("expected dependency failure");
    };
    assert_eq!(native_reason.as_ref().unwrap().as_str(), "engine-stopping");
    assert!(
        failure
            .evidence()
            .artifacts()
            .iter()
            .any(|artifact| artifact.kind() == EvidenceKind::Jobs
                && artifact.phase() == Phase::Before)
    );
}

struct TestProject {
    binary: PathBuf,
    project: PathBuf,
    environment: Environment,
    root: Option<tempfile::TempDir>,
    start_attempted: bool,
}

impl TestProject {
    fn start(&mut self, flags: &[&str]) -> BoundEngine {
        self.start_attempted = true;
        let mut words = vec!["proxy", "start", "--listen", "127.0.0.1:0", "--detach"];
        words.extend_from_slice(flags);
        let started = self.run(&words);
        let engine = &started["proxy"]["engine"];
        BoundEngine {
            instance: engine["instance"].as_str().unwrap().parse().unwrap(),
            project_id: engine["project_id"].as_str().unwrap().parse().unwrap(),
            enforced: engine["enforced"].as_bool().unwrap(),
            policy_locked: engine["policy_locked"].as_bool().unwrap(),
        }
    }

    fn command(&self, words: &[&str]) -> std::io::Result<Output> {
        self.prepare_command(words).output()
    }

    fn prepare_command(&self, words: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .env("HOME", self.environment.home.as_str())
            .env(
                "XDG_RUNTIME_DIR",
                self.environment.runtime_dir.as_ref().unwrap().as_str(),
            )
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .arg("--project")
            .arg(&self.project)
            .arg("--json")
            .args(words)
            .stdin(Stdio::null());
        command
    }

    fn run(&self, words: &[&str]) -> Value {
        let output = self.command(words).unwrap();
        assert!(
            output.status.success(),
            "{words:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn bind(&self, engine: BoundEngine) -> Teapot {
        Teapot::new(
            path(&self.binary),
            ExecutableKind::Native,
            path(&self.project),
            self.environment.clone(),
            engine,
        )
    }

    fn stop(&mut self) -> bool {
        let _ = self.command(&["proxy", "stop"]);
        let stopped = self
            .command(&["proxy", "status"])
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| serde_json::from_slice::<Value>(&output.stdout).ok())
            .is_some_and(|value| value["proxy"]["running"] == false);
        self.start_attempted = !stopped;
        stopped
    }
}

impl Drop for TestProject {
    fn drop(&mut self) {
        if self.start_attempted
            && !self.stop()
            && let Some(root) = self.root.take()
        {
            eprintln!(
                "Could not verify fixture teardown. Retained {}",
                root.keep().display()
            );
        }
    }
}

struct Fixture {
    url: String,
    port: u16,
    request_headers: Arc<Mutex<Vec<Vec<String>>>>,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/probe");
        let request_headers = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = Arc::clone(&stop);
        let server_headers = Arc::clone(&request_headers);
        let task = thread::spawn(move || {
            while !stop_server.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut lines = BufReader::new((&stream).take(16_384)).lines();
                        if let Some(request) = lines.next() {
                            assert!(request.unwrap().starts_with("GET /probe "));
                            let mut names = Vec::new();
                            for line in lines {
                                let line = line.unwrap();
                                if line.is_empty() {
                                    break;
                                }
                                let (name, _) = line.split_once(':').unwrap();
                                names.push(name.to_ascii_lowercase());
                            }
                            server_headers.lock().unwrap().push(names);
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("loopback fixture failed: {error}"),
                }
            }
        });
        Self {
            url,
            port: address.port(),
            request_headers,
            stop,
            task: Some(task),
        }
    }

    fn requests(&self) -> usize {
        self.request_headers.lock().unwrap().len()
    }

    fn assert_credential_free_session_probes(&self) {
        let requests = self.request_headers.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for headers in requests.iter() {
            for name in [
                "authorization",
                "proxy-authorization",
                "cookie",
                "x-api-key",
            ] {
                assert!(
                    !headers.iter().any(|header| header == name),
                    "unexpected {name} header"
                );
            }
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let result = self.task.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

fn pinned_project() -> TestProject {
    let binary = fs::canonicalize(
        std::env::var_os("SCOURGE_PINNED_TEAPOT")
            .expect("set SCOURGE_PINNED_TEAPOT to the frozen executable"),
    )
    .unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../fixtures/contracts/manifest.json")).unwrap();
    assert_eq!(
        Sha256Digest::of(&fs::read(&binary).unwrap()).as_str(),
        manifest["binary_sha256"].as_str().unwrap()
    );

    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("owned test project");
    fs::create_dir(&directory).unwrap();
    // Keep the argument path canonical while the XDG runtime path uses
    // the shorter TMPDIR spelling to fit Unix socket addresses.
    let project = TestProject {
        binary,
        project: fs::canonicalize(directory).unwrap(),
        environment: environment(root.path()),
        root: Some(root),
        start_attempted: false,
    };
    project.run(&["projects", "init"]);
    project
}

#[test]
#[ignore = "requires SCOURGE_PINNED_TEAPOT and a disposable loopback listener"]
fn pinned_teapot_exercises_each_operation() {
    let mut project = pinned_project();
    project.start_attempted = true;
    let started = project.run(&["proxy", "start", "--listen", "127.0.0.1:0", "--detach"]);
    let engine = &started["proxy"]["engine"];
    let bound = BoundEngine {
        instance: engine["instance"].as_str().unwrap().parse().unwrap(),
        project_id: engine["project_id"].as_str().unwrap().parse().unwrap(),
        enforced: false,
        policy_locked: false,
    };
    let teapot = project.bind(bound.clone());
    let fixture = Fixture::start();
    project.run(&["scope", "add", "127.0.0.1"]);
    project.run(&["sessions", "create", "alice"]);
    fs::write(
        project.project.join(".teapot/macros/probe.toml"),
        format!(
            "format = 1\n\n[[steps]]\nstate_changing = false\n[steps.request]\nmethod = \"GET\"\nurl = {:?}\n",
            fixture.url,
        ),
    )
    .unwrap();

    let description = teapot.describe().unwrap();
    assert_eq!(description.version.result()["protocol"], 1);
    assert_eq!(description.version.result()["answered_by"], "engine");
    assert_eq!(description.status.result()["running"], true);
    assert_eq!(description.version.result()["engine"]["enforced"], false);
    assert_eq!(
        description.version.result()["engine"]["policy_locked"],
        false
    );
    assert!(description.status.result()["health"].is_object());

    let session = "alice".parse().unwrap();
    let url = fixture.url.parse().unwrap();
    let direct = teapot.dry_run_request(Method::Get, &url, &session).unwrap();
    assert_eq!(direct.value.request_count, 1);
    assert_eq!(direct.value.within_ceiling, None);
    assert_eq!(direct.value.scope_would_refuse, Some(false));

    let planned = teapot
        .dry_run_macro(&"probe".parse().unwrap(), &session)
        .unwrap();
    assert_eq!(planned.value.request_count, 1);
    assert_eq!(planned.value.within_ceiling, None);
    assert_eq!(planned.evidence.result()["steps"][0]["flow"], Value::Null);

    let units = teapot.units_left().unwrap();
    assert_eq!(units.value, None);
    assert_eq!(units.evidence.result()["state"], "unbound");
    let jobs = teapot.list_jobs(5, Some(9)).unwrap();
    assert!(jobs.value.is_empty());
    assert_eq!(jobs.evidence.result(), &json!([]));
    assert_eq!(fixture.requests(), 0);

    let wrong_instance = project.bind(BoundEngine {
        instance: "wrong-instance".parse().unwrap(),
        ..bound.clone()
    });
    check_diagnostic(
        &wrong_instance.describe().unwrap_err(),
        DiagnosticCode::WrongListener,
        Some(0),
        None,
    );
    check_diagnostic(
        &wrong_instance.check_session(&session, &url).unwrap_err(),
        DiagnosticCode::WrongListener,
        Some(0),
        None,
    );
    let wrong_enforcement = project.bind(BoundEngine {
        enforced: true,
        ..bound
    });
    check_diagnostic(
        &wrong_enforcement.describe().unwrap_err(),
        DiagnosticCode::NativeFailure,
        Some(0),
        None,
    );
    assert_eq!(fixture.requests(), 0);

    let check = teapot.check_session(&session, &url).unwrap();
    assert_eq!(check.value, SessionState::Unknown);
    assert_eq!(check.evidence.result()["reason"], "no-rule");
    assert_eq!(check.evidence.result()["units"], 2);
    fixture.assert_credential_free_session_probes();

    assert!(project.stop());
    check_diagnostic(
        &teapot.describe().unwrap_err(),
        DiagnosticCode::TransportUnavailable,
        Some(0),
        None,
    );
}

#[test]
#[ignore = "requires SCOURGE_PINNED_TEAPOT and a disposable loopback listener"]
fn pinned_accounting_reads_leave_target_jobs_flows_and_existing_ledger_unchanged() {
    let mut project = pinned_project();
    let fixture = Fixture::start();
    let pass = project
        .root
        .as_ref()
        .unwrap()
        .path()
        .join("accounting.pass.toml");
    let pass_path = pass.to_str().unwrap();
    let now = OffsetDateTime::now_utc();
    let yesterday = (now - time::Duration::days(1)).format(&Rfc3339).unwrap();
    let tomorrow = (now + time::Duration::days(1)).format(&Rfc3339).unwrap();
    let pass_bytes = format!(
        r#"format = 1
id = "accounting-test"
name = "Disposable accounting test"
[approval]
owner = "local fixture"
reference = "bn-14o"
operator = "local fixture"
valid_from = {yesterday}
valid_until = {tomorrow}
revoked = false
[[destination]]
label = "local"
address = "127.0.0.1"
protocol = "tcp"
ports = {}
[ceilings]
requests = 100
"#,
        fixture.port
    );
    fs::write(&pass, &pass_bytes).unwrap();
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).unwrap();
    project.run(&["pass", "attach", pass_path]);
    project.start_attempted = true;
    let started = project.run(&[
        "proxy",
        "start",
        "--listen",
        "127.0.0.1:0",
        "--detach",
        "--pass",
        pass_path,
        "--no-enforce",
    ]);
    let engine = &started["proxy"]["engine"];
    let teapot = project.bind(BoundEngine {
        instance: engine["instance"].as_str().unwrap().parse().unwrap(),
        project_id: engine["project_id"].as_str().unwrap().parse().unwrap(),
        enforced: false,
        policy_locked: true,
    });
    project.run(&["scope", "add", "127.0.0.1"]);
    project.run(&["sessions", "create", "alice"]);
    let macro_path = project.project.join(".teapot/macros/probe.toml");
    let macro_bytes = format!(
        "format = 1\n\n[[steps]]\nstate_changing = false\n[steps.request]\nmethod = \"GET\"\nurl = {:?}\n",
        fixture.url,
    );
    fs::write(&macro_path, &macro_bytes).unwrap();

    // Fixture setup sends one GET and creates a real job and budget
    // reservation before either accounting sample.
    let seed = project.run(&["--yes", "macros", "run", "probe", "--session", "alice"]);
    assert!(seed["run"]["job"].is_u64());
    assert_eq!(fixture.requests(), 1);
    let jobs_before = project.run(&["jobs", "list"]);
    let flows_before = project.run(&["flows", "list"]);
    let ledger_path = format!("{pass_path}.ledger");
    let original_ledger = fs::read(&ledger_path).unwrap();
    assert!(!original_ledger.is_empty());

    let capture = teapot
        .begin_accounting(
            accounting_binding(&pass, Sha256Digest::of(pass_bytes.as_bytes())),
            Some(MacroPlan {
                name: &"probe".parse().unwrap(),
                session: &"alice".parse().unwrap(),
            }),
        )
        .unwrap();
    assert_eq!(capture.preflight(false), Ok(()));
    let refusal = capture.preflight(true).unwrap_err();
    assert_eq!(refusal.code(), ErrorCode::AccountingUnestablished);
    assert_eq!(refusal.code().exit_code(), 8);
    let observation = capture.finish().unwrap();
    assert_unknown_charge(&observation);
    assert_eq!(observation.within_ceiling(), Some(true));
    assert_eq!(observation.record().requested.as_ref().unwrap().value, 1);
    assert_eq!(
        observation.record().dry_run_ceiling.as_ref().unwrap().value,
        99
    );
    assert_eq!(pass_spent(&observation), (Some(1), Some(1)));
    assert_eq!(fs::read(ledger_path).unwrap(), original_ledger);
    assert_eq!(fs::read(pass).unwrap(), pass_bytes.as_bytes());
    assert_eq!(fs::read(macro_path).unwrap(), macro_bytes.as_bytes());
    assert_eq!(project.run(&["jobs", "list"]), jobs_before);
    assert_eq!(project.run(&["flows", "list"]), flows_before);
    assert_eq!(fixture.requests(), 1);
    assert!(project.stop());
}

#[test]
#[ignore = "requires SCOURGE_PINNED_TEAPOT and a disposable loopback listener"]
fn pinned_verifier_gate_refuses_before_target_traffic() {
    use GateRefusalReason as Reason;
    use RequiredEnforcement::{Egress, None};

    let mut project = pinned_project();
    let fixture = Fixture::start();
    let session = ["alice".parse().unwrap()];
    let bound = project.start(&[]);
    let teapot = project.bind(bound);
    project.run(&["scope", "add", "127.0.0.1"]);
    project.run(&["sessions", "create", "alice"]);

    let admit_and_send = |instrument: &Teapot, fixture_project: &TestProject, required| {
        instrument.with_verifier_admission(&session, required, |snapshot| {
            let response = fixture_project.run(&[
                "requests",
                "send",
                "GET",
                &fixture.url,
                "--session",
                "alice",
            ]);
            assert_eq!(response["sent"]["status"], 200);
            snapshot
        })
    };
    assert_eq!(fixture.requests(), 0);
    let observed = admit_and_send(&teapot, &project, None).unwrap();
    assert_eq!(observed.enforcement, EnforcementStatus::Unenforced);
    assert!(
        observed
            .edit_surface
            .readings
            .iter()
            .any(|reading| matches!(
                reading.report.as_ref(),
                Some(EditSurfaceReport::Session(observed)) if observed.session == session[0]
            ))
    );
    assert!(
        observed
            .calls
            .iter()
            .all(|call| call.exits.native == Some(0))
    );
    let baseline = fixture.requests();
    assert_eq!(baseline, 1);

    let refused = |reason, code, teapot: &Teapot, fixture_project: &TestProject, required| {
        let failure = admit_and_send(teapot, fixture_project, required).unwrap_err();
        assert_eq!(failure.reason, reason, "{failure:?}");
        assert_eq!(failure.code(), code);
        assert_eq!(failure.code().exit_code(), 8);
        assert_eq!(fixture.requests(), baseline);
    };
    refused(
        Reason::EnforcementRequired,
        ErrorCode::EnforcementUnavailable,
        &teapot,
        &project,
        Egress,
    );

    project.run(&[
        "rules",
        "add",
        "replace",
        "-",
        "original",
        "changed",
        "--direction",
        "response",
    ]);
    refused(
        Reason::ActiveRule,
        ErrorCode::InstrumentEditsActive,
        &teapot,
        &project,
        None,
    );
    project.run(&["rules", "toggle", "1"]);
    assert!(
        teapot
            .verifier_preflight(&session, None)
            .unwrap()
            .edit_surface
            .readings
            .iter()
            .any(|reading| reading.report
                == Some(EditSurfaceReport::Rules(vec![(false, RuleStatus::Off)])))
    );
    project.run(&["rules", "remove", "1"]);

    project.run(&["intercept", "rules", "add", "-"]);
    refused(
        Reason::ActiveIntercept,
        ErrorCode::InstrumentEditsActive,
        &teapot,
        &project,
        None,
    );
    project.run(&["intercept", "off"]);
    assert!(
        teapot
            .verifier_preflight(&session, None)
            .unwrap()
            .edit_surface
            .readings
            .iter()
            .any(|reading| matches!(
                reading.report,
                Some(EditSurfaceReport::Intercept { enabled: false, .. })
            ))
    );

    let scripts = project
        .root
        .as_ref()
        .unwrap()
        .path()
        .join(".config/teapot/scripts");
    fs::create_dir_all(&scripts).unwrap();
    fs::write(
        scripts.join("benign-hook.lua"),
        "local t = require('teapot')\nt.on('response', function(_flow) end)\n",
    )
    .unwrap();
    project.run(&["scripts", "reload"]);
    refused(
        Reason::ActiveScriptHook,
        ErrorCode::InstrumentEditsActive,
        &teapot,
        &project,
        None,
    );
    fs::remove_file(scripts.join("benign-hook.lua")).unwrap();
    project.run(&["scripts", "reload"]);

    project.run(&["sessions", "set", "alice", "--logged-out", "status:401"]);
    refused(
        Reason::SessionBehavior,
        ErrorCode::InstrumentEditsActive,
        &teapot,
        &project,
        None,
    );
    assert!(project.stop());
    refused(
        Reason::EngineUnestablished,
        ErrorCode::EnforcementUnavailable,
        &teapot,
        &project,
        None,
    );

    let today = time::OffsetDateTime::now_utc().date();
    let before = today.previous_day().unwrap();
    let after = today.next_day().unwrap();
    let pass = project
        .root
        .as_ref()
        .unwrap()
        .path()
        .join("owned.pass.toml");
    fs::write(&pass, format!(
        "format = 1\nid = \"scourge-gate-fixture\"\nname = \"Passive gate fixture\"\n[approval]\nowner = \"fixture\"\noperator = \"fixture\"\nreference = \"bn-g2i\"\nvalid_from = {before}T00:00:00Z\nvalid_until = {after}T00:00:00Z\nrevoked = false\n[[destination]]\nlabel = \"local\"\naddress = \"127.0.0.1\"\nprotocol = \"tcp\"\nports = {}\n[ceilings]\nrequests = 10\n",
        fixture.port,
    )).unwrap();
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).unwrap();
    let pass = pass.to_str().unwrap();
    // Let Teapot reach its own pass check regardless of host sandbox support.
    // This helper answers capability probes and cannot launch an engine.
    let root = project.root.as_ref().unwrap().path();
    let playpen_probe = root.join("playpen-probe");
    let unexpected_playpen_run = root.join("unexpected-playpen-run");
    fs::write(
        root.join(".scourge-test-script"),
        r#"
case "$*" in
    --version) printf 'playpen 0.1.0\n' ;;
    "run --help") printf '%s\n' '--pass --only --host --expose --report --display' ;;
    "doctor --format json") printf '%s\n' '{"ok":true,"checks":[]}' ;;
    *) printf '%s\n' "$*" >> "$HOME/unexpected-playpen-run"; exit 99 ;;
esac
"#,
    )
    .unwrap();
    let launcher =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-script-launcher.sh");
    symlink(launcher, &playpen_probe).unwrap();
    assert_eq!(
        Command::new(&playpen_probe)
            .env_clear()
            .env("HOME", root)
            .arg("run")
            .status()
            .unwrap()
            .code(),
        Some(99)
    );
    assert_eq!(
        fs::read_to_string(&unexpected_playpen_run).unwrap(),
        "run\n"
    );
    fs::remove_file(&unexpected_playpen_run).unwrap();
    project.start_attempted = true;
    let output = project
        .prepare_command(&[
            "proxy",
            "start",
            "--listen",
            "127.0.0.1:0",
            "--detach",
            "--pass",
            pass,
            "--enforce",
        ])
        .env("TEAPOT_PLAYPEN", &playpen_probe)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"]["reason"], "pass-not-enforceable");
    assert!(!unexpected_playpen_run.exists());
    assert_eq!(fixture.requests(), baseline);

    // Inspect the same pass in a deliberately unenforced disposable engine.
    // This is test setup, independent of the preceding verifier refusal.
    let bound = project.start(&["--pass", pass, "--no-enforce"]);
    let teapot = project.bind(bound);
    refused(
        Reason::PassNotEnforceable,
        ErrorCode::EnforcementUnavailable,
        &teapot,
        &project,
        Egress,
    );
    assert!(project.stop());
}
