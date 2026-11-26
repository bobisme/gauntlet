#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use scourge_core::{
    canonical::{self, Sha256Digest},
    domain::{LeadOrigin, LeadRevision, Run},
    engagement::{EngagementDraft, PassPin, PassRef, PassState, RequiredEnforcement},
    evidence::{Completion, Evidence},
    ids::{EngagementId, LeadId},
    preflight::{
        LiveServices, PreflightDeclaration, PreflightError, PreflightPass, PreflightRequest,
        RunLocks, prepare,
    },
    request::{Invocation, NormalizedInput},
    rounds::execute_live,
    store::{RequestScope, Store},
    teapot::{
        BodyCapture, BodyWindow, BoundEngine, CancelAcknowledgment, CancelError, DispatchEvidence,
        EditSurfaceReport, EnforcementStatus, Environment, ExecutableKind, FlowReference, FlowRole,
        GateRefusalReason, InvocationError, MacroOutcome, NotSentReason, OutputStream, OwnedJob,
        ReloginAction, RuleStatus, SendOptions, SendOutcome, SessionSource, SessionState, StepFlow,
        Teapot, TransportFailure,
        accounting::{
            AccountingBinding, AccountingError, AccountingObservation, AccountingRefusal,
            EvidenceKind, MacroPlan, Phase,
        },
    },
    template::{Claim, ClaimClass, EngagementPin, Method, SlotName, SlotValue, Templates},
    wire::{AbsolutePath, Attribution, DiagnosticCode, Effect, ErrorCode, Granularity, Unit},
    workspace::{
        InvestigationAuthority, ManifestArtifactKind, ManifestArtifactPin, ManifestAuthority,
        PassAuthority, TeapotProjectAuthority, VerifierRuntimeAuthority,
    },
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

#[test]
fn macro_dry_run_exposes_native_remaining_units_and_preserves_legacy_result() {
    let mock = AccountingWrapper::new();
    mock.plan(2, Some(17));
    let name = "two".parse().unwrap();
    let session = "alice".parse().unwrap();
    let observed = mock
        .teapot
        .dry_run_macro_with_units(&name, &session)
        .unwrap();
    let legacy = mock.teapot.dry_run_macro(&name, &session).unwrap();
    assert_eq!(observed.value.units_left, Some(17));
    assert_eq!(observed.value.dry_run, legacy.value);
    assert_eq!(legacy.value.request_count, 2);
    assert_eq!(legacy.value.within_ceiling, Some(true));
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
        self.plan_named("two", request_count, left);
    }

    fn plan_named(&self, name: &str, request_count: u64, left: Option<u64>) {
        let capture: Value =
            serde_json::from_str(include_str!("../../../fixtures/contracts/dry-run.json")).unwrap();
        let mut output = capture["output"].clone();
        output["run"]["name"] = json!(name);
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
fn registered_recipe_bound_rejects_unrelated_macro_and_caller_undercount() {
    let wrapper = AccountingWrapper::new();
    wrapper.jobs(&[]);
    wrapper.pass(Some(ceiling(100, Some(80), Some(20))));

    // An unrelated one-request macro cannot stand in for the registered
    // two-request plant operation, even though that small macro fits.
    wrapper.plan_named("unrelated", 1, Some(19));
    let mut unrelated = wrapper
        .teapot
        .begin_accounting(
            wrapper.binding.clone(),
            Some(MacroPlan {
                name: &"unrelated".parse().unwrap(),
                session: &"alice".parse().unwrap(),
            }),
        )
        .unwrap();
    assert_eq!(
        unrelated.preflight_registered(35, 2),
        Err(AccountingRefusal::CeilingUnknown)
    );

    // The registered macro count can match while the complete recipe plus
    // login/retry bound still exceeds the pass-wide capacity.
    wrapper.plan(2, Some(18));
    let mut undercounted = wrapper
        .teapot
        .begin_accounting(
            wrapper.binding.clone(),
            Some(MacroPlan {
                name: &"two".parse().unwrap(),
                session: &"alice".parse().unwrap(),
            }),
        )
        .unwrap();
    assert_eq!(
        undercounted.preflight_registered(35, 2),
        Err(AccountingRefusal::CeilingExceeded)
    );

    wrapper.pass(Some(ceiling(100, Some(10), Some(90))));
    wrapper.plan(2, Some(88));
    let mut exact = wrapper
        .teapot
        .begin_accounting(
            wrapper.binding.clone(),
            Some(MacroPlan {
                name: &"two".parse().unwrap(),
                session: &"alice".parse().unwrap(),
            }),
        )
        .unwrap();
    assert_eq!(exact.preflight_registered(35, 2), Ok(()));
    let observation = exact.finish().unwrap();
    let record = observation.record();
    assert_eq!(record.requested.as_ref().unwrap().value, 2);
    let admitted = record.admitted.as_ref().unwrap();
    assert_eq!(admitted.value, 35);
    assert_eq!(
        admitted.source.as_str(),
        "scourge.compiled_dispatch_plan.requests"
    );
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

fn write_output(root: &Path, name: &str, output: &Value) {
    fs::write(root.join(name), output.to_string()).unwrap();
}

#[test]
fn stored_read_pins_the_id_and_validates_body_windows() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"case "$4" in
version) exec /bin/cat "$HOME/version.json" ;;
flows) printf '%s\n' "$@" > "$HOME/record"; exec /bin/cat "$HOME/flow.json" ;;
*) exit 20 ;;
esac"#,
    );
    let version = bound_version(root.path());
    write_output(root.path(), "version.json", &version);
    let captured: Value =
        serde_json::from_str(include_str!("../../../fixtures/contracts/read-flow.json")).unwrap();
    let output = &captured["output"];
    write_output(root.path(), "flow.json", output);
    let found = wrapper.read_flow(3, None).unwrap();
    assert_eq!(found.value.id, 3);
    assert_eq!(
        found.value.destination.as_deref(),
        Some("http://127.0.0.1:39381")
    );
    assert_eq!(found.value.method.as_deref(), Some("GET"));
    assert_eq!(found.value.status, Some(200));
    assert_eq!(found.value.origin, "replay");
    assert_eq!(found.value.tags, ["unbound"]);
    assert!(found.value.elapsed_ms.is_some());
    assert_eq!(found.value.request.body.unwrap().capture, BodyCapture::None);
    let response = found.value.response.body.unwrap();
    assert_eq!(response.bytes.unwrap(), br#"{"id":"fixture"}"#);
    assert!(response.whole);

    let mut partial = output.clone();
    let flow = &mut partial["flow"];
    flow["response_body_base64"] = json!("Imk=");
    flow["response_body_info"]["shown"] = json!(2);
    flow["response_body_info"]["whole"] = json!(false);
    write_output(root.path(), "flow.json", &partial);
    let window = BodyWindow::new(1, 2).unwrap();
    let read = wrapper.read_flow(3, Some(window)).unwrap();
    let response = read.value.response.body.unwrap();
    assert_eq!(response.bytes.unwrap(), b"\"i");
    assert_eq!(response.offset, 1);
    assert!(!response.whole);
    let argv = fs::read_to_string(root.path().join("record")).unwrap();
    assert_eq!(
        argv.lines().skip(3).collect::<Vec<_>>(),
        [
            "flows",
            "show",
            "3",
            "--base64",
            "--stored",
            "--offset",
            "1",
            "--max-body",
            "2"
        ]
    );

    for (path, bad, native_exit) in [
        ("/flow/id", json!(4), Some(0)),
        ("/flow/id", json!("3"), None),
        ("/flow/response_body_base64", json!("Imk!"), Some(0)),
        ("/flow/response_body_base64", json!("ImkA"), Some(0)),
        ("/flow/response_body_info/whole", json!(true), Some(0)),
        (
            "/flow/response_body_info/decoding",
            json!("decoded:gzip"),
            Some(0),
        ),
        ("/flow/request_body_info/shown", json!(1), Some(0)),
        ("/flow/started_at", json!("unparseable"), Some(0)),
    ] {
        let mut bad_output = partial.clone();
        *bad_output.pointer_mut(path).unwrap() = bad;
        write_output(root.path(), "flow.json", &bad_output);
        check_diagnostic(
            &wrapper.read_flow(3, Some(window)).unwrap_err(),
            DiagnosticCode::InvalidNativeOutput,
            native_exit,
            Some(0),
        );
    }

    let mut alias = partial.clone();
    alias["flow"]["selector"] = json!("@last");
    write_output(root.path(), "flow.json", &alias);
    check_diagnostic(
        &wrapper.read_flow(3, Some(window)).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );
    fs::write(
        root.path().join("flow.json"),
        partial
            .to_string()
            .replacen(r#""id":3"#, r#""id":3,"id":3"#, 1),
    )
    .unwrap();
    check_diagnostic(
        &wrapper.read_flow(3, Some(window)).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        None,
        Some(0),
    );
    assert!(BodyWindow::new(0, 0).is_err());
    assert!(BodyWindow::new(0, 1_048_577).is_err());
    assert_eq!(
        wrapper.read_flow(0, None).unwrap_err().code(),
        ErrorCode::UsageError
    );

    let mut wrong = version;
    wrong["version"]["engine"]["project_id"] = json!("other-project");
    write_output(root.path(), "version.json", &wrong);
    fs::remove_file(root.path().join("record")).unwrap();
    check_diagnostic(
        &wrapper.read_flow(3, None).unwrap_err(),
        DiagnosticCode::WrongListener,
        Some(0),
        Some(0),
    );
    assert!(!root.path().join("record").exists());
}

#[test]
fn oversized_stored_read_is_rejected_by_the_capture_limit() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"
case "$4" in
version) exec /bin/cat "$HOME/version.json" ;;
flows) exec /usr/bin/yes 'sensitive native output' ;;
*) exit 20 ;;
esac"#,
    );
    write_output(root.path(), "version.json", &bound_version(root.path()));
    assert!(matches!(
        wrapper.read_flow(3, None).unwrap_err(),
        InvocationError::DependencyUnavailable {
            transport_failure: Some(TransportFailure::OutputLimit(OutputStream::Stdout)),
            ..
        }
    ));
}

fn owned_job(id: u64, engine: BoundEngine) -> OwnedJob {
    OwnedJob::from_run("R-example".parse().unwrap(), id, engine).unwrap()
}

#[test]
fn cancel_links_acknowledgment_and_observation_to_one_owned_job() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"
case "$4 $5" in
'version ') exec /bin/cat "$HOME/version.json" ;;
'jobs stop')
    [ "$6" = 41 ] && [ "$#" = 6 ] || exit 20
    printf 'stop\n' >> "$HOME/record"
    exec /bin/cat "$HOME/stop.json" ;;
'jobs list')
    [ "$6 $7 $8 $9" = '--limit 1 --before 42' ] && [ "$#" = 9 ] || exit 20
    printf 'list\n' >> "$HOME/record"
    exec /bin/cat "$HOME/jobs.json" ;;
*) exit 20 ;;
esac"#,
    );
    write_output(root.path(), "version.json", &bound_version(root.path()));
    let job = owned_job(41, example_engine());
    let foreign = owned_job(
        41,
        BoundEngine {
            project_id: "foreign-project".parse().unwrap(),
            ..example_engine()
        },
    );
    assert!(matches!(
        wrapper.cancel(&foreign),
        Err(CancelError::NotRequested(_))
    ));
    assert!(!root.path().join("record").exists());

    let mut stop = json!({"advice": [], "stopped": {
        "engine_running": true, "wait_secs": 10, "jobs": [{
            "id": 41, "kind": "macro-run", "state": "ending", "reason": null,
            "stopped_now": true, "ended": false, "sent": 0
        }]
    }});
    let list: Value =
        serde_json::from_str(include_str!("../../../fixtures/contracts/list-jobs.json")).unwrap();
    let mut terminal = list["output"]["jobs"][0].clone();
    terminal["id"] = json!(41);
    write_output(root.path(), "stop.json", &stop);
    write_output(
        root.path(),
        "jobs.json",
        &json!({"advice": [], "jobs": [terminal]}),
    );
    let canceled = wrapper.cancel(&job).unwrap();
    assert_eq!(
        canceled.acknowledgment.value,
        CancelAcknowledgment::StopPending
    );
    assert!(canceled.observation.unwrap().value.unwrap().is_terminal());
    assert_eq!(
        fs::read_to_string(root.path().join("record")).unwrap(),
        "stop\nlist\n"
    );

    // A job that completed while cancellation raced it remains a completed job.
    let reply = &mut stop["stopped"]["jobs"][0];
    reply["state"] = json!("completed");
    reply["ended"] = json!(true);
    reply["stopped_now"] = json!(false);
    write_output(root.path(), "stop.json", &stop);
    let mut older = terminal;
    older["id"] = json!(40);
    write_output(
        root.path(),
        "jobs.json",
        &json!({"advice": [], "jobs": [older]}),
    );
    let raced = wrapper.cancel(&job).unwrap();
    assert_eq!(
        raced.acknowledgment.value,
        CancelAcknowledgment::EndedWithoutStop
    );
    assert!(raced.observation.unwrap().value.is_none());

    // A valid acknowledgment survives a separate observation failure.
    write_output(
        root.path(),
        "jobs.json",
        &json!({"advice": [], "jobs": null}),
    );
    let canceled = wrapper.cancel(&job).unwrap();
    assert_eq!(
        canceled.acknowledgment.value,
        CancelAcknowledgment::EndedWithoutStop
    );
    assert!(canceled.observation.is_err());

    let mut duplicate = stop.clone();
    duplicate["stopped"]["jobs"] = json!([stop["stopped"]["jobs"][0], stop["stopped"]["jobs"][0],]);
    let mut foreign = stop.clone();
    foreign["stopped"]["jobs"][0]["id"] = json!(40);
    for bad in [duplicate, foreign] {
        write_output(root.path(), "stop.json", &bad);
        let CancelError::Unconfirmed(failure) = wrapper.cancel(&job).unwrap_err() else {
            panic!("malformed stop reply must leave cancel unconfirmed");
        };
        check_diagnostic(
            &failure,
            DiagnosticCode::InvalidNativeOutput,
            Some(0),
            Some(0),
        );
    }
}

#[test]
fn cancel_overflow_and_observed_restart_leave_request_unconfirmed() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"case "$4 $5" in
'version ')
    if [ -f "$HOME/stopped" ]; then exec /bin/cat "$HOME/restarted.json"; fi
    exec /bin/cat "$HOME/version.json" ;;
'jobs stop')
    if [ ! -f "$HOME/stop.json" ]; then exec /usr/bin/yes 'sensitive native output'; fi
    printf 'seen' > "$HOME/stopped"
    exec /bin/cat "$HOME/stop.json" ;;
*) exit 20 ;;
esac"#,
    );
    let version = bound_version(root.path());
    write_output(root.path(), "version.json", &version);
    let job = owned_job(41, example_engine());
    assert!(matches!(
        wrapper.cancel(&job).unwrap_err(),
        CancelError::Unconfirmed(InvocationError::DependencyUnavailable {
            transport_failure: Some(TransportFailure::OutputLimit(OutputStream::Stdout)),
            ..
        })
    ));
    let mut restarted = version;
    restarted["version"]["engine"]["instance"] = json!("other-engine");
    write_output(root.path(), "restarted.json", &restarted);
    let stop = json!({"advice": [], "stopped": {
        "engine_running": true, "wait_secs": 10, "jobs": [{
            "id": 41, "kind": "macro-run", "state": "stopped", "reason": "operator",
            "stopped_now": true, "ended": true, "sent": 0
        }]
    }});
    write_output(root.path(), "stop.json", &stop);
    let CancelError::Unconfirmed(cause) = wrapper.cancel(&job).unwrap_err() else {
        panic!("restart after stop must leave the request unconfirmed");
    };
    check_diagnostic(&cause, DiagnosticCode::WrongListener, Some(0), Some(0));
    let CancelError::NotRequested(cause) = wrapper.cancel(&job).unwrap_err() else {
        panic!("restart before stop must prevent the request");
    };
    check_diagnostic(&cause, DiagnosticCode::WrongListener, Some(0), Some(0));
}

fn captured_send() -> Value {
    let capture: Value =
        serde_json::from_str(include_str!("../../../fixtures/contracts/send.json")).unwrap();
    capture["output"].clone()
}

fn captured_macro_send() -> Value {
    let capture: Value =
        serde_json::from_str(include_str!("../../../fixtures/contracts/macro-send.json")).unwrap();
    capture["output"].clone()
}

/// One `relogin` object exactly as the repository recorded a real reply
/// (`fixtures/contracts/channel-observed.txt`, the frozen `sessions show`
/// observation of a login that ran and then a retry that was answered
/// logged-out again).
fn recorded_relogin(record: &str) -> Value {
    let observed = include_str!("../../../fixtures/contracts/channel-observed.txt");
    let line = observed
        .lines()
        .find(|line| line.starts_with(record))
        .unwrap_or_else(|| panic!("{record} is a recorded channel observation"));
    let value: Value = serde_json::from_str(line[record.len()..].trim()).unwrap();
    value["relogin"].clone()
}

fn replay_output(step_one: &Value, step_two: &Value) -> Value {
    json!({
        "advice": [],
        "flow": {
            "parent": 0,
            "dry_run": false,
            "destination": "http://127.0.0.1:39381",
            "notes": [],
            "flows": [],
            "session": {"name": "alice", "source": "flag"},
            "text": "5  201  16  3",
            "id": 5,
            "status": 201,
            "time_ms": 3,
            "macro_replay": {
                "name": "plant",
                "step": 2,
                "steps_in_macro": 2,
                "state_changing": [2],
                "units": 2,
                "units_left": null,
                "job": 1,
                "preparatory": [step_one],
                "replayed": step_two,
                "replaced": ["json:note"],
                "variables": []
            }
        }
    })
}

#[test]
fn send_binds_the_named_session_and_the_only_per_send_reference() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"case "$4" in
version) exec /bin/cat "$HOME/version.json" ;;
requests) printf '%s\n' "$@" > "$HOME/record"; exec /bin/cat "$HOME/send.json" ;;
*) exit 20 ;;
esac"#,
    );
    write_output(root.path(), "version.json", &bound_version(root.path()));
    write_output(root.path(), "send.json", &captured_send());

    let session = "alice".parse().unwrap();
    let url = "http://127.0.0.1:39381/probe".parse().unwrap();
    let sent = wrapper
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    assert_eq!(sent.value.flow, Some(3));
    assert_eq!(sent.value.dispatch(), DispatchEvidence::Flow { flow: 3 });
    assert_eq!(sent.value.session.source, SessionSource::Flag);
    assert_eq!(
        sent.value.session.name.as_ref().map(|name| name.as_str()),
        Some("alice")
    );
    assert_eq!(sent.value.destination, "http://127.0.0.1:39381");
    assert_eq!(sent.value.status, Some(200));
    assert_eq!(sent.value.hops.len(), 1);
    assert_eq!(sent.value.hops[0].sent_bytes, 72);
    assert_eq!(sent.value.request_bytes, 72);
    assert_eq!(
        sent.value.flows(),
        [StepFlow {
            step: 1,
            role: FlowRole::Request,
            reference: FlowReference::Retained(3),
        }]
    );
    let argv = fs::read_to_string(root.path().join("record")).unwrap();
    assert_eq!(
        argv.lines().skip(3).collect::<Vec<_>>(),
        [
            "requests",
            "send",
            "GET",
            "http://127.0.0.1:39381/probe",
            "--session",
            "alice"
        ]
    );

    let mut with_login = captured_send();
    // The frozen shape (sessions/sender.rs): a retried send's own flow and
    // hops are the retry, and `logged_out_flow` is the send that was answered
    // logged-out. They are different sends.
    with_login["sent"]["flow"] = json!(9);
    with_login["sent"]["hops"][0]["flow"] = json!(9);
    with_login["sent"]["relogin"] = json!({
        "rule": "logged-out", "action": "re-logged-in", "ran": true, "generation": 1,
        "login": "login", "login_job": 1, "login_flows": [7],
        "logged_out_flow": 3, "retried": true, "retry_flow": 9,
        "not_retried": null, "paused": false, "reason": null
    });
    write_output(root.path(), "send.json", &with_login);
    let sent = wrapper
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    assert_eq!(sent.value.flow, Some(9));
    assert_eq!(sent.value.dispatch(), DispatchEvidence::Flow { flow: 9 });
    assert_eq!(
        sent.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(3),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(7),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Retry,
                reference: FlowReference::Retained(9),
            },
        ]
    );

    // A retry that followed a redirect keeps the retry and its redirect
    // apart from the original request.
    let mut retried_redirect = with_login.clone();
    let mut redirect = retried_redirect["sent"]["hops"][0].clone();
    redirect["flow"] = json!(10);
    retried_redirect["sent"]["hops"] =
        json!([retried_redirect["sent"]["hops"][0].clone(), redirect]);
    write_output(root.path(), "send.json", &retried_redirect);
    let sent = wrapper
        .send(
            Method::Get,
            &url,
            &session,
            SendOptions {
                follow: Some(1),
                ..SendOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        sent.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(3),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(7),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Retry,
                reference: FlowReference::Retained(9),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Redirect,
                reference: FlowReference::Retained(10),
            },
        ]
    );

    // Capture lost for the retry: the reply's own flow is null while the
    // original send's flow is still known. The retry is a sent send whose
    // reference is missing, never a recorded non-send (INV-41).
    let mut lost = captured_send();
    lost["sent"]["flow"] = Value::Null;
    lost["sent"]["hops"][0]["flow"] = Value::Null;
    lost["sent"]["relogin"] = json!({
        "rule": "logged-out", "action": "re-logged-in", "ran": true, "generation": 1,
        "login": "login", "login_job": 1, "login_flows": [7],
        "logged_out_flow": 3, "retried": true, "retry_flow": null,
        "not_retried": null, "paused": false, "reason": null
    });
    write_output(root.path(), "send.json", &lost);
    let sent = wrapper
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    assert_eq!(
        sent.value.dispatch(),
        DispatchEvidence::NoFlow {
            outcome: SendOutcome::Complete
        }
    );
    assert!(sent.value.dispatch().was_sent());
    assert!(!sent.value.dispatch().is_not_sent());
    assert_eq!(
        sent.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(3),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(7),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Retry,
                reference: FlowReference::Missing,
            },
        ]
    );

    // Capture off or lost: the reply says the request was sent, but there is
    // no per-send reference. That is not a recorded non-send.
    let mut missing = captured_send();
    missing["sent"]["flow"] = Value::Null;
    missing["sent"]["hops"][0]["flow"] = Value::Null;
    write_output(root.path(), "send.json", &missing);
    let sent = wrapper
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    assert_eq!(
        sent.value.dispatch(),
        DispatchEvidence::NoFlow {
            outcome: SendOutcome::Complete
        }
    );
    assert!(sent.value.dispatch().was_sent());
    assert!(!sent.value.dispatch().is_not_sent());
    assert!(sent.value.dispatch().is_no_flow());
    assert_eq!(sent.value.flow, None);
    assert_eq!(
        sent.value.flows(),
        [StepFlow {
            step: 1,
            role: FlowRole::Request,
            reference: FlowReference::Missing,
        }]
    );

    for (pointer, bad) in [
        ("/sent/dry_run", json!(true)),
        ("/sent/session/name", json!("bob")),
        ("/sent/session/source", json!("default")),
        ("/sent/flow", json!(4)),
        ("/sent/hops", json!([])),
        ("/sent/hops/0/status", json!(500)),
        ("/sent/hops/0/outcome", json!("unknown")),
        ("/sent/hops/0/outcome", json!("stopped")),
        ("/sent/destination", json!("http://127.0.0.1:1")),
    ] {
        let mut output = captured_send();
        *output.pointer_mut(pointer).unwrap() = bad;
        write_output(root.path(), "send.json", &output);
        check_diagnostic(
            &wrapper
                .send(Method::Get, &url, &session, SendOptions::default())
                .unwrap_err(),
            DiagnosticCode::InvalidNativeOutput,
            Some(0),
            Some(0),
        );
    }
    let mut schema_invalid = captured_send();
    schema_invalid["sent"]["request_bytes"] = json!("72");
    write_output(root.path(), "send.json", &schema_invalid);
    check_diagnostic(
        &wrapper
            .send(Method::Get, &url, &session, SendOptions::default())
            .unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        None,
        Some(0),
    );

    let mut duplicate = captured_send();
    let hop = duplicate["sent"]["hops"][0].clone();
    duplicate["sent"]["hops"] = json!([hop.clone(), hop]);
    write_output(root.path(), "send.json", &duplicate);
    check_diagnostic(
        &wrapper
            .send(Method::Get, &url, &session, SendOptions::default())
            .unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    // A redirect chain is bounded by the caller's `--follow`, not by what the
    // reply claims: extra hops are traffic past the bound.
    let mut redirected = captured_send();
    let mut redirect = redirected["sent"]["hops"][0].clone();
    redirect["flow"] = json!(10);
    redirect["location"] = json!(null);
    redirected["sent"]["hops"] = json!([redirected["sent"]["hops"][0].clone(), redirect]);
    write_output(root.path(), "send.json", &redirected);
    check_diagnostic(
        &wrapper
            .send(Method::Get, &url, &session, SendOptions::default())
            .unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );
    for follow in [1, 2] {
        let sent = wrapper
            .send(
                Method::Get,
                &url,
                &session,
                SendOptions {
                    follow: Some(follow),
                    ..SendOptions::default()
                },
            )
            .unwrap();
        assert_eq!(sent.value.hops.len(), 2);
        assert_eq!(sent.value.flow, Some(3));
        assert_eq!(
            sent.value.flows(),
            [
                StepFlow {
                    step: 1,
                    role: FlowRole::Request,
                    reference: FlowReference::Retained(3),
                },
                StepFlow {
                    step: 1,
                    role: FlowRole::Redirect,
                    reference: FlowReference::Retained(10),
                },
            ]
        );
    }

    // Retry topology: the reply's flow and the retry's flow are one send, and
    // the original request is a different one.
    for relogin in [
        // The reply's flow is not the retry's.
        json!({
            "rule": "logged-out", "action": "re-logged-in", "ran": true, "generation": 1,
            "login_flows": [7], "logged_out_flow": 3, "retried": true,
            "retry_flow": 8, "not_retried": null, "paused": false, "reason": null
        }),
        // Double counted: the retry flow is also named as the original.
        json!({
            "rule": "logged-out", "action": "re-logged-in", "ran": true, "generation": 1,
            "login_flows": [7], "logged_out_flow": 9, "retried": true,
            "retry_flow": 9, "not_retried": null, "paused": false, "reason": null
        }),
        // A flow with no retry is a claim nothing supports.
        json!({
            "rule": "logged-out", "action": "login-shared", "ran": false, "generation": 1,
            "login_flows": [], "logged_out_flow": 3, "retried": false,
            "retry_flow": 9, "not_retried": null, "paused": false, "reason": null
        }),
        // Not retried, so the logged-out answer must be one of this send's hops.
        json!({
            "rule": "logged-out", "action": "login-failed", "ran": true, "generation": 1,
            "login_flows": [7], "logged_out_flow": 12, "retried": false,
            "retry_flow": null, "not_retried": "login-failed", "paused": false,
            "reason": "no-form"
        }),
    ] {
        let mut output = captured_send();
        output["sent"]["flow"] = json!(9);
        output["sent"]["hops"][0]["flow"] = json!(9);
        output["sent"]["relogin"] = relogin;
        write_output(root.path(), "send.json", &output);
        check_diagnostic(
            &wrapper
                .send(Method::Get, &url, &session, SendOptions::default())
                .unwrap_err(),
            DiagnosticCode::InvalidNativeOutput,
            Some(0),
            Some(0),
        );
    }

    // A logged-out answer that was not retried is one of this send's hops.
    let mut reported = captured_send();
    reported["sent"]["relogin"] = json!({
        "rule": "logged-out", "action": "reported", "ran": false, "generation": 0,
        "login": null, "login_job": null, "login_flows": [],
        "logged_out_flow": 3, "retried": false, "retry_flow": null,
        "not_retried": "no-login", "paused": false, "reason": null
    });
    write_output(root.path(), "send.json", &reported);
    let sent = wrapper
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    assert_eq!(
        sent.value.flows(),
        [StepFlow {
            step: 1,
            role: FlowRole::Request,
            reference: FlowReference::Retained(3),
        }]
    );

    // The repository-recorded paused-after-retry envelope: the login ran and
    // the retry was answered logged-out again, so the frozen sender keeps
    // `ran=true` and overwrites only the action
    // (`fixtures/contracts/channel-observed.txt` session-GET). Accepting it
    // must keep the original/login/retry topology intact.
    let paused_after_retry = recorded_relogin("session-GET ");
    assert_eq!(paused_after_retry["action"], json!("paused"));
    assert_eq!(paused_after_retry["ran"], json!(true));
    assert_eq!(paused_after_retry["paused"], json!(true));
    assert_eq!(paused_after_retry["retried"], json!(true));
    let original = paused_after_retry["logged_out_flow"].as_u64().unwrap();
    let login = paused_after_retry["login_flows"][0].as_u64().unwrap();
    let retry = paused_after_retry["retry_flow"].as_u64().unwrap();
    let mut recorded = captured_send();
    recorded["sent"]["flow"] = json!(retry);
    recorded["sent"]["hops"][0]["flow"] = json!(retry);
    recorded["sent"]["relogin"] = paused_after_retry;
    write_output(root.path(), "send.json", &recorded);
    let sent = wrapper
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    assert_eq!(
        sent.value.relogin.as_ref().map(|relogin| relogin.action),
        Some(ReloginAction::Paused)
    );
    assert_eq!(
        sent.value.dispatch(),
        DispatchEvidence::Flow { flow: retry }
    );
    assert_eq!(
        sent.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(original),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(login),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Retry,
                reference: FlowReference::Retained(retry),
            },
        ]
    );

    // A session that was already paused ran no login, so `paused` also
    // appears with `ran=false`: a different real reply that still parses.
    let mut already_paused = captured_send();
    already_paused["sent"]["relogin"] = json!({
        "rule": "logged-out", "action": "paused", "ran": false, "generation": 0,
        "login": "login", "login_job": null, "login_flows": [],
        "logged_out_flow": 3, "retried": false, "retry_flow": null,
        "not_retried": "paused", "paused": true, "reason": "paused"
    });
    write_output(root.path(), "send.json", &already_paused);
    let sent = wrapper
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    assert_eq!(sent.value.dispatch(), DispatchEvidence::Flow { flow: 3 });

    // A `re-logged-in` reply says this send ran the login (`teapot-api`
    // `ReloginUsed`; `run_login` builds it only through `base(RELOGGED_IN)`,
    // which sets `ran=true`). A send that waited through that login is
    // answered `login-shared`, because `decided`/`decided_locked` compare the
    // send's generation against the advanced one before copying anything. The
    // old positive for `re-logged-in` with `ran=false` was an impossible
    // envelope, so it is rejected like every other pair the sender cannot
    // write.
    let mut waited = captured_send();
    waited["sent"]["relogin"] = json!({
        "rule": "logged-out", "action": "re-logged-in", "ran": false, "generation": 1,
        "login": "login", "login_job": null, "login_flows": [],
        "logged_out_flow": 3, "retried": false, "retry_flow": null,
        "not_retried": null, "paused": false, "reason": null
    });
    write_output(root.path(), "send.json", &waited);
    check_diagnostic(
        &wrapper
            .send(Method::Get, &url, &session, SendOptions::default())
            .unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    // Only shapes the frozen sender writes are accepted: a `login-shared`
    // send never ran the login, and only a login that allows a retry can
    // carry `retried`.
    for relogin in [
        json!({
            "rule": "logged-out", "action": "login-shared", "ran": true, "generation": 1,
            "login_flows": [], "logged_out_flow": 3, "retried": false,
            "retry_flow": null, "not_retried": null, "paused": false, "reason": null
        }),
        json!({
            "rule": "logged-out", "action": "login-failed", "ran": true, "generation": 1,
            "login_flows": [7], "logged_out_flow": 3, "retried": true,
            "retry_flow": 9, "not_retried": null, "paused": false, "reason": "no-form"
        }),
    ] {
        let mut output = captured_send();
        output["sent"]["flow"] = json!(9);
        output["sent"]["hops"][0]["flow"] = json!(9);
        output["sent"]["relogin"] = relogin;
        write_output(root.path(), "send.json", &output);
        check_diagnostic(
            &wrapper
                .send(Method::Get, &url, &session, SendOptions::default())
                .unwrap_err(),
            DiagnosticCode::InvalidNativeOutput,
            Some(0),
            Some(0),
        );
    }
}

/// The retry state the frozen sender can and cannot write, driven through
/// both decoders that carry a `relogin` object: `requests send` and a macro
/// step. Each accepted row is a shape a frozen construction path produces;
/// each rejected row is a pair it cannot, so an overclaiming envelope cannot
/// become a login/retry claim in either path.
#[test]
fn relogin_retry_state_follows_the_frozen_sender_construction_paths() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"case "$4 $5" in
'version ') exec /bin/cat "$HOME/version.json" ;;
'requests send') printf '%s\n' "$@" > "$HOME/record"; exec /bin/cat "$HOME/send.json" ;;
'--yes macros') printf '%s\n' "$@" > "$HOME/record"; exec /bin/cat "$HOME/run.json" ;;
*) exit 20 ;;
esac"#,
    );
    write_output(root.path(), "version.json", &bound_version(root.path()));
    let name = "plant".parse().unwrap();
    let session = "alice".parse().unwrap();
    let url = "http://127.0.0.1:39381/probe".parse().unwrap();

    // Two recorded replies, used instead of typing the shape in:
    // `session-POST` is `run_login` refusing the retry of a state-changing
    // request, and `session-GET` is the paused-after-retry branch.
    let not_retried_state_changing = recorded_relogin("session-POST ");
    assert_eq!(not_retried_state_changing["action"], json!("re-logged-in"));
    assert_eq!(not_retried_state_changing["ran"], json!(true));
    assert_eq!(not_retried_state_changing["retried"], json!(false));
    assert_eq!(
        not_retried_state_changing["not_retried"],
        json!("state-changing")
    );
    let paused_after_retry = recorded_relogin("session-GET ");
    assert_eq!(paused_after_retry["action"], json!("paused"));
    assert_eq!(paused_after_retry["ran"], json!(true));
    assert_eq!(paused_after_retry["paused"], json!(true));
    assert_eq!(paused_after_retry["retried"], json!(true));
    assert_eq!(paused_after_retry["not_retried"], Value::Null);

    // (label, relogin, accepted)
    let table = [
        // `run_login` ran the login (`ran=true`) and the sender did not send
        // the POST again: `not_retried` is written only on that path.
        (
            "recorded re-logged-in, not retried (state-changing)",
            not_retried_state_changing,
            true,
        ),
        // The retry was answered logged-out again: the sender keeps the login
        // that ran and overwrites the action and `paused` together.
        ("recorded paused after retry", paused_after_retry, true),
        // `decided` reports a session that was already paused with `ran=false`.
        (
            "paused before this send (ran=false)",
            json!({
                "rule": "logged-out", "action": "paused", "ran": false, "generation": 0,
                "login": "login", "login_job": null, "login_flows": [],
                "logged_out_flow": 3, "retried": false, "retry_flow": null,
                "not_retried": "paused", "paused": true, "reason": "paused"
            }),
            true,
        ),
        // Another send's login allowed the retry, so this one shares it:
        // `login-shared` with no login flows of its own.
        (
            "login-shared then retried",
            json!({
                "rule": "logged-out", "action": "login-shared", "ran": false, "generation": 1,
                "login": "login", "login_job": null, "login_flows": [],
                "logged_out_flow": 3, "retried": true, "retry_flow": 9,
                "not_retried": null, "paused": false, "reason": null
            }),
            true,
        ),
        // Capture loss (INV-41): the retry happened, its flow is unknown.
        (
            "retried with a lost retry flow",
            json!({
                "rule": "logged-out", "action": "re-logged-in", "ran": true, "generation": 1,
                "login": "login", "login_job": 1, "login_flows": [7],
                "logged_out_flow": 3, "retried": true, "retry_flow": null,
                "not_retried": null, "paused": false, "reason": null
            }),
            true,
        ),
        // `run_login` alone builds `re-logged-in`, always with `ran=true`; a
        // send that waited through that login is answered `login-shared`.
        (
            "re-logged-in without running the login",
            json!({
                "rule": "logged-out", "action": "re-logged-in", "ran": false, "generation": 1,
                "login": "login", "login_job": null, "login_flows": [],
                "logged_out_flow": 3, "retried": false, "retry_flow": null,
                "not_retried": null, "paused": false, "reason": null
            }),
            false,
        ),
        (
            "re-logged-in without running the login, then retried",
            json!({
                "rule": "logged-out", "action": "re-logged-in", "ran": false, "generation": 1,
                "login": "login", "login_job": null, "login_flows": [7],
                "logged_out_flow": 3, "retried": true, "retry_flow": 9,
                "not_retried": null, "paused": false, "reason": null
            }),
            false,
        ),
        // `login-shared` is the action for a send that ran no login.
        (
            "login-shared claiming the login ran",
            json!({
                "rule": "logged-out", "action": "login-shared", "ran": true, "generation": 1,
                "login": "login", "login_job": null, "login_flows": [],
                "logged_out_flow": 3, "retried": false, "retry_flow": null,
                "not_retried": null, "paused": false, "reason": null
            }),
            false,
        ),
        // `retried` is set only after the retry was sent, and `not_retried`
        // only on the paths that return before sending it.
        (
            "retried with a not-retried reason",
            json!({
                "rule": "logged-out", "action": "re-logged-in", "ran": true, "generation": 1,
                "login": "login", "login_job": 1, "login_flows": [7],
                "logged_out_flow": 3, "retried": true, "retry_flow": 9,
                "not_retried": "retried-once", "paused": false, "reason": null
            }),
            false,
        ),
        // The paused-after-retry branch assigns `paused` with the action.
        (
            "paused after retry without a paused session",
            json!({
                "rule": "logged-out", "action": "paused", "ran": true, "generation": 1,
                "login": "login", "login_job": 2, "login_flows": [11],
                "logged_out_flow": 3, "retried": true, "retry_flow": 9,
                "not_retried": null, "paused": false, "reason": "logged-out-again"
            }),
            false,
        ),
        (
            "paused after retry without a paused session (ran=false)",
            json!({
                "rule": "logged-out", "action": "paused", "ran": false, "generation": 1,
                "login": "login", "login_job": 2, "login_flows": [11],
                "logged_out_flow": 3, "retried": true, "retry_flow": 9,
                "not_retried": null, "paused": false, "reason": "logged-out-again"
            }),
            false,
        ),
        // A retry flow with no retry is a claim nothing supports.
        (
            "retry flow without a retry",
            json!({
                "rule": "logged-out", "action": "login-shared", "ran": false, "generation": 1,
                "login": "login", "login_job": null, "login_flows": [],
                "logged_out_flow": 3, "retried": false, "retry_flow": 9,
                "not_retried": null, "paused": false, "reason": null
            }),
            false,
        ),
    ];

    for (label, relogin, accepted) in table {
        // The frozen sender's own flow is the retry's when it retried and the
        // logged-out send's otherwise, so the row's flow is chosen the same
        // way and no other check decides the outcome.
        let own = if relogin["retried"].as_bool().unwrap() {
            relogin["retry_flow"].as_u64()
        } else {
            relogin["logged_out_flow"].as_u64()
        };
        let own = own.map_or(Value::Null, |flow| json!(flow));

        let mut send_reply = captured_send();
        send_reply["sent"]["flow"] = own.clone();
        send_reply["sent"]["hops"][0]["flow"] = own.clone();
        send_reply["sent"]["relogin"] = relogin.clone();
        write_output(root.path(), "send.json", &send_reply);
        let sent = wrapper.send(Method::Get, &url, &session, SendOptions::default());

        let mut run_reply = captured_macro_send();
        run_reply["run"]["steps"][0]["flow"] = own;
        run_reply["run"]["steps"][0]["relogin"] = relogin;
        write_output(root.path(), "run.json", &run_reply);
        let run = wrapper.run_macro(&name, &session, None);

        if accepted {
            let sent = sent.unwrap_or_else(|error| panic!("{label}: send: {error:?}"));
            assert_eq!(
                sent.value.relogin.as_ref().map(|relogin| relogin.action),
                Some(match label {
                    "recorded paused after retry" => ReloginAction::Paused,
                    "paused before this send (ran=false)" => ReloginAction::Paused,
                    "login-shared then retried" => ReloginAction::LoginShared,
                    _ => ReloginAction::ReLoggedIn,
                }),
                "{label}: send"
            );
            let run = run.unwrap_or_else(|error| panic!("{label}: macro: {error:?}"));
            assert_eq!(
                run.value.step(1).unwrap().dispatch(),
                sent.value.dispatch(),
                "{label}: both decoders bind the same send"
            );
        } else {
            let sent = sent
                .err()
                .unwrap_or_else(|| panic!("{label}: send accepted an impossible envelope"));
            check_diagnostic(&sent, DiagnosticCode::InvalidNativeOutput, Some(0), Some(0));
            let run = run
                .err()
                .unwrap_or_else(|| panic!("{label}: macro accepted an impossible envelope"));
            check_diagnostic(&run, DiagnosticCode::InvalidNativeOutput, Some(0), Some(0));
        }
    }

    // The recorded paused-after-retry reply keeps the original/login/retry
    // topology rather than being merely accepted.
    let retried_paused = recorded_relogin("session-GET ");
    let original = retried_paused["logged_out_flow"].as_u64().unwrap();
    let login = retried_paused["login_flows"][0].as_u64().unwrap();
    let retry = retried_paused["retry_flow"].as_u64().unwrap();
    let mut reply = captured_send();
    reply["sent"]["flow"] = json!(retry);
    reply["sent"]["hops"][0]["flow"] = json!(retry);
    reply["sent"]["relogin"] = retried_paused;
    write_output(root.path(), "send.json", &reply);
    let sent = wrapper
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    assert_eq!(
        sent.value.dispatch(),
        DispatchEvidence::Flow { flow: retry }
    );
    assert_eq!(
        sent.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(original),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(login),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Retry,
                reference: FlowReference::Retained(retry),
            },
        ]
    );
}

#[test]
fn send_options_are_bounded_and_never_become_shell_words() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(root.path(), r#"printf seen > "$HOME/received""#);
    let session = "alice".parse().unwrap();
    let url = "http://127.0.0.1:39381/probe".parse().unwrap();
    let headers = vec!["--session".to_owned()];
    assert_eq!(
        wrapper
            .send(
                Method::Get,
                &url,
                &session,
                SendOptions {
                    headers: &headers,
                    ..SendOptions::default()
                }
            )
            .unwrap_err()
            .code(),
        ErrorCode::UsageError
    );
    assert!(
        wrapper
            .send(
                Method::Get,
                &url,
                &session,
                SendOptions {
                    follow: Some(21),
                    ..SendOptions::default()
                }
            )
            .is_err()
    );
    assert!(!root.path().join("received").exists());
}

#[test]
fn literal_body_and_edit_values_are_never_teapot_file_sources() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"case "$4 $5" in
'version ') exec /bin/cat "$HOME/version.json" ;;
'requests send') printf '%s\n' "$@" > "$HOME/record-send"; exec /bin/cat "$HOME/send.json" ;;
'--yes flows') printf '%s\n' "$@" > "$HOME/record-replay"; exec /bin/cat "$HOME/replay.json" ;;
*) exit 20 ;;
esac"#,
    );
    write_output(root.path(), "version.json", &bound_version(root.path()));
    write_output(root.path(), "send.json", &captured_send());
    let macro_send = captured_macro_send();
    write_output(
        root.path(),
        "replay.json",
        &replay_output(
            &macro_send["run"]["steps"][0],
            &macro_send["run"]["steps"][1],
        ),
    );
    // A file the frozen Teapot reads for an `@FILE` argument (engine
    // commands/requests.rs `localize`, core edit/parse.rs `resolve`).
    let sentinel = root.path().join("target-secret");
    fs::write(&sentinel, b"SENTINEL-BYTES\n").unwrap();
    let reference = format!("@{}", sentinel.display());
    let escaped = format!("@{reference}");
    assert_ne!(reference, escaped);

    let session = "alice".parse().unwrap();
    let url = "http://127.0.0.1:39381/probe".parse().unwrap();
    let argument = |record: &str| -> Vec<String> {
        fs::read_to_string(root.path().join(record))
            .unwrap()
            .lines()
            .skip(3)
            .map(str::to_owned)
            .collect()
    };
    let value_after = |words: &[String], flag: &str| -> String {
        let at = words
            .iter()
            .position(|word| word == flag)
            .unwrap_or_else(|| panic!("{flag} is not in {words:?}"));
        words[at + 1].clone()
    };

    // A body and an edit whose literal text begins `@` must not reach Teapot
    // as a path source: `@x` becomes `@@x`, which Teapot reads as the text
    // `@x`, and the sentinel is never opened.
    let body = reference.clone();
    let edit = format!("json:note={reference}");
    wrapper
        .send(
            Method::Get,
            &url,
            &session,
            SendOptions {
                body: Some(&body),
                edits: &[edit],
                ..SendOptions::default()
            },
        )
        .unwrap();
    let words = argument("record-send");
    assert_eq!(value_after(&words, "--body"), escaped, "{words:?}");
    assert_eq!(
        value_after(&words, "--set"),
        format!("json:note={escaped}"),
        "{words:?}"
    );
    assert!(
        !words.contains(&reference),
        "a bare @FILE reached argv: {words:?}"
    );
    assert!(
        !words.contains(&format!("json:note={reference}")),
        "a bare @FILE edit reached argv: {words:?}"
    );

    // `@-` is standard input and `@@x` is already the literal `@x`: both take
    // one more `@` so the text survives exactly.
    for (given, expected) in [("@-", "@@-"), ("@@x", "@@@x"), ("@", "@@")] {
        let body = given.to_owned();
        wrapper
            .send(
                Method::Get,
                &url,
                &session,
                SendOptions {
                    body: Some(&body),
                    ..SendOptions::default()
                },
            )
            .unwrap();
        let words = argument("record-send");
        assert_eq!(value_after(&words, "--body"), expected, "{given}");
    }

    // The replay's `--set` takes the same encoding.
    let edit = format!("json:note={reference}");
    wrapper
        .replay_macro(&"plant".parse().unwrap(), &session, 2, &[edit])
        .unwrap();
    let words = argument("record-replay");
    assert_eq!(
        value_after(&words, "--set"),
        format!("json:note={escaped}"),
        "{words:?}"
    );
    assert!(
        !words.contains(&format!("json:note={reference}")),
        "{words:?}"
    );

    // `path:` and `method:` take the whole text after the colon as the value
    // (dropping one optional `=`), so a no-equals `@FILE` is a source too
    // (`edit/parse.rs`: `rest.strip_prefix('=').unwrap_or(rest)`). Each form
    // is escaped on send and on replay, and the grammar is preserved.
    for (given, expected) in [
        (format!("path:{reference}"), format!("path:{escaped}")),
        (format!("method:{reference}"), format!("method:{escaped}")),
        (format!("path:={reference}"), format!("path:={escaped}")),
        (format!("method:={reference}"), format!("method:={escaped}")),
    ] {
        wrapper
            .send(
                Method::Get,
                &url,
                &session,
                SendOptions {
                    edits: std::slice::from_ref(&given),
                    ..SendOptions::default()
                },
            )
            .unwrap();
        let words = argument("record-send");
        assert_eq!(value_after(&words, "--set"), expected, "{given}");
        assert!(
            !words.contains(&given),
            "a bare @FILE {given} reached argv: {words:?}"
        );

        wrapper
            .replay_macro(
                &"plant".parse().unwrap(),
                &session,
                2,
                std::slice::from_ref(&given),
            )
            .unwrap();
        let words = argument("record-replay");
        assert_eq!(value_after(&words, "--set"), expected, "{given}");
        assert!(
            !words.contains(&given),
            "a bare @FILE {given} reached argv: {words:?}"
        );
    }

    // A source-free removal has no value to resolve, and `path:/a=b` is one
    // path rather than a value after an `=`: both stay byte-identical.
    for given in [
        "json-:csrf",
        "form-:x",
        "query-:q",
        "cookie-:c",
        "path:/a=b",
    ] {
        let given = given.to_owned();
        wrapper
            .send(
                Method::Get,
                &url,
                &session,
                SendOptions {
                    edits: std::slice::from_ref(&given),
                    ..SendOptions::default()
                },
            )
            .unwrap();
        let words = argument("record-send");
        assert_eq!(value_after(&words, "--set"), given.as_str(), "{given}");
    }

    // A NUL cannot be in argv: it is a usage error here, never a spawn
    // failure that would read as a missing tool.
    fs::remove_file(root.path().join("record-send")).unwrap();
    for options in [
        SendOptions {
            body: Some("a\0b"),
            ..SendOptions::default()
        },
        SendOptions {
            edits: &["json:note=a\0b".to_owned()],
            ..SendOptions::default()
        },
        SendOptions {
            headers: &["X-Note: a\0b".to_owned()],
            ..SendOptions::default()
        },
    ] {
        assert_eq!(
            wrapper
                .send(Method::Get, &url, &session, options)
                .unwrap_err()
                .code(),
            ErrorCode::UsageError
        );
    }
    assert!(
        !root.path().join("record-send").exists(),
        "a NUL-bearing argument was spawned"
    );
}

#[test]
fn send_transport_overflow_is_typed_without_decoding_oversized_output() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"case "$4" in
version) exec /bin/cat "$HOME/version.json" ;;
requests) exec /usr/bin/yes 'sensitive native output' ;;
*) exit 20 ;;
esac"#,
    );
    write_output(root.path(), "version.json", &bound_version(root.path()));
    let session = "alice".parse().unwrap();
    let url = "http://127.0.0.1:39381/probe".parse().unwrap();
    assert!(matches!(
        wrapper
            .send(Method::Get, &url, &session, SendOptions::default())
            .unwrap_err(),
        InvocationError::DependencyUnavailable {
            transport_failure: Some(TransportFailure::OutputLimit(OutputStream::Stdout)),
            ..
        }
    ));
}

#[test]
fn macro_run_binds_login_and_retry_flows_to_the_step_that_caused_them() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"case "$4 $5" in
'version ') exec /bin/cat "$HOME/version.json" ;;
'--yes macros') printf '%s\n' "$@" > "$HOME/record"; exec /bin/cat "$HOME/run.json" ;;
*) exit 20 ;;
esac"#,
    );
    write_output(root.path(), "version.json", &bound_version(root.path()));
    let mut output = captured_macro_send();
    // The frozen shape: a retried step's own flow is the retry, and
    // `logged_out_flow` is the send that was answered logged-out.
    output["run"]["steps"][0]["flow"] = json!(9);
    output["run"]["steps"][0]["relogin"] = json!({
        "rule": "logged-out", "action": "re-logged-in", "ran": true, "generation": 1,
        "login": "login", "login_job": 1, "login_flows": [7, 8],
        "logged_out_flow": 4, "retried": true, "retry_flow": 9,
        "not_retried": null, "paused": false, "reason": null
    });
    write_output(root.path(), "run.json", &output);

    let name = "plant".parse().unwrap();
    let session = "alice".parse().unwrap();
    let run = wrapper.run_macro(&name, &session, None).unwrap();
    assert_eq!(run.value.outcome, MacroOutcome::Completed);
    assert_eq!(run.value.job, Some(1));
    assert_eq!(run.value.units, 2);
    assert_eq!(run.value.steps.len(), 2);
    assert_eq!(
        run.value.step(1).unwrap().dispatch(),
        DispatchEvidence::Flow { flow: 9 }
    );
    assert_eq!(
        run.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(4),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(7),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(8),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Retry,
                reference: FlowReference::Retained(9),
            },
            StepFlow {
                step: 2,
                role: FlowRole::Request,
                reference: FlowReference::Retained(5),
            },
        ]
    );
    let argv = fs::read_to_string(root.path().join("record")).unwrap();
    assert_eq!(
        argv.lines().skip(3).collect::<Vec<_>>(),
        ["--yes", "macros", "run", "plant", "--session", "alice"]
    );

    // Capture lost for the retry: the step was sent again and no flow was
    // kept for the retry, so its reference is missing, never "not sent".
    let mut lost = output.clone();
    lost["run"]["steps"][0]["flow"] = Value::Null;
    lost["run"]["steps"][0]["relogin"]["retry_flow"] = Value::Null;
    write_output(root.path(), "run.json", &lost);
    let run = wrapper.run_macro(&name, &session, None).unwrap();
    assert_eq!(
        run.value.step(1).unwrap().dispatch(),
        DispatchEvidence::NoFlow {
            outcome: SendOutcome::Complete
        }
    );
    assert_eq!(
        run.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(4),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(7),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(8),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Retry,
                reference: FlowReference::Missing,
            },
            StepFlow {
                step: 2,
                role: FlowRole::Request,
                reference: FlowReference::Retained(5),
            },
        ]
    );

    // The repository-recorded paused-after-retry shape bound to a step: the
    // step's own flow is the retry, and the original request and the login
    // flow stay separate sends.
    let paused_after_retry = recorded_relogin("session-GET ");
    let original = paused_after_retry["logged_out_flow"].as_u64().unwrap();
    let login = paused_after_retry["login_flows"][0].as_u64().unwrap();
    let retry = paused_after_retry["retry_flow"].as_u64().unwrap();
    let mut recorded = captured_macro_send();
    recorded["run"]["steps"][0]["flow"] = json!(retry);
    recorded["run"]["steps"][0]["relogin"] = paused_after_retry;
    write_output(root.path(), "run.json", &recorded);
    let run = wrapper.run_macro(&name, &session, None).unwrap();
    assert_eq!(
        run.value
            .step(1)
            .unwrap()
            .relogin
            .as_ref()
            .map(|relogin| relogin.action),
        Some(ReloginAction::Paused)
    );
    assert_eq!(
        run.value.step(1).unwrap().dispatch(),
        DispatchEvidence::Flow { flow: retry }
    );
    assert_eq!(
        run.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(original),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Login,
                reference: FlowReference::Retained(login),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Retry,
                reference: FlowReference::Retained(retry),
            },
            StepFlow {
                step: 2,
                role: FlowRole::Request,
                reference: FlowReference::Retained(5),
            },
        ]
    );

    // A retried step whose own flow is not the retry's is contradictory.
    let mut mismatched_retry = output.clone();
    mismatched_retry["run"]["steps"][0]["relogin"]["retry_flow"] = json!(10);
    write_output(root.path(), "run.json", &mismatched_retry);
    check_diagnostic(
        &wrapper.run_macro(&name, &session, None).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    // An unbounded successful run sends every step. A `refused`, `not-run`,
    // `stopped`, `unknown` or `failed` row is what a stopped run looks like,
    // and Teapot exits such a run as an error envelope: an impossible success
    // is rejected, never read as proof that nothing was dispatched.
    for index in [0, 1] {
        for bad in ["refused", "not-run", "stopped", "unknown", "failed"] {
            let mut output = captured_macro_send();
            output["run"]["steps"][index]["outcome"] = json!(bad);
            // A step that was not sent has no flow and no response.
            output["run"]["steps"][index]["flow"] = Value::Null;
            output["run"]["steps"][index]["status"] = Value::Null;
            output["run"]["units"] = json!(1);
            output["run"]["state_changing"] = json!(if index == 0 { vec![2] } else { vec![] });
            write_output(root.path(), "run.json", &output);
            check_diagnostic(
                &wrapper.run_macro(&name, &session, None).unwrap_err(),
                DiagnosticCode::InvalidNativeOutput,
                Some(0),
                Some(0),
            );
        }
    }

    // A flow on a step the instrument says was not sent is contradictory.
    let mut contradictory = captured_macro_send();
    contradictory["run"]["steps"][1]["outcome"] = json!("refused");
    contradictory["run"]["units"] = json!(1);
    write_output(root.path(), "run.json", &contradictory);
    check_diagnostic(
        &wrapper.run_macro(&name, &session, None).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    // `--until N` sends the prefix `1..=N` only: a second sent step past the
    // bound is extra traffic, and the outcome must say the run stopped there.
    write_output(root.path(), "run.json", &captured_macro_send());
    check_diagnostic(
        &wrapper.run_macro(&name, &session, Some(1)).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );
    let mut two_sent = captured_macro_send();
    two_sent["run"]["outcome"] = json!("until");
    write_output(root.path(), "run.json", &two_sent);
    check_diagnostic(
        &wrapper.run_macro(&name, &session, Some(1)).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    let mut wrong_units = captured_macro_send();
    wrong_units["run"]["units"] = json!(1);
    write_output(root.path(), "run.json", &wrong_units);
    check_diagnostic(
        &wrapper.run_macro(&name, &session, None).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    let mut until = captured_macro_send();
    until["run"]["outcome"] = json!("until");
    until["run"]["units"] = json!(1);
    until["run"]["state_changing"] = json!([]);
    until["run"]["steps"][1]["outcome"] = json!("not-run");
    until["run"]["steps"][1]["flow"] = Value::Null;
    until["run"]["steps"][1]["status"] = Value::Null;
    until["run"]["steps"][1]["class"] = Value::Null;
    write_output(root.path(), "run.json", &until);
    let run = wrapper.run_macro(&name, &session, Some(1)).unwrap();
    assert_eq!(run.value.outcome, MacroOutcome::Until);
    assert_eq!(
        run.value.step(2).unwrap().dispatch(),
        DispatchEvidence::NotSent {
            reason: NotSentReason::NotRun
        },
        "only a step past `--until` is a recorded non-send"
    );
    let argv = fs::read_to_string(root.path().join("record")).unwrap();
    assert_eq!(
        argv.lines().skip(3).collect::<Vec<_>>(),
        [
            "--yes",
            "macros",
            "run",
            "plant",
            "--session",
            "alice",
            "--until",
            "1"
        ]
    );

    // A not-run suffix row is exactly what frozen `StepReport::new` writes: no
    // answer-derived field at all, so `MacroRun::flows` cannot report traffic
    // for a step the same reply calls `NotSent{NotRun}`.
    for (field, value) in [
        ("status", json!(201)),
        ("flow", json!(66)),
        ("class", json!("2xx")),
        ("reason", json!("logged-out")),
        ("set", json!([{"name": "csrf", "len": 9, "by": "extract"}])),
        ("withheld", json!(["X-Trace"])),
        ("csrf_refreshed", json!(["csrf"])),
        (
            "relogin",
            json!({
                "rule": "logged-out", "action": "reported", "ran": false, "generation": 1,
                "login": "login", "login_job": null, "login_flows": [77],
                "logged_out_flow": null, "retried": false, "retry_flow": null,
                "not_retried": "no-login", "paused": false, "reason": null
            }),
        ),
    ] {
        let mut output = until.clone();
        output["run"]["steps"][1][field] = value;
        write_output(root.path(), "run.json", &output);
        check_diagnostic(
            &wrapper.run_macro(&name, &session, Some(1)).unwrap_err(),
            DiagnosticCode::InvalidNativeOutput,
            Some(0),
            Some(0),
        );
    }

    // Declaration metadata is not answer-derived: it may remain on a not-run
    // row, and `flows` stays empty for it.
    let mut declared = until.clone();
    declared["run"]["steps"][1]["references"] = json!(["csrf"]);
    declared["run"]["steps"][1]["compute"] = json!("1 + 1");
    write_output(root.path(), "run.json", &declared);
    let run = wrapper.run_macro(&name, &session, Some(1)).unwrap();
    assert_eq!(
        run.value.step(2).unwrap().dispatch(),
        DispatchEvidence::NotSent {
            reason: NotSentReason::NotRun
        }
    );
    assert!(run.value.flows().iter().all(|flow| flow.step == 1));

    // `--until` that reaches the last step reports `completed`.
    write_output(root.path(), "run.json", &captured_macro_send());
    let run = wrapper.run_macro(&name, &session, Some(2)).unwrap();
    assert_eq!(run.value.outcome, MacroOutcome::Completed);
    assert_eq!(run.value.units, 2);

    // The bound is the caller's, so a reply that ran past it is refused.
    check_diagnostic(
        &wrapper.run_macro(&name, &session, Some(1)).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    // `until` without the bound is an outcome a live run cannot report, and
    // so is `--until 2` on the reply a `--until 1` run produced.
    write_output(root.path(), "run.json", &until);
    check_diagnostic(
        &wrapper.run_macro(&name, &session, None).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );
    check_diagnostic(
        &wrapper.run_macro(&name, &session, Some(2)).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    // Steps past the bound are not-run with no flow and no status.
    let mut sent_past = until.clone();
    sent_past["run"]["steps"][1]["flow"] = json!(5);
    sent_past["run"]["steps"][1]["status"] = json!(201);
    write_output(root.path(), "run.json", &sent_past);
    check_diagnostic(
        &wrapper.run_macro(&name, &session, Some(1)).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    // Teapot refuses `--until` past the last step as a usage error.
    write_output(root.path(), "run.json", &until);
    check_diagnostic(
        &wrapper.run_macro(&name, &session, Some(3)).unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        Some(0),
        Some(0),
    );

    assert_eq!(
        wrapper
            .run_macro(&name, &session, Some(0))
            .unwrap_err()
            .code(),
        ErrorCode::UsageError
    );
    assert_eq!(
        wrapper
            .run_macro(&"--x".parse().unwrap(), &session, None)
            .unwrap_err()
            .code(),
        ErrorCode::UsageError
    );
}

#[test]
fn macro_replay_requires_an_edit_and_keeps_the_replayed_step_distinct() {
    let root = tempfile::tempdir().unwrap();
    let wrapper = bound_wrapper(
        root.path(),
        r#"case "$4 $5" in
'version ') exec /bin/cat "$HOME/version.json" ;;
'--yes flows') printf '%s\n' "$@" > "$HOME/record"; exec /bin/cat "$HOME/replay.json" ;;
*) exit 20 ;;
esac"#,
    );
    write_output(root.path(), "version.json", &bound_version(root.path()));
    let macro_send = captured_macro_send();
    let step_one = macro_send["run"]["steps"][0].clone();
    let step_two = macro_send["run"]["steps"][1].clone();
    write_output(
        root.path(),
        "replay.json",
        &replay_output(&step_one, &step_two),
    );

    let name = "plant".parse().unwrap();
    let session = "alice".parse().unwrap();
    let edits = vec!["json:note=\"replay\"".to_owned()];
    let replay = wrapper.replay_macro(&name, &session, 2, &edits).unwrap();
    assert_eq!(replay.value.parent, 0);
    assert_eq!(replay.value.status, Some(201));
    assert_eq!(replay.value.dispatch(), DispatchEvidence::Flow { flow: 5 });
    assert_eq!(replay.value.replay.preparatory.len(), 1);
    assert_eq!(replay.value.replay.replayed.step, 2);
    assert_eq!(
        replay.value.replay.replaced,
        ["json:note"],
        "the reply keeps the replaced substitution locations"
    );
    assert_eq!(
        replay.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(4),
            },
            StepFlow {
                step: 2,
                role: FlowRole::Request,
                reference: FlowReference::Retained(5),
            },
        ]
    );
    let argv = fs::read_to_string(root.path().join("record")).unwrap();
    assert_eq!(
        argv.lines().skip(3).collect::<Vec<_>>(),
        [
            "--yes",
            "flows",
            "replay",
            "--macro",
            "plant",
            "--step",
            "2",
            "--session",
            "alice",
            "--set",
            "json:note=\"replay\""
        ]
    );

    // Capture off: the replay was still sent, but neither the outer ID nor
    // the replayed step has a flow.
    let mut missing = replay_output(&step_one, &step_two);
    missing["flow"]["id"] = Value::Null;
    missing["flow"]["macro_replay"]["replayed"]["flow"] = Value::Null;
    write_output(root.path(), "replay.json", &missing);
    let replay = wrapper.replay_macro(&name, &session, 2, &edits).unwrap();
    assert_eq!(
        replay.value.dispatch(),
        DispatchEvidence::NoFlow {
            outcome: SendOutcome::Complete
        }
    );
    assert!(replay.value.dispatch().was_sent());

    for (pointer, bad) in [
        ("/flow/id", json!(4)),
        ("/flow/parent", json!(4)),
        ("/flow/macro_replay/units", json!(1)),
        ("/flow/macro_replay/preparatory", json!([])),
        ("/flow/macro_replay/replayed/flow", Value::Null),
    ] {
        let mut output = replay_output(&step_one, &step_two);
        *output.pointer_mut(pointer).unwrap() = bad;
        write_output(root.path(), "replay.json", &output);
        check_diagnostic(
            &wrapper
                .replay_macro(&name, &session, 2, &edits)
                .unwrap_err(),
            DiagnosticCode::InvalidNativeOutput,
            Some(0),
            Some(0),
        );
    }
    let mut schema_invalid = replay_output(&step_one, &step_two);
    schema_invalid["flow"]["flows"] = json!([{"kind": "replay"}]);
    write_output(root.path(), "replay.json", &schema_invalid);
    check_diagnostic(
        &wrapper
            .replay_macro(&name, &session, 2, &edits)
            .unwrap_err(),
        DiagnosticCode::InvalidNativeOutput,
        None,
        Some(0),
    );

    fs::remove_file(root.path().join("record")).unwrap();
    assert_eq!(
        wrapper
            .replay_macro(&name, &session, 2, &[])
            .unwrap_err()
            .code(),
        ErrorCode::UsageError
    );
    assert_eq!(
        wrapper
            .replay_macro(&name, &session, 2, &["--set".to_owned()])
            .unwrap_err()
            .code(),
        ErrorCode::UsageError
    );
    assert!(!root.path().join("record").exists());
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

struct FixtureRequest {
    method: String,
    path: String,
    headers: Vec<String>,
    body: Vec<u8>,
}

struct Fixture {
    url: String,
    port: u16,
    requests: Arc<Mutex<Vec<FixtureRequest>>>,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://{address}/probe");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = Arc::clone(&stop);
        let server_requests = Arc::clone(&requests);
        let task = thread::spawn(move || {
            while !stop_server.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut reader = BufReader::new((&stream).take(1 << 20));
                        let mut request_line = String::new();
                        reader.read_line(&mut request_line).unwrap();
                        let mut words = request_line.split_whitespace();
                        let method = words.next().unwrap_or_default().to_owned();
                        let path = words.next().unwrap_or_default().to_owned();
                        let mut names = Vec::new();
                        let mut length = 0;
                        loop {
                            let mut line = String::new();
                            if reader.read_line(&mut line).unwrap() == 0 {
                                break;
                            }
                            let line = line.trim_end_matches(['\r', '\n']);
                            if line.is_empty() {
                                break;
                            }
                            let (name, value) = line.split_once(':').unwrap();
                            names.push(name.to_ascii_lowercase());
                            if name.eq_ignore_ascii_case("content-length") {
                                length = value.trim().parse::<usize>().unwrap();
                            }
                        }
                        let mut body = vec![0; length];
                        reader.read_exact(&mut body).unwrap();
                        server_requests.lock().unwrap().push(FixtureRequest {
                            method: method.clone(),
                            path: path.clone(),
                            headers: names,
                            body,
                        });
                        let (status, location, body) = match (method.as_str(), path.as_str()) {
                            ("GET", "/probe") => ("200 OK", None, b"{}".to_vec()),
                            ("POST", "/plant") => {
                                ("201 Created", None, br#"{"id":"fixture"}"#.to_vec())
                            }
                            ("GET", "/redirect") => ("302 Found", Some("/probe"), Vec::new()),
                            ("GET", "/chain") => ("302 Found", Some("/redirect"), Vec::new()),
                            _ => ("404 Not Found", None, b"{}".to_vec()),
                        };
                        write!(
                            stream,
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n",
                            body.len()
                        )
                        .unwrap();
                        if let Some(location) = location {
                            write!(stream, "Location: {location}\r\n").unwrap();
                        }
                        write!(stream, "Connection: close\r\n\r\n").unwrap();
                        stream.write_all(&body).unwrap();
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
            requests,
            stop,
            task: Some(task),
        }
    }

    fn requests(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn recorded(&self) -> Vec<(String, String, Vec<u8>)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| {
                (
                    request.method.clone(),
                    request.path.clone(),
                    request.body.clone(),
                )
            })
            .collect()
    }

    fn assert_credential_free_session_probes(&self) {
        let requests = self.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            for name in [
                "authorization",
                "proxy-authorization",
                "cookie",
                "x-api-key",
            ] {
                assert!(
                    !request.headers.iter().any(|header| header == name),
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
    let reference_manifest: Value = serde_json::from_str(include_str!(
        "../../../fixtures/contracts/request-reference-manifest.json"
    ))
    .unwrap();
    let binary_digest = Sha256Digest::of(&fs::read(&binary).unwrap());
    assert!(
        [
            manifest["binary_sha256"].as_str().unwrap(),
            reference_manifest["binary_sha256"].as_str().unwrap(),
        ]
        .contains(&binary_digest.as_str()),
        "the Teapot executable must match a frozen historical or request-reference contract"
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
        ..bound.clone()
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

    let flow_id = check.evidence.result()["session_flow"].as_u64().unwrap();
    let read = teapot.read_flow(flow_id, None).unwrap();
    assert_eq!(read.value.id, flow_id);
    assert_eq!(read.value.url.as_deref(), Some(fixture.url.as_str()));
    assert!(read.value.elapsed_ms.is_some());
    assert_eq!(read.value.state, "complete");
    assert!(
        read.value
            .request
            .rendered_head
            .unwrap()
            .starts_with("GET /probe ")
    );
    let response = read.value.response.body.unwrap();
    assert!(response.whole);
    assert_eq!(response.bytes.unwrap(), b"{}");
    let partial = teapot
        .read_flow(flow_id, Some(BodyWindow::new(1, 1).unwrap()))
        .unwrap();
    let body = partial.value.response.body.unwrap();
    assert!(!body.whole);
    assert_eq!(body.offset, 1);
    assert_eq!(body.captured, 2);
    assert_eq!(body.bytes.unwrap(), b"}");
    assert_eq!(
        fixture.requests(),
        2,
        "reading a stored flow sent target traffic"
    );

    // The fixture owns this database. Seed a terminal job so the pinned
    // binary's exact-ID and idempotent stop paths need no active job setup.
    let db = rusqlite::Connection::open(project.project.join(".teapot/project.db")).unwrap();
    db.execute(
        "INSERT INTO jobs (id, kind, state, instance, started_at, ended_at)
         VALUES (41, 'macro-run', 'completed', ?1, 0, 1000000000)",
        [bound.instance.as_str()],
    )
    .unwrap();
    drop(db);
    let job = owned_job(41, bound);
    for _ in 0..2 {
        let canceled = teapot.cancel(&job).unwrap();
        assert_eq!(
            canceled.acknowledgment.value,
            CancelAcknowledgment::EndedWithoutStop
        );
        let observed = canceled.observation.unwrap().value.unwrap();
        assert_eq!(observed.id, 41);
        assert_eq!(observed.state, "completed");
        assert!(observed.is_terminal());
    }
    assert_eq!(
        fixture.requests(),
        2,
        "canceling a terminal job sent target traffic"
    );

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
fn pinned_send_macro_replay_and_capture_off_match_the_frozen_variants() {
    let mut project = pinned_project();
    let fixture = Fixture::start();
    let engine = project.start(&[]);
    let teapot = project.bind(engine);
    project.run(&["scope", "add", "127.0.0.1"]);
    project.run(&["sessions", "create", "alice"]);
    fs::write(
        project.project.join(".teapot/macros/plant.toml"),
        format!(
            "format = 1\n\n[[steps]]\nstate_changing = false\n[steps.request]\nmethod = \"GET\"\nurl = {:?}\n\n[[steps]]\nstate_changing = true\n[steps.request]\nmethod = \"POST\"\nurl = {:?}\nheaders = [[\"Content-Type\", \"application/json\"]]\nbody = {{ text = '{{\"note\":\"\"}}' }}\n",
            fixture.url,
            format!("http://127.0.0.1:{}/plant", fixture.port),
        ),
    )
    .unwrap();

    let session = "alice".parse().unwrap();
    let url = fixture.url.parse().unwrap();
    let sent = teapot
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    let flow = sent
        .value
        .dispatch()
        .flow()
        .expect("a captured send has its frozen per-send reference");
    assert_eq!(sent.value.session.source, SessionSource::Flag);
    // The pinned fixture never rotates a session to logged-out, so a real
    // reply carries no `relogin` object. That is asserted rather than assumed,
    // so the tightened retry-state validation is known to accept real output
    // and no login claim is invented for a send that had none (the recorded
    // `channel-observed.txt` replies anchor the shapes that do carry one).
    assert!(sent.value.relogin.is_none());
    assert_eq!(
        sent.value.destination,
        format!("http://127.0.0.1:{}", fixture.port)
    );
    assert_eq!(fixture.requests(), 1);
    let read = teapot.read_flow(flow, None).unwrap();
    assert_eq!(read.value.id, flow);
    assert_eq!(read.value.destination, Some(sent.value.destination.clone()));
    assert_eq!(read.value.method.as_deref(), Some("GET"));
    assert_eq!(read.value.status, Some(200));
    assert_eq!(read.value.origin, "replay");
    assert!(read.value.elapsed_ms.is_some());
    assert_eq!(read.value.response.body.unwrap().bytes.unwrap(), b"{}");
    assert_eq!(
        fixture.requests(),
        1,
        "reading a stored send flow sent target traffic"
    );

    let plant = "plant".parse().unwrap();
    let run = teapot.run_macro(&plant, &session, None).unwrap();
    assert_eq!(run.value.outcome, MacroOutcome::Completed);
    assert_eq!(run.value.units, 2);
    assert_eq!(run.value.steps.len(), 2);
    assert!(run.value.steps.iter().all(|step| step.relogin.is_none()));
    assert!(run.value.step(1).unwrap().dispatch().flow().is_some());
    let second = run
        .value
        .step(2)
        .unwrap()
        .dispatch()
        .flow()
        .expect("the declared plant's second step is captured");
    assert_eq!(run.value.flows().len(), 2);
    let read = teapot.read_flow(second, None).unwrap();
    assert_eq!(read.value.method.as_deref(), Some("POST"));
    assert_eq!(read.value.status, Some(201));
    assert_eq!(
        read.value.response.body.unwrap().bytes.unwrap(),
        br#"{"id":"fixture"}"#
    );
    assert_eq!(
        read.value.request.body.unwrap().bytes.unwrap(),
        br#"{"note":""}"#
    );

    let edits = vec!["json:note=\"replay\"".to_owned()];
    let replay = teapot.replay_macro(&plant, &session, 2, &edits).unwrap();
    assert_eq!(replay.value.parent, 0);
    assert_eq!(replay.value.replay.preparatory.len(), 1);
    assert_eq!(replay.value.replay.replayed.step, 2);
    assert_eq!(replay.value.replay.units, 2);
    assert!(replay.value.replay.replayed.relogin.is_none());
    assert_eq!(replay.value.flows().len(), 2);
    let replayed = replay
        .value
        .dispatch()
        .flow()
        .expect("the replayed step is captured");
    let read = teapot.read_flow(replayed, None).unwrap();
    assert_eq!(read.value.method.as_deref(), Some("POST"));
    assert_eq!(read.value.status, Some(201));
    assert_eq!(
        read.value.response.body.unwrap().bytes.unwrap(),
        br#"{"id":"fixture"}"#
    );
    assert_eq!(
        read.value.request.body.unwrap().bytes.unwrap(),
        br#"{"note":"replay"}"#
    );
    assert_eq!(
        replay
            .value
            .flows()
            .iter()
            .map(|flow| flow.step)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    let recorded = fixture.recorded();
    assert_eq!(recorded.len(), 5);
    assert_eq!(
        (recorded[2].0.as_str(), recorded[2].1.as_str()),
        ("POST", "/plant")
    );
    assert_eq!(recorded[2].2, br#"{"note":""}"#.to_vec());
    assert_eq!(recorded[4].2, br#"{"note":"replay"}"#.to_vec());

    // Capture off: the request still reaches the target, but the frozen reply
    // has no flow ID. The adapter keeps that as a sent no-flow, not as a
    // recorded non-send.
    assert!(project.stop());
    project.run(&["config", "set", "budget.min-free-mib", "1099511627776"]);
    let engine = project.start(&[]);
    let teapot = project.bind(engine);
    let before = fixture.requests();
    let sent = teapot
        .send(Method::Get, &url, &session, SendOptions::default())
        .unwrap();
    assert_eq!(
        sent.value.dispatch(),
        DispatchEvidence::NoFlow {
            outcome: SendOutcome::Complete
        }
    );
    assert!(sent.value.dispatch().was_sent());
    assert!(!sent.value.dispatch().is_not_sent());
    assert_eq!(sent.value.flow, None);
    assert_eq!(fixture.requests(), before + 1);
    assert!(project.stop());
}

#[test]
#[ignore = "requires SCOURGE_PINNED_TEAPOT and a disposable loopback listener"]
fn pinned_follow_until_and_literal_at_values_match_the_frozen_replies() {
    let mut project = pinned_project();
    let fixture = Fixture::start();
    let engine = project.start(&[]);
    let teapot = project.bind(engine);
    project.run(&["scope", "add", "127.0.0.1"]);
    project.run(&["sessions", "create", "alice"]);
    fs::write(
        project.project.join(".teapot/macros/plant.toml"),
        format!(
            "format = 1\n\n[[steps]]\nstate_changing = false\n[steps.request]\nmethod = \"GET\"\nurl = {:?}\n\n[[steps]]\nstate_changing = true\n[steps.request]\nmethod = \"POST\"\nurl = {:?}\nheaders = [[\"Content-Type\", \"application/json\"]]\nbody = {{ text = '{{\"note\":\"\"}}' }}\n",
            fixture.url,
            format!("http://127.0.0.1:{}/plant", fixture.port),
        ),
    )
    .unwrap();
    let session = "alice".parse().unwrap();
    let base = format!("http://127.0.0.1:{}", fixture.port);

    // The caller's `--follow` is the bound: without it one hop, with N at most
    // N redirects. Both the stopped and the whole chain are real replies.
    let chain = format!("{base}/chain").parse().unwrap();
    let sent = teapot
        .send(Method::Get, &chain, &session, SendOptions::default())
        .unwrap();
    assert_eq!(sent.value.hops.len(), 1, "no --follow sends one request");
    assert_eq!(sent.value.status, Some(302));
    let sent = teapot
        .send(
            Method::Get,
            &chain,
            &session,
            SendOptions {
                follow: Some(1),
                ..SendOptions::default()
            },
        )
        .unwrap();
    assert_eq!(sent.value.hops.len(), 2, "--follow 1 follows one redirect");
    assert_eq!(sent.value.status, Some(302));
    assert_ne!(sent.value.hops[0].flow, sent.value.hops[1].flow);
    let first = sent.value.hops[0].flow.unwrap();
    let second = sent.value.hops[1].flow.unwrap();
    assert_eq!(
        sent.value.flows(),
        [
            StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Retained(first),
            },
            StepFlow {
                step: 1,
                role: FlowRole::Redirect,
                reference: FlowReference::Retained(second),
            },
        ]
    );
    let sent = teapot
        .send(
            Method::Get,
            &chain,
            &session,
            SendOptions {
                follow: Some(2),
                ..SendOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        sent.value.hops.len(),
        3,
        "--follow 2 follows the whole chain"
    );
    assert_eq!(sent.value.status, Some(200));

    // `--until 1` on a two-step macro: the prefix is sent, the rest is
    // not-run, and the run says it stopped there. The whole macro sends both.
    let plant = "plant".parse().unwrap();
    let bounded = teapot.run_macro(&plant, &session, Some(1)).unwrap();
    assert_eq!(bounded.value.outcome, MacroOutcome::Until);
    assert_eq!(bounded.value.units, 1);
    assert!(bounded.value.step(1).unwrap().dispatch().flow().is_some());
    assert_eq!(
        bounded.value.step(2).unwrap().dispatch(),
        DispatchEvidence::NotSent {
            reason: NotSentReason::NotRun
        }
    );
    let run = teapot.run_macro(&plant, &session, None).unwrap();
    assert_eq!(run.value.outcome, MacroOutcome::Completed);
    assert_eq!(run.value.units, 2);
    assert!(
        run.value
            .steps
            .iter()
            .all(|step| step.dispatch().flow().is_some())
    );

    // Literal `@` values: Teapot reads `@FILE` from the caller's side, so a
    // verifier's literal bytes must arrive as text. A readable sentinel
    // proves the bytes are not exfiltrated, and a path that cannot be read
    // proves no source was opened at all (an unescaped one would exit 1).
    let sentinel = project.project.join("literal-at-sentinel");
    fs::write(&sentinel, b"SENTINEL-BYTES").unwrap();
    let missing = "scourge-witness-does-not-exist";
    let probe = fixture.url.parse().unwrap();
    for literal in [
        format!("@{}", sentinel.display()),
        format!("@/{missing}"),
        "@-".to_owned(),
        "@@x".to_owned(),
    ] {
        let before = fixture.requests();
        let sent = teapot
            .send(
                Method::Get,
                &probe,
                &session,
                SendOptions {
                    body: Some(&literal),
                    ..SendOptions::default()
                },
            )
            .unwrap();
        assert!(sent.value.dispatch().flow().is_some());
        let recorded = fixture.recorded();
        assert_eq!(recorded.len(), before + 1);
        assert_eq!(
            recorded.last().unwrap().2,
            literal.as_bytes(),
            "the target received {literal:?} as text"
        );
    }
    assert_eq!(fs::read(&sentinel).unwrap(), b"SENTINEL-BYTES");

    // The same for a `--set` value: the JSON body carries the literal text.
    let edit = format!("json:note=@/{missing}");
    let plant_url = format!("{base}/plant").parse().unwrap();
    teapot
        .send(
            Method::Post,
            &plant_url,
            &session,
            SendOptions {
                body: Some("{\"note\":\"\"}"),
                edits: &[edit],
                ..SendOptions::default()
            },
        )
        .unwrap();
    let recorded = fixture.recorded();
    assert_eq!(
        recorded.last().unwrap().2,
        format!("{{\"note\":\"@/{missing}\"}}").into_bytes()
    );

    // And on the replay's `--set`, which is the other variant that takes one.
    let replay_edit = format!("json:note=@/{missing}");
    let replay = teapot
        .replay_macro(&plant, &session, 2, &[replay_edit])
        .unwrap();
    assert!(replay.value.dispatch().flow().is_some());
    let recorded = fixture.recorded();
    assert_eq!(
        recorded.last().unwrap().2,
        format!("{{\"note\":\"@/{missing}\"}}").into_bytes()
    );

    // A no-equals `path:` or `method:` edit is a source in the frozen parser
    // too. A sentinel that holds a *valid* value is the witness: unescaped,
    // Teapot would read it and the request would go out; escaped, the literal
    // text is validated and refused, so the target sees no traffic at all.
    let path_source = project.project.join("literal-path-source");
    fs::write(&path_source, b"/scourge-from-file").unwrap();
    let method_source = project.project.join("literal-method-source");
    fs::write(&method_source, b"PATCH").unwrap();
    for (edit, forged) in [
        (
            format!("path:@{}", path_source.display()),
            "/scourge-from-file",
        ),
        (format!("method:@{}", method_source.display()), "PATCH"),
    ] {
        let before = fixture.requests();
        assert!(
            teapot
                .send(
                    Method::Get,
                    &probe,
                    &session,
                    SendOptions {
                        edits: std::slice::from_ref(&edit),
                        ..SendOptions::default()
                    },
                )
                .is_err(),
            "{edit} must be refused, not read as a source"
        );
        assert_eq!(fixture.requests(), before, "{edit} sent target traffic");
        assert!(
            fixture
                .recorded()
                .iter()
                .all(|(method, path, _)| method != forged && path != forged),
            "{edit} used the sentinel value"
        );

        let before = fixture.requests();
        assert!(
            teapot
                .replay_macro(&plant, &session, 2, std::slice::from_ref(&edit))
                .is_err(),
            "replay {edit} must be refused, not read as a source"
        );
        assert_eq!(
            fixture.requests(),
            before,
            "replay {edit} sent target traffic"
        );
    }
    assert_eq!(fs::read(&path_source).unwrap(), b"/scourge-from-file");
    assert_eq!(fs::read(&method_source).unwrap(), b"PATCH");

    assert!(project.stop());
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
#[ignore = "requires pinned Teapot (request-reference pin for refusal path), pinned Investigation, and an owned loopback target"]
fn pinned_live_preflight_refusal_and_success_never_reach_connected_target() {
    const ENGAGEMENT: &[u8] =
        include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");

    let mut project = pinned_project();
    let target = Fixture::start();
    let root = project.root.as_ref().unwrap().path().to_path_buf();
    let pass_file = root.join("preflight.pass.toml");
    let pass_reference: PassRef = "pass.development-fixture".parse().unwrap();
    let now = OffsetDateTime::now_utc();
    let yesterday = (now - time::Duration::days(1)).format(&Rfc3339).unwrap();
    let tomorrow = (now + time::Duration::days(1)).format(&Rfc3339).unwrap();
    let pass_bytes = format!(
        r#"format = 1
id = "scourge-development-fixture"
name = "Disposable verifier preflight"
[approval]
owner = "local fixture"
reference = "bn-2a3"
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
        target.port
    );
    fs::write(&pass_file, &pass_bytes).unwrap();
    fs::set_permissions(&pass_file, fs::Permissions::from_mode(0o600)).unwrap();
    let pass_path = pass_file.to_str().unwrap();
    project.run(&["pass", "attach", pass_path]);
    let bound = project.start(&["--pass", pass_path, "--no-enforce"]);
    let teapot = project.bind(bound.clone());
    project.run(&["scope", "add", "127.0.0.1"]);
    for session in [
        "alice",
        "alice_verify",
        "bob",
        "bob_verify",
        "scourge_anonymous",
    ] {
        project.run(&["sessions", "create", session]);
    }
    fs::write(
        project.project.join(".teapot/macros/create-order.toml"),
        format!(
            "format = 1\n\n[[steps]]\nstate_changing = true\n[steps.request]\nmethod = \"POST\"\nurl = {:?}\nheaders = [[\"Content-Type\", \"application/json\"]]\nbody = {{ text = '{{\"note\":\"\",\"detail\":\"\"}}' }}\n",
            format!("http://127.0.0.1:{}/plant", target.port),
        ),
    )
    .unwrap();

    let reference_manifest: Value = serde_json::from_str(include_str!(
        "../../../fixtures/contracts/request-reference-manifest.json"
    ))
    .unwrap();
    let request_reference_binary = Sha256Digest::of(&fs::read(&project.binary).unwrap()).as_str()
        == reference_manifest["binary_sha256"].as_str().unwrap();
    let target_baseline = if request_reference_binary {
        let probe = project.run(&["requests", "send", "GET", &target.url, "--session", "alice"]);
        assert_eq!(probe["sent"]["status"], 200);
        assert_eq!(target.requests(), 1, "same Teapot route is live");
        1
    } else {
        0
    };

    let pass_digest = Sha256Digest::of(pass_bytes.as_bytes());
    let manifest = EngagementDraft::parse_toml(ENGAGEMENT)
        .unwrap()
        .accept(PassPin {
            reference: &pass_reference,
            digest: &pass_digest,
        })
        .unwrap();
    let investigation = InvestigationAuthority {
        executable: fs::canonicalize(std::env::var_os("SCOURGE_INVESTIGATION_BIN").unwrap())
            .unwrap(),
        case_root: root.clone(),
        workspace_root: root.join("evidence"),
        import_root: root.join("import"),
        scratch_root: root.join("scratch"),
    };
    for directory in [
        &investigation.workspace_root,
        &investigation.import_root,
        &investigation.scratch_root,
    ] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let evidence = Evidence::initialize_qualified(&investigation).unwrap();
    let capture = evidence
        .capture(&scourge_core::ids::RunId::generate())
        .unwrap();
    evidence
        .attach(&capture, 1, "engagement", manifest.canonical_bytes())
        .unwrap();
    let manifest_artifact = evidence
        .finalize(&capture, Some(1), Completion::Complete, &["engagement"])
        .unwrap()
        .original_artifacts
        .remove(0)
        .artifact;
    assert_eq!(manifest_artifact.digest, *manifest.digest());

    let state_root = root.join("preflight-state");
    fs::create_dir(&state_root).unwrap();
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = Store::open(state_root.join("state.sqlite3")).unwrap();
    let locks = RunLocks::open(&state_root).unwrap();
    let engagement: EngagementId = "local".parse().unwrap();
    store
        .append_manifest(&engagement, &manifest_artifact, manifest.pass_digest())
        .unwrap();
    let lead = LeadId::from_str("L-live-preflight").unwrap();
    store
        .append_lead_revision(
            &engagement,
            &LeadRevision {
                lead_id: lead.clone(),
                revision: 1,
                text: "live preflight sink".parse().unwrap(),
                class: Some("web-authz/private-object-read".parse().unwrap()),
                property: Some("orders".parse().unwrap()),
                slots: BTreeMap::from([
                    ("owner".parse().unwrap(), json!("alice")),
                    ("other".parse().unwrap(), json!("bob")),
                ]),
                proposed_policy: None,
                origin: LeadOrigin::Local,
                source_ref: None,
                endpoint: None,
                flow_ids: Vec::new(),
                producer_confidence: None,
            },
        )
        .unwrap();
    let slot = |name: &str, value: &str| SlotValue {
        name: SlotName::from_str(name).unwrap(),
        value: value.to_owned().try_into().unwrap(),
    };
    let claim = Claim {
        class: ClaimClass::from_str("web-authz/private-object-read").unwrap(),
        engagement: EngagementPin {
            revision: manifest.revision(),
            digest: manifest.digest().clone(),
        },
        lead: lead.clone(),
        property: Some("orders".parse().unwrap()),
        lead_slots: vec![slot("owner", "alice"), slot("other", "bob")],
        overrides: Vec::new(),
    };
    let input: NormalizedInput =
        Invocation::new("verify", json!({"lead_id":lead.as_str(), "rounds": 1}))
            .normalize()
            .unwrap();
    let scope = RequestScope::new(engagement, "workspace:live-preflight".parse().unwrap());
    let retained = evidence
        .read_json(&manifest_artifact.artifact_id)
        .unwrap()
        .artifact;
    let runtime = VerifierRuntimeAuthority {
        manifest: ManifestAuthority {
            revision: manifest.revision(),
            digest: manifest.digest().clone(),
            canonical_bytes: manifest.canonical_bytes().to_vec(),
            artifact: ManifestArtifactPin {
                kind: ManifestArtifactKind::EngagementManifest,
                reference: retained.reference,
                revision: retained.revision,
                size_bytes: retained.size_bytes,
                source_id: retained.source_id.parse().unwrap(),
            },
        },
        pass: PassAuthority {
            path: pass_file.clone(),
            digest: pass_digest.clone(),
        },
        teapot: TeapotProjectAuthority {
            executable: project.binary.clone(),
            project: project.project.clone(),
            home: root.clone(),
            config_home: None,
            data_home: None,
            state_home: None,
            cache_home: None,
            runtime_dir: project
                .environment
                .runtime_dir
                .as_ref()
                .map(|path| path.as_str().into()),
            wrapper: false,
        },
        engine: bound,
        investigation,
        target: manifest.target_version().clone(),
        origin: scourge_core::rounds::TargetOrigin::parse(&format!(
            "http://127.0.0.1:{}",
            target.port
        ))
        .unwrap(),
        environment_kind: scourge_core::wire::EnvironmentKind::Simulated,
        custody: scourge_core::wire::Custody::Shared,
        target_isolation: scourge_core::wire::TargetIsolation::SeparatePrincipalsUnconfined,
        principal_slots: BTreeMap::new(),
    };
    let services = LiveServices::new(&teapot, &evidence, &runtime).unwrap();
    let pass_absolute = path(&pass_file);
    let make_run = || {
        Run::declare(
            scope.engagement.clone(),
            Templates::resolve(&claim, &manifest)
                .unwrap()
                .ready()
                .unwrap()
                .freeze()
                .unwrap()
                .1,
        )
    };
    let request = |run| PreflightRequest {
        declaration: PreflightDeclaration {
            scope: &scope,
            input: &input,
            run,
            claim: &claim,
            lead_revision: 1,
            engagement: &manifest,
            manifest_artifact: &manifest_artifact,
        },
        pass: PreflightPass {
            pass_reference: &pass_reference,
            pass_state: PassState::Active(&pass_digest),
            pass_file: &pass_absolute,
        },
    };

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
    let refused_run = make_run();
    let refusal = prepare(&mut store, &locks, &services, request(&refused_run)).unwrap_err();
    assert!(matches!(refusal, PreflightError::Gate(_)));
    assert!(matches!(
        refusal.code(),
        ErrorCode::InstrumentEditsActive | ErrorCode::EnforcementUnavailable
    ));
    assert!(
        store
            .find_request(&scope, &refused_run.request_key)
            .unwrap()
            .is_some(),
        "the refusal is after durable declaration"
    );
    assert_eq!(target.requests(), target_baseline);
    project.run(&["rules", "remove", "1"]);

    let admitted_run = make_run();
    let prepared = prepare(&mut store, &locks, &services, request(&admitted_run)).unwrap();
    assert!(prepared.holds_locks());
    assert_eq!(
        prepared
            .admission()
            .accounting()
            .evidence()
            .binding()
            .pass_id
            .as_str(),
        "scourge-development-fixture"
    );
    assert_eq!(
        target.requests(),
        target_baseline,
        "live preflight reached the target"
    );

    if request_reference_binary {
        // The run was admitted against the exact pinned source and executable.
        // Remove scope only after admission so its first and only attempted
        // target request takes Teapot's durable pre-admission refusal path.
        project.run(&["scope", "clear", "--yes"]);
        let failure = execute_live(
            &mut store,
            prepared,
            &manifest,
            &teapot,
            &evidence,
            &runtime.origin,
        )
        .unwrap_err();
        assert_eq!(failure.effects, Effect::Unknown);
        assert!(failure.capture_handle.is_some());
        assert_eq!(failure.recovery.run_id, admitted_run.id);
        assert_eq!(failure.recovery.request_key, admitted_run.request_key);
        assert_eq!(
            target.requests(),
            target_baseline,
            "out-of-scope refusal dispatched bytes"
        );
        let interrupted = store.recover_run(&admitted_run.id).unwrap();
        assert_eq!(interrupted.id, admitted_run.id);
        assert_eq!(interrupted.request_key, admitted_run.request_key);
        assert_eq!(interrupted.steps.len(), 1);
        assert_eq!(interrupted.steps[0].effects, Some(Effect::Unknown));
        assert!(interrupted.steps[0].flows.is_empty());
        assert!(
            interrupted.steps[0]
                .instrument_reference
                .as_ref()
                .is_some_and(|reference| reference.as_str().starts_with("refusal:"))
        );
        assert!(store.conflicts_held(&admitted_run.id).unwrap());
        let capture = evidence
            .recover(failure.capture_handle.as_ref().unwrap())
            .unwrap();
        let finalized = capture.finalized.unwrap();
        assert!(!finalized.complete, "refusal finalizes as interrupted");
        assert!(finalized.missing_positions.is_empty());

        let reconciled = store
            .reconcile_run_with_evidence(&scope, &admitted_run.id, &evidence, &teapot)
            .unwrap();
        assert_eq!(reconciled.acceptance.run.id, admitted_run.id);
        assert_eq!(
            reconciled.acceptance.run.request_key,
            admitted_run.request_key
        );
        assert_eq!(reconciled.effects, Effect::None);
        assert_eq!(reconciled.acceptance.run.steps.len(), 1);
        assert_eq!(
            reconciled.acceptance.run.steps[0].effects,
            Some(Effect::None)
        );
        assert_eq!(
            target.requests(),
            target_baseline,
            "local reconciliation resent the request"
        );
        let revision = reconciled.revision;
        let replay = store
            .reconcile_run_with_evidence(&scope, &admitted_run.id, &evidence, &teapot)
            .unwrap();
        assert_eq!(replay.revision, revision);
        assert!(!replay.committed);
        assert_eq!(replay.effects, Effect::None);
        assert_eq!(target.requests(), target_baseline);

        let reopened = store
            .reopen_request(&scope, &admitted_run.request_key, &input)
            .unwrap();
        assert_eq!(reopened.run.id, admitted_run.id);
        assert_eq!(reopened.run.request_key, admitted_run.request_key);
        assert_eq!(
            target.requests(),
            target_baseline,
            "same-key replay resent the request"
        );
        assert!(project.stop());
        return;
    }

    // Positive control through the same bound Teapot, project, macro, session,
    // and target proves the sink is on the production dispatch route.
    let plant = "create-order".parse().unwrap();
    let verifier_session = "alice_verify".parse().unwrap();
    let sent = teapot.run_macro(&plant, &verifier_session, None).unwrap();
    assert_eq!(sent.value.units, 1);
    assert_eq!(target.requests(), target_baseline + 1);
    drop(prepared);
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
