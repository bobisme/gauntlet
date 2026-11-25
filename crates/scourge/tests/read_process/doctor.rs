use rusqlite::{Connection, params};
use scourge_core::{
    store::{
        StoreError,
        checks::{RecordedCheck, Stage},
    },
    wire::{DiagnosticCode, DiagnosticV1},
};

use super::*;

pub(super) fn seed(store: &mut Store) {
    let scope = SCOPE.parse().unwrap();
    let check = failed_check();
    let revision = store.revision().unwrap();
    assert_eq!(store.record_check(&scope, &check).unwrap(), revision + 1);

    let mut foreign = failed_check();
    foreign.run_id = Some("R-foreign".parse().unwrap());
    assert!(matches!(
        store.record_check(&scope, &foreign),
        Err(StoreError::SelectorNotFound)
    ));

    let mut older = failed_check();
    older.observed_at = "1970-01-01T00:15:59.999999999Z".parse().unwrap();
    assert!(matches!(
        store.record_check(&scope, &older),
        Err(StoreError::Conflict)
    ));
    assert_eq!(store.revision().unwrap(), revision + 1);
    for (native_exit, wrapper_exit) in [(Some(7), Some(0)), (Some(0), Some(7)), (None, Some(-1))] {
        let invalid = RecordedCheck {
            code: None,
            native_exit,
            wrapper_exit,
            ..failed_check()
        };
        assert!(matches!(
            store.record_check(&scope, &invalid),
            Err(StoreError::Integrity)
        ));
    }
    assert_eq!(store.revision().unwrap(), revision + 1);

    for (stage, when) in [
        (Stage::DryRun, "1970-01-01T00:00:00.25Z"),
        (Stage::UnitsLeft, "1970-01-01T00:16:40.000000001Z"),
    ] {
        store
            .record_check(
                &scope,
                &RecordedCheck {
                    stage,
                    observed_at: when.parse().unwrap(),
                    code: None,
                    native_exit: Some(0),
                    wrapper_exit: None,
                    run_id: None,
                },
            )
            .unwrap();
    }
    let mut foreign = failed_check();
    foreign.code = Some(DiagnosticCode::TransportUnavailable);
    foreign.run_id = Some("R-foreign".parse().unwrap());
    store
        .record_check(&FOREIGN.parse().unwrap(), &foreign)
        .unwrap();
}

fn failed_check() -> RecordedCheck {
    RecordedCheck {
        stage: Stage::Describe,
        observed_at: "1970-01-01T00:16:00Z".parse().unwrap(),
        code: Some(DiagnosticCode::WrongListener),
        native_exit: Some(0),
        wrapper_exit: Some(0),
        run_id: Some("R-local".parse().unwrap()),
    }
}

pub(super) fn populated(output: &Output) {
    let (view, json) = envelope(output, 0);
    assert_eq!(view.command.unwrap().as_str(), "doctor");
    assert_eq!(view.engagement.as_ref().unwrap().as_str(), SCOPE);
    assert!(view.ok && view.error.is_none());
    assert_eq!(view.result.unwrap().as_str(), "blocked");
    assert_eq!(view.blockers, [ErrorCode::DependencyUnavailable]);
    assert!(view.transport.is_none());
    assert_eq!(view.diagnostics.len(), 1);
    assert_eq!(view.advice[0].r#type.as_str(), "check-clock-skew");
    let diagnostics: DiagnosticV1 = wire::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostics.workspace, view.workspace);
    assert_eq!(diagnostics.engagement, view.engagement);
    assert_eq!(diagnostics.diagnostic, view.diagnostics[0]);
    assert_eq!(diagnostics.run_id.unwrap().as_str(), "R-local");
    assert_eq!(diagnostics.request_key.unwrap().as_str(), "rk_local");
    assert_eq!(
        json["checks"][0],
        json!({
            "stage": "describe", "state": "failed", "observed_at": "1970-01-01T00:16:00Z",
            "age_seconds": 40, "timestamp_in_future": false, "code": "WRONG_LISTENER",
            "native_exit": 0, "wrapper_exit": 0, "run_id": "R-local", "request_key": "rk_local",
            "correlation_withheld": false,
        })
    );
    assert_eq!(json["checks"][1]["state"], "missing");
    assert_eq!(json["checks"][2]["state"], "passed");
    assert_eq!(json["checks"][2]["age_seconds"], 999);
    assert_eq!(json["checks"][3]["state"], "passed");
    assert!(json["checks"][3]["age_seconds"].is_null());
    assert_eq!(json["checks"][3]["timestamp_in_future"], true);
    assert_eq!(json["checks"][4]["state"], "missing");
    assert_eq!(json["checks"].as_array().unwrap().len(), Stage::ALL.len());
    assert!(output.stdout.len() < 3000 && output.stderr.len() < 512);
}

pub(super) fn stock_populated(output: &Output) {
    let (view, json) = envelope(output, 0);
    assert_eq!(view.command.unwrap().as_str(), "doctor");
    assert_eq!(view.engagement.as_ref().unwrap().as_str(), SCOPE);
    assert_eq!(view.blockers, [ErrorCode::DependencyUnavailable]);
    assert_eq!(json["checks"][0]["code"], "WRONG_LISTENER");
    assert_eq!(json["checks"][0]["run_id"], "R-local");
    let age = json["checks"][0]["age_seconds"].as_u64().unwrap();
    let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
    assert!((now.saturating_sub(1000)..=now.saturating_sub(960)).contains(&age));
    let event: DiagnosticV1 = wire::from_slice(&output.stderr).unwrap();
    assert_eq!(event.diagnostic, view.diagnostics[0]);
    assert_eq!(event.run_id.unwrap().as_str(), "R-local");
    assert_eq!(event.request_key.unwrap().as_str(), "rk_local");
}

pub(super) fn stock_regressions(fixture: &Fixture) {
    let scope = SCOPE.parse().unwrap();
    let mut writer = Store::open(&fixture.path).unwrap();
    let mut run = Run::declare(scope, Sha256Digest::of(b"second doctor event"));
    run.id = "R-second".parse().unwrap();
    run.request_key = "rk_second".parse().unwrap();
    historical_run::seed(&fixture.path, &run);
    writer
        .record_check(
            &run.engagement,
            &RecordedCheck {
                stage: Stage::ListJobs,
                code: Some(DiagnosticCode::NativeFailure),
                native_exit: None,
                wrapper_exit: None,
                run_id: Some(run.id),
                ..failed_check()
            },
        )
        .unwrap();

    let invoke = || {
        fixture
            .stock()
            .args([
                "--workspace",
                fixture.root.to_str().unwrap(),
                "--engagement",
                SCOPE,
                "doctor",
                "--json",
            ])
            .output()
            .unwrap()
    };
    let output = invoke();
    let (view, _) = envelope(&output, 0);
    let events: Vec<DiagnosticV1> = output
        .stderr
        .split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| wire::from_slice(line).unwrap())
        .collect();
    assert_eq!(events.len(), 2);
    for ((event, diagnostic), (expected_run, expected_key)) in events
        .iter()
        .zip(view.diagnostics)
        .zip([("R-local", "rk_local"), ("R-second", "rk_second")])
    {
        assert_eq!(event.diagnostic, diagnostic);
        assert_eq!(event.run_id.as_ref().unwrap().as_str(), expected_run);
        assert_eq!(event.request_key.as_ref().unwrap().as_str(), expected_key);
    }

    let raw = Connection::open(&fixture.path).unwrap();
    raw.execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    raw.execute(
        "UPDATE recorded_checks SET code=NULL, native_exit=7 WHERE engagement_id=? AND stage='describe'",
        [SCOPE],
    ).unwrap();
    let (invalid, _) = response(&invoke(), 6);
    assert_eq!(invalid.error.unwrap().code, ErrorCode::IntegrityFailure);
}

pub(super) fn empty(output: &Output) {
    let (view, json) = response(output, 0);
    assert_eq!(view.result.unwrap().as_str(), "checked");
    assert!(view.blockers.is_empty());
    let checks = json["checks"].as_array().unwrap();
    assert_eq!(checks.len(), Stage::ALL.len());
    for check in checks {
        assert_eq!(check["state"], "missing");
        assert!(check["observed_at"].is_null());
        assert!(check["age_seconds"].is_null());
    }
}

pub(super) fn cases(fixture: &Fixture) {
    populated(&fixture.read(&["doctor", "--json"]));
    let first = "describe  failed  age=40s  1970-01-01T00:16:00Z  WRONG_LISTENER  native_exit=0  wrapper_exit=0  R-local  rk_local";
    for format in ["text", "pretty"] {
        let output = fixture.read(&["doctor", "--format", format]);
        assert_eq!(output.status.code(), Some(0));
        assert_redacted(&output);
        let view = str::from_utf8(&output.stdout).unwrap();
        let first = if format == "pretty" {
            first.replace("  ", "  │  ")
        } else {
            first.to_owned()
        };
        assert_eq!(view.lines().next(), Some(first.as_str()));
        assert!(view.contains("age=999s"));
        assert!(view.contains("age=unknown"));
        assert!(view.contains("missing"));
    }

    let output = fixture
        .child()
        .args(["doctor", "--engagement", "empty", "--json"])
        .output()
        .unwrap();
    empty(&output);
    let (help, json) = fixture.json(&["doctor", "--help"], 0);
    assert_eq!(help.command.unwrap().as_str(), "doctor");
    assert!(
        json["help"]
            .as_str()
            .unwrap()
            .contains("Doctor runs no checks.")
    );
    let (error, _) = fixture.json(&["doctor", "--probe"], 2);
    assert_eq!(error.error.unwrap().code, ErrorCode::UsageError);

    let output = fixture
        .child()
        .args(["doctor", "--engagement", FOREIGN, "--json"])
        .output()
        .unwrap();
    let (_, json) = envelope(&output, 0);
    assert_eq!(json["checks"][0]["code"], "TRANSPORT_UNAVAILABLE");
    assert_eq!(json["checks"][0]["request_key"], "rk_foreign");
    assert!(!str::from_utf8(&output.stdout).unwrap().contains("R-local"));

    source_edge_cases(fixture);
}

fn source_edge_cases(fixture: &Fixture) {
    let path = fixture.dir.path().join("doctor edge cases.sqlite");
    let mut store = Store::open(&path).unwrap();
    let scope = SCOPE.parse().unwrap();
    let digest = Sha256Digest::of(b"doctor manifest");
    store
        .append_manifest(
            &scope,
            &Artifact {
                artifact_id: SECRET.parse().unwrap(),
                digest: digest.clone(),
            },
            &digest,
        )
        .unwrap();

    // Generated run and key identities are short. A valid but oversized
    // legacy ID must not defeat the doctor's bounded projection.
    let mut run = Run::declare(scope, digest);
    run.id = format!("R-{}", "x".repeat(4096)).parse().unwrap();
    run.request_key = format!("rk_{}", "x".repeat(4096)).parse().unwrap();
    historical_run::seed(&path, &run);
    let mut check = failed_check();
    check.run_id = Some(run.id);
    store.record_check(&run.engagement, &check).unwrap();

    let run = || {
        fixture
            .child()
            .env("SCOURGE_READ_TEST_STORE", &path)
            .args(["doctor", "--json"])
            .output()
            .unwrap()
    };
    let bounded = run();
    let (_, json) = envelope(&bounded, 0);
    assert!(bounded.stdout.len() < 3000);
    assert!(json["checks"][0]["run_id"].is_null());
    assert!(json["checks"][0]["request_key"].is_null());
    assert_eq!(json["checks"][0]["correlation_withheld"], true);
    let bounded_event: DiagnosticV1 = wire::from_slice(&bounded.stderr).unwrap();
    assert!(bounded_event.run_id.is_none() && bounded_event.request_key.is_none());

    // Inject a malformed raw row after writing a valid observation. Only the
    // dedicated corruption fixture bypasses the typed persistence API.
    let raw = Connection::open(&path).unwrap();
    let revision = store.revision().unwrap();
    let operation: String = raw
        .query_row(
            "SELECT operation FROM audit_events WHERE revision=?",
            [i64::try_from(revision).unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(operation, "diagnostic.record");
    raw.execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    for exits in [(7, 0), (0, 7)] {
        raw.execute(
            "UPDATE recorded_checks SET code=NULL, native_exit=?, wrapper_exit=?",
            params![exits.0, exits.1],
        )
        .unwrap();
        let (invalid, _) = response(&run(), 6);
        assert_eq!(invalid.error.unwrap().code, ErrorCode::IntegrityFailure);
    }
    raw.execute(
        "UPDATE recorded_checks SET code='WRONG_LISTENER', native_exit=0, wrapper_exit=0",
        [],
    )
    .unwrap();
    raw.execute("UPDATE recorded_checks SET observed_at=?", params![SECRET])
        .unwrap();
    let (invalid, _) = response(&run(), 6);
    assert_eq!(invalid.error.unwrap().code, ErrorCode::IntegrityFailure);
    assert_eq!(store.revision().unwrap(), revision);

    raw.execute_batch("DROP TABLE recorded_checks; PRAGMA user_version=4;")
        .unwrap();
    let wal = path.with_file_name("doctor edge cases.sqlite-wal");
    let before = (fs::read(&path).unwrap(), fs::read(&wal).unwrap());
    let (old_schema, json) = response(&run(), 0);
    assert!(old_schema.ok);
    assert_eq!(old_schema.blockers, [ErrorCode::CapabilityUnavailable]);
    assert_eq!(old_schema.result.unwrap().as_str(), "blocked");
    assert!(
        json["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|check| check["state"] == "unavailable")
    );
    assert_eq!(fs::read(&path).unwrap(), before.0);
    assert_eq!(fs::read(wal).unwrap(), before.1);
    assert_eq!(store.revision().unwrap(), revision);
}
