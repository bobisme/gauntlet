use std::{fs, process::Command};

fn source(body: &str) -> String {
    format!(
        r#"
use scourge_core::preflight::{{LiveAdmission, Prepared}};

{body}
"#
    )
}

fn check_probe(name: &str, body: &str, expected_diagnostic: &str) {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("src")).unwrap();
    let manifest = format!(
        r#"[package]
name = "privacy-probe-{name}"
version = "0.0.0"
edition = "2024"

[workspace]

[dependencies]
scourge-core = {{ path = {:?} }}
"#,
        env!("CARGO_MANIFEST_DIR")
    );
    fs::write(directory.path().join("Cargo.toml"), manifest).unwrap();
    fs::write(directory.path().join("src/lib.rs"), source(body)).unwrap();
    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline", "--quiet"])
        .env(
            "CARGO_TARGET_DIR",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/privacy-probes"),
        )
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert!(!output.status.success(), "{name} unexpectedly compiled");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(expected_diagnostic),
        "{name} did not report its intended privacy diagnostic `{expected_diagnostic}`:\n{stderr}"
    );
}

fn private_field(owner: &str, field: &str) -> String {
    format!("field `{field}` of struct `{owner}` is private")
}

#[test]
fn every_prepared_authority_field_is_independently_private() {
    for field in [
        "acceptance",
        "experiment",
        "artifact",
        "execution_plan",
        "admission",
        "authority",
        "lease",
    ] {
        check_probe(
            &format!("prepared-{field}"),
            &format!("fn probe(value: &Prepared<LiveAdmission<'_>>) {{ let _ = &value.{field}; }}"),
            &private_field("Prepared", field),
        );
    }
}

#[test]
fn every_live_admission_authority_field_is_independently_private() {
    for field in [
        "instrument",
        "accounting",
        "sessions",
        "requirement",
        "started_at",
        "target_origin",
        "target_version",
        "teapot",
        "evidence",
    ] {
        check_probe(
            &format!("admission-{field}"),
            &format!("fn probe(value: &LiveAdmission<'_>) {{ let _ = &value.{field}; }}"),
            &private_field("LiveAdmission", field),
        );
    }
}

#[test]
fn direct_construction_and_destructuring_routes_are_private() {
    for (name, body, expected_diagnostic) in [
        (
            "prepared-construct",
            "fn probe() -> Prepared<LiveAdmission<'static>> { Prepared { acceptance: todo!(), ..todo!() } }",
            "fields `acceptance`, `experiment`, `artifact`, `execution_plan`, `admission`, `authority` and `lease` of struct `Prepared` are private",
        ),
        (
            "prepared-destructure",
            "fn probe(value: Prepared<LiveAdmission<'_>>) { let Prepared { acceptance: _, .. } = value; }",
            "field `acceptance` of struct `Prepared` is private",
        ),
        (
            "admission-construct",
            "fn probe() -> LiveAdmission<'static> { LiveAdmission { instrument: todo!(), ..todo!() } }",
            "fields `instrument`, `accounting`, `sessions`, `requirement`, `started_at`, `target_origin`, `target_version`, `teapot` and `evidence` of struct `LiveAdmission` are private",
        ),
        (
            "admission-destructure",
            "fn probe(value: LiveAdmission<'_>) { let LiveAdmission { instrument: _, .. } = value; }",
            "field `instrument` of struct `LiveAdmission` is private",
        ),
    ] {
        check_probe(name, body, expected_diagnostic);
    }
}
