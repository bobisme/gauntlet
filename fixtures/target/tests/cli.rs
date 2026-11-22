use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scourge-fixture"))
        .env_remove("SCOURGE_FIXTURE_ADMIN_SECRET")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn help_and_version_do_not_require_a_secret() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--listen"));
    assert!(help.contains("Agent workflow"));
    assert!(help.contains("Exit codes"));
    let version = run(&["--version"]);
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        format!("scourge-fixture {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn invalid_configuration_fails_before_listening() {
    for args in [
        vec![],
        vec!["--admin-secret", ""],
        vec!["--admin-secret", "test-secret", "--listen", "invalid"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("error:"));
        assert!(!error.contains("test-secret"));
    }
}
