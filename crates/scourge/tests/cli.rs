use std::{
    path::Path,
    process::{Command, Output},
};

use scourge_core::{
    response::exit_table,
    wire::{self, Action, ResponseV1},
};

fn command() -> Command {
    static STATE: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let mut process = Command::new(env!("CARGO_BIN_EXE_scourge"));
    process.env_remove("FORMAT");
    process.env(
        "XDG_STATE_HOME",
        STATE.get_or_init(|| tempfile::tempdir().unwrap()).path(),
    );
    process
}

fn response(output: &Output, exit: i32) -> ResponseV1 {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
        1
    );
    assert!(output.stdout.ends_with(b"\n"));
    wire::from_slice(&output.stdout).unwrap()
}

fn invoke_action(action: &Action, cwd: &Path) -> Output {
    assert_eq!(action.argv[0].as_str(), "scourge");
    command()
        .current_dir(cwd)
        .args(action.argv[1..].iter().map(|word| word.as_str()))
        .output()
        .unwrap()
}

#[test]
fn parse_error_before_workspace_is_one_json_object() {
    let output = command()
        .args([
            "--unknown=seeded-untrusted-option",
            "status",
            "--format=json",
        ])
        .output()
        .unwrap();
    let parsed = response(&output, 2);
    assert!(!parsed.ok);
    assert_eq!(parsed.error.unwrap().code, wire::ErrorCode::UsageError);
    assert_eq!(parsed.effects, wire::Effect::None);
    assert_eq!(parsed.command, None);
    assert_eq!(parsed.workspace, None);
    assert_eq!(parsed.engagement, None);
    assert_eq!(parsed.request_key, None);
    assert_eq!(parsed.run, None);
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("seeded-untrusted-option")
    );
    let cwd = tempfile::Builder::new()
        .prefix("unrelated path ")
        .tempdir()
        .unwrap();
    let next = &parsed.next[0];
    assert_eq!(next.effects, wire::ActionEffect::None);
    assert_eq!(
        response(&invoke_action(next, cwd.path()), 0)
            .result
            .unwrap()
            .as_str(),
        "help"
    );
}

#[test]
fn unknown_workspace_is_one_json_object() {
    let cwd = tempfile::Builder::new()
        .prefix("unrelated path ")
        .tempdir()
        .unwrap();
    let output = command()
        .current_dir(cwd.path())
        .args([
            "status",
            "--workspace",
            "missing workspace",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let parsed = response(&output, 3);
    assert_eq!(parsed.command.unwrap().as_str(), "status");
    assert_eq!(parsed.workspace, None);
    let error = parsed.error.unwrap();
    assert_eq!(error.code, wire::ErrorCode::WorkspaceUnbound);
    assert_eq!(error.commit_status, wire::CommitStatus::NotCommitted);
    let status = response(&invoke_action(&parsed.next[0], cwd.path()), 0);
    assert!(status.ok);
    assert_eq!(status.result.unwrap().as_str(), "blocked");
    assert_eq!(status.blockers, [wire::ErrorCode::WorkspaceUnbound]);
    assert!(status.error.is_none());
}

#[test]
fn hidden_json_alias_has_byte_for_byte_parity() {
    for (args, code) in [
        (&["status"][..], 0),
        (&["--no-such-option"][..], 2),
        (&["--help"][..], 0),
    ] {
        let alias = command().args(args).arg("--json").output().unwrap();
        let canonical = command()
            .args(args)
            .args(["--format", "json"])
            .output()
            .unwrap();
        response(&alias, code);
        response(&canonical, code);
        assert_eq!(alias.stdout, canonical.stdout);
        assert_eq!(alias.stderr, canonical.stderr);
    }
    let help = command().arg("--help").output().unwrap();
    assert!(!String::from_utf8(help.stdout).unwrap().contains("--json"));
}

#[test]
fn format_precedence_and_option_delimiter_apply_on_errors() {
    let from_environment = command()
        .env("FORMAT", "json")
        .arg("--not-an-option")
        .output()
        .unwrap();
    response(&from_environment, 2);

    let explicit_text = command()
        .env("FORMAT", "json")
        .args(["--format", "text", "status"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&explicit_text.stdout).contains("Blocker  WORKSPACE_UNBOUND"));

    let explicit_pretty = command()
        .args(["--format=pretty", "status"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&explicit_pretty.stdout).contains("[BLOCKED]  WORKSPACE_UNBOUND")
    );

    let fallback = command()
        .env("FORMAT", "unknown")
        .arg("status")
        .output()
        .unwrap();
    assert_eq!(fallback.stdout, explicit_text.stdout);

    for args in [
        ["--format=pretty", "status", "--json"],
        ["--json", "status", "--format=text"],
    ] {
        let conflict = command().args(args).output().unwrap();
        assert_eq!(
            response(&conflict, 2).error.unwrap().message.as_str(),
            "Select one output format."
        );
    }

    let missing_format_value = command().args(["--format", "--json"]).output().unwrap();
    response(&missing_format_value, 2);

    let literal = command().args(["status", "--", "--json"]).output().unwrap();
    assert_eq!(literal.status.code(), Some(2));
    assert!(literal.stdout.is_empty());
}

#[test]
fn help_displays_the_generated_exit_rows_and_version_is_an_envelope() {
    let help = command()
        .args(["--format", "json", "--help"])
        .output()
        .unwrap();
    let parsed = response(&help, 0);
    let help = parsed.extensions["help"].as_str().unwrap();
    for (exit, code) in exit_table() {
        let label = code.map_or(
            "Completed, including reads with blockers",
            wire::ErrorCode::as_str,
        );
        assert!(
            help.lines()
                .any(|line| line == format!("  {exit}  {label}"))
        );
    }
    for flag in ["version", "--version"] {
        let version = command().args(["--format", "json", flag]).output().unwrap();
        let parsed = response(&version, 0);
        assert_eq!(parsed.command.unwrap().as_str(), "version");
        assert_eq!(
            parsed.extensions["version"].as_str(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn subcommand_help_preserves_the_resolved_command_and_accepts_global_selectors() {
    for args in [
        &["--format", "json", "status", "--help"][..],
        &["status", "-h", "--format", "json"],
        &["status", "--help", "--json"],
        &["--format", "json", "help", "status"],
        &["help", "status", "--format", "json"],
        &["--json", "help", "status"],
        &["help", "status", "--json"],
    ] {
        let output = command().args(args).output().unwrap();
        let parsed = response(&output, 0);
        assert_eq!(parsed.command.unwrap().as_str(), "status", "{args:?}");
        assert_eq!(parsed.result.unwrap().as_str(), "help");
        assert!(
            parsed.extensions["help"]
                .as_str()
                .unwrap()
                .contains("Usage: scourge status [OPTIONS]")
        );
    }

    let from_env = command()
        .env("FORMAT", "json")
        .args(["help", "status"])
        .output()
        .unwrap();
    assert_eq!(response(&from_env, 0).command.unwrap().as_str(), "status");

    for format in ["text", "pretty"] {
        let output = command()
            .env("FORMAT", "json")
            .args(["help", "status", "--format", format])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(
            str::from_utf8(&output.stdout)
                .unwrap()
                .contains("Usage: scourge status [OPTIONS]")
        );
    }
}

#[cfg(unix)]
#[test]
fn help_and_usage_advice_use_the_canonical_binary_name() {
    use std::os::unix::process::CommandExt;

    const SEEDED_BASENAME: &str = "seeded-hostile-executable-basename-Xs0z";
    for args in [
        &["--json", "--help"][..],
        &["--format", "json", "status", "--help"],
        &["help", "status", "--json"],
    ] {
        let output = command().arg0(SEEDED_BASENAME).args(args).output().unwrap();
        let parsed = response(&output, 0);
        assert!(
            parsed.extensions["help"]
                .as_str()
                .unwrap()
                .contains("Usage: scourge ")
        );
        assert!(
            !str::from_utf8(&output.stdout)
                .unwrap()
                .contains(SEEDED_BASENAME)
        );
    }

    let output = command()
        .arg0(SEEDED_BASENAME)
        .args(["--json", "--unknown"])
        .output()
        .unwrap();
    let parsed = response(&output, 2);
    assert_eq!(parsed.next[0].argv[0].as_str(), "scourge");
    assert!(
        !str::from_utf8(&output.stdout)
            .unwrap()
            .contains(SEEDED_BASENAME)
    );
}
