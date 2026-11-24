//! Exercise the production output path in another process before the command
//! lanes that return refusals and native diagnostics are wired to the binary.

use std::{
    env,
    ffi::OsStr,
    io,
    process::{self, Command, Stdio},
};

use scourge_core::{
    response::Context,
    wire::{
        self, Cleanup, CommitStatus, Diagnostic, DiagnosticCode, DiagnosticV1, Effect, ErrorCode,
        Reproduction, ResponseV1, RunFlag, RunState, RunSummary,
    },
};

const SECRET: &str = "seeded-session-secret-Xs0z";
const WORKSPACE: &str = "/work/example orders";
const ENGAGEMENT: &str = "orders-api";
const REQUEST: &str = "rk_example_01";
const RUN: &str = "R-4";

fn main() {
    if let Some(scenario) = env::var_os("SCOURGE_TEST_SCENARIO") {
        let exit = scourge::run(
            env::args_os(),
            None,
            false,
            |_| fixture(scenario.as_os_str()),
            &mut io::stdout().lock(),
            &mut io::stderr().lock(),
        )
        .unwrap_or_else(|_| ErrorCode::DependencyUnavailable.exit_code());
        process::exit(i32::from(exit));
    }
    refusal_is_one_json_object_with_redacted_keyed_stderr();
    masked_native_failures_keep_typed_diagnostics();
    broken_stdout_preserves_the_refusal_diagnostic_on_stderr();
}

fn fixture(scenario: &OsStr) -> ResponseV1 {
    let mut context = Context::for_command("status");
    context.workspace = Some(WORKSPACE.parse().unwrap());
    context.engagement = Some(ENGAGEMENT.parse().unwrap());
    let (mut response, diagnostic, native_exit) = match scenario.to_str() {
        Some("wrong-listener") => (
            context.blocked(vec![ErrorCode::DependencyUnavailable]),
            DiagnosticCode::WrongListener,
            Some(0),
        ),
        Some("refusal" | "tool-unavailable") => {
            context = Context::for_command("verify");
            context.workspace = Some(WORKSPACE.parse().unwrap());
            context.engagement = Some(ENGAGEMENT.parse().unwrap());
            context.request_key = Some(REQUEST.parse().unwrap());
            let (code, diagnostic, flag, native_exit, message) = if scenario == "refusal" {
                (
                    ErrorCode::AccountingUnestablished,
                    DiagnosticCode::NativeFailure,
                    RunFlag::Refused,
                    Some(1),
                    "The run requires attributable accounting.",
                )
            } else {
                (
                    ErrorCode::DependencyUnavailable,
                    DiagnosticCode::ToolUnavailable,
                    RunFlag::FailedBeforeStart,
                    None,
                    "Could not start the bound Teapot executable.",
                )
            };
            let mut response =
                context.failure(code, message, CommitStatus::Committed, Effect::None);
            response.run = Some(RunSummary {
                id: RUN.parse().unwrap(),
                state: RunState::Finalized,
                flags: vec![flag],
                oracle_result: None,
                reproduction: Reproduction::NotAttempted,
                cleanup: Cleanup::NotRequired,
            });
            (response, diagnostic, native_exit)
        }
        _ => panic!("unknown test scenario"),
    };
    response.diagnostics.push(Diagnostic {
        code: diagnostic,
        stage: "describe".parse().unwrap(),
        message: format!(
            "Untrusted native output: {}",
            env::var("SCOURGE_TEST_NATIVE_OUTPUT").unwrap()
        )
        .parse()
        .unwrap(),
        native_exit,
        wrapper_exit: Some(0),
    });
    response
}

fn fixture_process(scenario: &str) -> Command {
    let mut command = Command::new(env::current_exe().unwrap());
    command
        .args(["--format", "json"])
        .env("SCOURGE_TEST_SCENARIO", scenario)
        .env("SCOURGE_TEST_NATIVE_OUTPUT", SECRET);
    command
}

fn run_fixture(scenario: &str, exit: i32) -> (ResponseV1, DiagnosticV1) {
    let output = fixture_process(scenario).output().unwrap();
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    for line in [&output.stdout, &output.stderr] {
        assert_eq!(line.iter().filter(|&&byte| byte == b'\n').count(), 1);
        assert!(line.ends_with(b"\n"));
        assert!(!str::from_utf8(line).unwrap().contains(SECRET));
    }
    let response: ResponseV1 = wire::from_slice(&output.stdout).unwrap();
    let event: DiagnosticV1 = wire::from_slice(&output.stderr).unwrap();
    assert_eq!(
        response.diagnostics.as_slice(),
        std::slice::from_ref(&event.diagnostic)
    );
    assert_eq!(event.workspace, response.workspace);
    assert_eq!(event.engagement, response.engagement);
    assert_eq!(event.request_key, response.request_key);
    assert_eq!(
        event.run_id,
        response.run.as_ref().map(|run| run.id.clone())
    );
    (response, event)
}

fn broken_stdout_preserves_the_refusal_diagnostic_on_stderr() {
    let (_, expected) = run_fixture("refusal", 8);
    let (reader, writer) = io::pipe().unwrap();
    drop(reader);
    let output = fixture_process("refusal")
        .stdout(Stdio::from(writer))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr.iter().filter(|&&byte| byte == b'\n').count(),
        1
    );
    assert!(output.stderr.ends_with(b"\n"));
    assert!(!str::from_utf8(&output.stderr).unwrap().contains(SECRET));
    assert_eq!(
        wire::from_slice::<DiagnosticV1>(&output.stderr).unwrap(),
        expected
    );
}

fn refusal_is_one_json_object_with_redacted_keyed_stderr() {
    let (response, event) = run_fixture("refusal", 8);
    assert!(!response.ok);
    let error = response.error.unwrap();
    assert_eq!(error.code, ErrorCode::AccountingUnestablished);
    assert_eq!(error.commit_status, CommitStatus::Committed);
    assert_eq!(response.effects, Effect::None);
    assert!(response.result.is_none());
    assert_eq!(event.workspace.unwrap().as_str(), WORKSPACE);
    assert_eq!(event.engagement.unwrap().as_str(), ENGAGEMENT);
    assert_eq!(event.request_key.unwrap().as_str(), REQUEST);
    assert_eq!(event.run_id.unwrap().as_str(), RUN);
    assert_eq!(
        event.diagnostic.message.as_str(),
        "The native operation failed."
    );
}

fn masked_native_failures_keep_typed_diagnostics() {
    let (read, event) = run_fixture("wrong-listener", 0);
    assert!(read.ok);
    assert!(read.error.is_none());
    assert_eq!(read.result.unwrap().as_str(), "blocked");
    assert_eq!(read.blockers, [ErrorCode::DependencyUnavailable]);
    assert_eq!(event.diagnostic.code, DiagnosticCode::WrongListener);
    assert_eq!(event.diagnostic.native_exit, Some(0));
    assert_eq!(event.diagnostic.wrapper_exit, Some(0));
    assert!(event.request_key.is_none());
    assert!(event.run_id.is_none());

    let (failed, event) = run_fixture("tool-unavailable", 7);
    assert!(!failed.ok);
    assert_eq!(failed.error.unwrap().code, ErrorCode::DependencyUnavailable);
    assert_eq!(event.diagnostic.code, DiagnosticCode::ToolUnavailable);
    assert_eq!(event.diagnostic.native_exit, None);
    assert_eq!(event.diagnostic.wrapper_exit, Some(0));
}
