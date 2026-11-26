use std::{fs, io::ErrorKind, path::Path, process::Stdio};

use rustix::{
    io::Errno,
    process::{Pid, WaitOptions, waitpid},
};

use super::*;

const SMALL_LIMITS: process::Limits = process::Limits {
    stdout: 4096,
    stderr: 4096,
    deadline: Duration::from_millis(400),
};

fn fake_child(script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .env_clear()
        .stdin(Stdio::null())
        .args(["-c", script]);
    command
}

fn captured_version() -> String {
    let capture = include_str!("../../../../fixtures/contracts/describe.json");
    serde_json::from_str::<Value>(capture).unwrap()["output"].to_string()
}

fn assert_reaped(pid_file: &Path) {
    let pid = fs::read_to_string(pid_file).unwrap().parse().unwrap();
    let pid = Pid::from_raw(pid).unwrap();
    assert!(matches!(
        waitpid(Some(pid), WaitOptions::NOHANG),
        Err(Errno::CHILD)
    ));
    assert!(!Path::new(&format!("/proc/{}", pid.as_raw_pid())).exists());
}

fn assert_capture_failure(
    error: process::RunError,
    executable: ExecutableKind,
    expected: TransportFailure,
    expected_code: DiagnosticCode,
    expected_exits: Exits,
) {
    let failure = process_failure(&VERSION, executable, error);
    assert_eq!(failure.code(), ErrorCode::DependencyUnavailable);
    let diagnostic = failure.diagnostic().unwrap();
    assert_eq!(diagnostic.code, expected_code);
    assert_eq!(diagnostic.native_exit, expected_exits.native);
    assert_eq!(diagnostic.wrapper_exit, expected_exits.wrapper);
    assert!(!diagnostic.message.as_str().contains("sensitive-child-text"));
    match failure {
        InvocationError::DependencyUnavailable {
            transport_failure, ..
        } => {
            assert_eq!(transport_failure, Some(expected));
        }
        _ => panic!("expected typed dependency failure"),
    }
}

#[test]
fn unclassified_wrapper_spawn_errors_are_typed_as_tool_unavailable() {
    // These OS spawn refusals must not fall through to NativeFailure. The
    // wrapper never ran, so neither native nor wrapper exits are known.
    for reason in [ErrorKind::WouldBlock, ErrorKind::ExecutableFileBusy] {
        let failure = process_failure(
            &VERSION,
            ExecutableKind::Wrapper,
            process::RunError::Spawn(reason),
        );
        assert_eq!(failure.code(), ErrorCode::DependencyUnavailable);
        let diagnostic = failure.diagnostic().unwrap();
        assert_eq!(diagnostic.code, DiagnosticCode::ToolUnavailable);
        assert_eq!(diagnostic.native_exit, None);
        assert_eq!(diagnostic.wrapper_exit, None);
    }
}

#[test]
fn deadline_kills_and_reaps_silent_child() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("pid");
    let mut command = fake_child("printf '%s' \"$$\" > \"$PID_FILE\"; exec /bin/sleep 30");
    command.env("PID_FILE", &pid_file);
    assert_capture_failure(
        process::run(&mut command, SMALL_LIMITS).unwrap_err(),
        ExecutableKind::Native,
        TransportFailure::Timeout,
        DiagnosticCode::TransportUnavailable,
        Exits::default(),
    );
    assert_reaped(&pid_file);
}

#[test]
fn valid_json_then_hang_never_becomes_success_even_after_pipe_eof() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("pid");
    let mut command = fake_child(
        "printf '%s' \"$$\" > \"$PID_FILE\"; printf '%s' \"$REPLY\"; exec 1>&- 2>&-; exec /bin/sleep 30",
    );
    command
        .env("PID_FILE", &pid_file)
        .env("REPLY", captured_version());
    assert_capture_failure(
        process::run(&mut command, SMALL_LIMITS).unwrap_err(),
        ExecutableKind::Wrapper,
        TransportFailure::Timeout,
        DiagnosticCode::TransportUnavailable,
        Exits::default(),
    );
    assert_reaped(&pid_file);
}

#[test]
fn deadline_kills_helper_holding_pipe_and_retains_known_wrapper_exit() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("pid");
    let helper_file = directory.path().join("helper");
    let mut command = fake_child(
        "printf '%s' \"$$\" > \"$PID_FILE\"; /bin/sleep 30 & printf '%s' \"$!\" > \"$HELPER_FILE\"; exit 23",
    );
    command
        .env("PID_FILE", &pid_file)
        .env("HELPER_FILE", &helper_file);
    assert_capture_failure(
        process::run(&mut command, SMALL_LIMITS).unwrap_err(),
        ExecutableKind::Wrapper,
        TransportFailure::Timeout,
        DiagnosticCode::TransportUnavailable,
        Exits {
            native: None,
            wrapper: Some(23),
        },
    );
    assert_reaped(&pid_file);

    let helper: u32 = fs::read_to_string(helper_file).unwrap().parse().unwrap();
    let state = format!("/proc/{helper}/stat");
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match fs::read_to_string(&state) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Ok(stat)
                if stat
                    .rsplit_once(") ")
                    .is_some_and(|(_, rest)| rest.starts_with("Z ")) =>
            {
                break;
            }
            Ok(_) => assert!(std::time::Instant::now() < deadline, "helper still alive"),
            Err(error) => panic!("could not check helper state: {error}"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn stdout_and_stderr_flood_reject_before_decoding_and_kill_child() {
    for (script, stream) in [
        (
            "exec /usr/bin/yes sensitive-child-text",
            OutputStream::Stdout,
        ),
        (
            "exec /usr/bin/yes sensitive-child-text >&2",
            OutputStream::Stderr,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("pid");
        let mut command = fake_child(&format!("printf '%s' \"$$\" > \"$PID_FILE\"; {script}"));
        command.env("PID_FILE", &pid_file);
        let error = process::run(&mut command, SMALL_LIMITS).unwrap_err();
        let process::RunError::Capture { kind, status } = error else {
            panic!("expected a capture failure");
        };
        assert_eq!(kind, TransportFailure::OutputLimit(stream));
        // The local program may exit on SIGPIPE before the group SIGKILL.
        let native = status.and_then(|status| status.code()).map(i64::from);
        assert_capture_failure(
            error,
            ExecutableKind::Native,
            TransportFailure::OutputLimit(stream),
            DiagnosticCode::InvalidNativeOutput,
            Exits {
                native,
                wrapper: None,
            },
        );
        assert_reaped(&pid_file);
    }
}

#[test]
fn drains_both_pipes_under_back_pressure_and_keeps_normal_exit() {
    let bytes = 256 * 1024;
    let limits = process::Limits {
        stdout: bytes,
        stderr: bytes,
        deadline: Duration::from_secs(3),
    };
    let script =
        "/usr/bin/head -c 262144 /dev/zero & /usr/bin/head -c 262144 /dev/zero >&2 & wait; exit 23";
    let output = process::run(&mut fake_child(script), limits).unwrap();
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout.len(), bytes);
    assert_eq!(output.stderr.len(), bytes);
}

#[test]
fn exact_cap_preserves_strict_json_and_ignores_no_overflow_suffix() {
    let version = captured_version();
    let limits = process::Limits {
        stdout: version.len(),
        ..SMALL_LIMITS
    };
    let mut child = fake_child("printf '%s' \"$REPLY\"");
    child.env("REPLY", &version);
    let output = process::run(&mut child, limits).unwrap();
    let reply = NativeOutput::Version
        .decode(
            ExecutableKind::Native,
            output.status.code().map(i64::from),
            &output.stdout,
            &output.stderr,
        )
        .unwrap();
    assert_eq!(
        reply.exits(),
        Exits {
            native: Some(0),
            wrapper: None
        }
    );

    child.env("REPLY", format!("{version}\n"));
    let failure = process::run(&mut child, limits).unwrap_err();
    let process::RunError::Capture { status, .. } = failure else {
        panic!("expected a capture failure");
    };
    let native = status.and_then(|status| status.code()).map(i64::from);
    assert_capture_failure(
        failure,
        ExecutableKind::Native,
        TransportFailure::OutputLimit(OutputStream::Stdout),
        DiagnosticCode::InvalidNativeOutput,
        Exits {
            native,
            wrapper: None,
        },
    );

    for reply in ["{".to_owned(), format!("{version}\n{version}")] {
        child.env("REPLY", reply);
        let output = process::run(&mut child, SMALL_LIMITS).unwrap();
        let failure = NativeOutput::Version
            .decode(
                ExecutableKind::Wrapper,
                output.status.code().map(i64::from),
                &output.stdout,
                &output.stderr,
            )
            .unwrap_err();
        let diagnostic = failure.diagnostic().unwrap();
        assert_eq!(diagnostic.code, DiagnosticCode::InvalidNativeOutput);
        assert_eq!(diagnostic.wrapper_exit, Some(0));
        assert_eq!(diagnostic.native_exit, None);
    }
}

#[test]
fn executable_above_staging_limit_has_a_full_digest_without_snapshot_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("teapot");
    let content = b"test executable bytes";
    fs::write(&path, content).unwrap();
    let limit = content.len() as u64;
    let (digest, snapshot) = read_executable(File::open(&path).unwrap(), limit).unwrap();
    assert_eq!(digest, Sha256Digest::of(content));
    assert_eq!(snapshot.as_deref(), Some(content.as_slice()));

    let (streamed, snapshot) = read_executable(File::open(&path).unwrap(), limit - 1).unwrap();
    assert_eq!(streamed, digest);
    assert!(snapshot.is_none());
}

#[test]
fn pinned_executable_survives_replace_use_restore_and_pre_pin_passive() {
    let directory = tempfile::tempdir().unwrap();
    let operator = directory.path().join("teapot");
    let admitted = directory.path().join("teapot.admitted");
    fs::copy("/bin/true", &operator).unwrap();
    let teapot = Teapot::new(
        operator.to_str().unwrap().parse().unwrap(),
        ExecutableKind::Native,
        "/tmp".parse().unwrap(),
        Environment {
            home: "/tmp".parse().unwrap(),
            config_home: None,
            data_home: None,
            state_home: None,
            cache_home: None,
            runtime_dir: None,
        },
        BoundEngine {
            instance: "engine.fixture".parse().unwrap(),
            project_id: "project.fixture".parse().unwrap(),
            enforced: false,
            policy_locked: false,
        },
    );
    let passive = teapot.passive();
    let (digest, bytes) = read_executable(
        File::open(&operator).unwrap(),
        MAX_REQUEST_REFERENCE_EXECUTABLE_BYTES,
    )
    .unwrap();
    teapot
        .bound_executable
        .set(Arc::new(
            BoundExecutable::from_bytes(bytes.unwrap(), digest).unwrap(),
        ))
        .unwrap();

    fs::rename(&operator, &admitted).unwrap();
    fs::copy("/bin/false", &operator).unwrap();
    assert!(!Command::new(&operator).status().unwrap().success());
    assert!(teapot.run(&["version"]).unwrap().status.success());
    assert!(passive.command().status().unwrap().success());

    fs::remove_file(&operator).unwrap();
    fs::rename(&admitted, &operator).unwrap();
    assert!(Command::new(&operator).status().unwrap().success());
    assert!(teapot.run(&["version"]).unwrap().status.success());
}
