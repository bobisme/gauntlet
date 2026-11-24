#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
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
    canonical::Sha256Digest,
    teapot::{BoundEngine, Environment, ExecutableKind, InvocationError, SessionState, Teapot},
    template::Method,
    wire::{AbsolutePath, DiagnosticCode, ErrorCode},
};
use serde_json::{Value, json};

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
    fs::write(&program, format!("#!/bin/sh\n{contents}\n")).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
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

struct TestProject {
    binary: PathBuf,
    project: PathBuf,
    environment: Environment,
    root: Option<tempfile::TempDir>,
    start_attempted: bool,
}

impl TestProject {
    fn command(&self, words: &[&str]) -> std::io::Result<Output> {
        Command::new(&self.binary)
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
            .stdin(Stdio::null())
            .output()
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
    request_headers: Arc<Mutex<Vec<Vec<String>>>>,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/probe", listener.local_addr().unwrap());
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

#[test]
#[ignore = "requires SCOURGE_PINNED_TEAPOT and a disposable loopback listener"]
fn pinned_teapot_exercises_each_operation() {
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
    let mut project = TestProject {
        binary,
        project: fs::canonicalize(directory).unwrap(),
        environment: environment(root.path()),
        root: Some(root),
        start_attempted: false,
    };
    project.run(&["projects", "init"]);
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
