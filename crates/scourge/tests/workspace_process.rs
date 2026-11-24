use scourge_core::wire::{self, ErrorCode, ResponseV1};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

const E: &[u8] = include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");
fn run(cwd: &Path, state: &Path, args: &[&str]) -> Output {
    run_with_home(cwd, state, args, cwd)
}
fn run_with_home(cwd: &Path, state: &Path, args: &[&str], home: &Path) -> Output {
    bounded(
        Command::new(env!("CARGO_BIN_EXE_scourge"))
            .current_dir(cwd)
            .env("XDG_STATE_HOME", state)
            .env("HOME", home)
            .env_remove("FORMAT")
            .args(args),
    )
}
fn bounded(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= until {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("CLI timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn json(out: Output, code: i32) -> ResponseV1 {
    assert_eq!(out.status.code(), Some(code), "{out:?}");
    wire::from_slice(&out.stdout).unwrap()
}
#[test]
fn init_add_select_and_invalid_binding_are_process_visible() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let root = t.path().join("work");
    let first = t.path().join("my.engagement.toml");
    let second = t.path().join("second.toml");
    fs::write(&first, E).unwrap();
    fs::write(&second, E).unwrap();
    let root = root.to_str().unwrap();
    let first = first.to_str().unwrap();
    let second = second.to_str().unwrap();
    let initialized = json(
        run(
            t.path(),
            &state,
            &["--json", "init", root, "--engagement", first],
        ),
        0,
    );
    assert_eq!(
        initialized.extensions["engagements"],
        serde_json::json!(["my.engagement"])
    );
    let store = state.join("scourge");
    let binding = fs::read_dir(&store)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            !path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("pending-")
        })
        .unwrap();
    fs::remove_file(binding).unwrap();
    assert!(
        json(
            run(
                t.path(),
                &state,
                &["--json", "init", root, "--engagement", first]
            ),
            0
        )
        .ok
    );
    let nested = Path::new(root).join("nested");
    fs::create_dir(&nested).unwrap();
    assert_eq!(
        json(run(&nested, &state, &["status", "--json"]), 0)
            .result
            .unwrap()
            .as_str(),
        "bound"
    );
    let added = json(
        run(
            t.path(),
            &state,
            &[
                "--json",
                "--workspace",
                root,
                "engagement",
                "add",
                second,
                "--name",
                "second",
            ],
        ),
        0,
    );
    assert_eq!(
        added.extensions["engagements"],
        serde_json::json!(["my.engagement", "second"])
    );
    assert_eq!(
        json(run(&nested, &state, &["--json", "engagement", "show"]), 3)
            .error
            .unwrap()
            .code,
        ErrorCode::EngagementRequired
    );
    assert_eq!(
        json(
            run(
                &nested,
                &state,
                &["--json", "--engagement", "second", "engagement", "show"]
            ),
            0
        )
        .engagement
        .unwrap()
        .as_str(),
        "second"
    );
    assert!(
        json(
            run(
                &nested,
                &state,
                &["--json", "engagement", "add", second, "--name", "second"]
            ),
            0
        )
        .ok
    );
    let chosen = json(
        run(
            &nested,
            &state,
            &["--json", "status", "--engagement", "second"],
        ),
        0,
    );
    assert_eq!(chosen.engagement.unwrap().as_str(), "second");
    assert_eq!(
        json(
            run(
                &nested,
                &state,
                &["--json", "status", "--engagement", "missing"]
            ),
            3
        )
        .error
        .unwrap()
        .code,
        ErrorCode::ObjectNotFound
    );
    let cfg = fs::read(Path::new(root).join("scourge.toml")).unwrap();
    fs::write(
        Path::new(root).join("scourge.toml"),
        [cfg.as_slice(), b"\n# changed"].concat(),
    )
    .unwrap();
    assert_eq!(
        json(
            run(&nested, &state, &["--json", "--workspace", root, "status"]),
            3
        )
        .error
        .unwrap()
        .code,
        ErrorCode::WorkspaceUnbound
    );
    let blocked = json(run(&nested, &state, &["--json"]), 0);
    assert_eq!(blocked.blockers, [ErrorCode::WorkspaceUnbound]);
    assert!(blocked.extensions.contains_key("orientation"));
}
#[cfg(unix)]
#[test]
fn hostile_nested_config_never_dispatches_or_reads_foreign_fifo() {
    use std::os::unix::{
        fs::{OpenOptionsExt, symlink},
        net::{UnixListener, UnixStream},
    };
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let root = t.path().join("root");
    let nested = root.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir(&state).unwrap();
    let engagement = t.path().join("initial.toml");
    fs::write(&engagement, E).unwrap();
    assert!(
        json(
            run(
                t.path(),
                &state,
                &[
                    "--json",
                    "init",
                    root.to_str().unwrap(),
                    "--engagement",
                    engagement.to_str().unwrap()
                ]
            ),
            0
        )
        .ok
    );
    let fifo = t.path().join("foreign");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut witness = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(2048)
        .open(&fifo)
        .unwrap();
    witness.write_all(b"foreign-secret").unwrap();
    let secret = t.path().join("secret");
    assert!(
        Command::new("mkfifo")
            .arg(&secret)
            .status()
            .unwrap()
            .success()
    );
    let mut secret_witness = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(2048)
        .open(&secret)
        .unwrap();
    secret_witness.write_all(b"credential").unwrap();
    let sock = t.path().join("socket");
    let target = t.path().join("target");
    let socket_listener = UnixListener::bind(&sock).unwrap();
    let target_listener = UnixListener::bind(&target).unwrap();
    socket_listener.set_nonblocking(true).unwrap();
    target_listener.set_nonblocking(true).unwrap();
    drop(UnixStream::connect(&sock).unwrap());
    drop(socket_listener.accept().unwrap());
    drop(UnixStream::connect(&target).unwrap());
    drop(target_listener.accept().unwrap());
    let sentinel = t.path().join("invoked");
    let adapter = t.path().join("adapter");
    fs::write(
        t.path().join(".scourge-test-script"),
        ": > \"$HOME/invoked\"\n",
    )
    .unwrap();
    let launcher = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scourge-core/tests/fixtures/test-script-launcher.sh");
    symlink(&launcher, &adapter).unwrap();
    for program in ["teapot", "uname"] {
        symlink(&launcher, t.path().join(program)).unwrap();
    }
    assert!(
        Command::new(&adapter)
            .env("PATH", t.path())
            .env("HOME", t.path())
            .status()
            .unwrap()
            .success()
    );
    assert!(sentinel.exists());
    fs::remove_file(&sentinel).unwrap();
    symlink(&fifo, nested.join("evidence")).unwrap();
    fs::write(nested.join("scourge.toml"),format!("version = 1\nworkspace_id = \"00000000-0000-4000-8000-000000000001\"\nadapter = \"{}\"\nsocket = \"{}\"\ncredential = \"{}\"\nevidence_root = \"{}\"\ntarget = \"{}\"\n",adapter.display(),sock.display(),secret.display(),nested.join("evidence").display(),target.display())).unwrap();
    let config = nested.join("scourge.toml");
    let held = nested.join("hostile.config");
    fs::rename(&config, &held).unwrap();
    assert_eq!(
        json(
            run_with_home(&nested, &state, &["--json", "status"], t.path()),
            0
        )
        .result
        .unwrap()
        .as_str(),
        "bound"
    );
    assert!(
        !sentinel.exists(),
        "ancestor binding must not dispatch the hostile nested adapter"
    );
    fs::rename(&held, &config).unwrap();
    assert_eq!(
        json(
            run_with_home(
                &nested,
                &state,
                &["--json", "--workspace", root.to_str().unwrap(), "status"],
                t.path(),
            ),
            0
        )
        .result
        .unwrap()
        .as_str(),
        "bound"
    );
    assert!(
        !sentinel.exists(),
        "explicit ancestor selection must not dispatch the nested adapter"
    );
    assert_eq!(
        json(
            run_with_home(
                &nested,
                &state,
                &["--json", "--workspace", ".", "status"],
                t.path(),
            ),
            3
        )
        .error
        .unwrap()
        .code,
        ErrorCode::WorkspaceUnbound
    );
    assert!(
        !sentinel.exists(),
        "unbound nested selection must not dispatch the adapter"
    );
    for (args, code) in [
        (&["--json"][..], 0),
        (&["--json", "status"][..], 0),
        (&["--json", "--help"][..], 0),
        (&["--json", "--workspace", ".", "status"][..], 3),
    ] {
        let out = bounded(
            Command::new(env!("CARGO_BIN_EXE_scourge"))
                .current_dir(&nested)
                .env("XDG_STATE_HOME", &state)
                .env("HOME", t.path())
                .env("PATH", t.path())
                .env_remove("FORMAT")
                .args(args),
        );
        let response = json(out, code);
        if args.contains(&"--help") {
            assert_eq!(response.result.unwrap().as_str(), "help");
        } else {
            if code == 0 {
                assert_eq!(response.blockers, [ErrorCode::WorkspaceUnbound]);
            } else {
                assert_eq!(response.error.unwrap().code, ErrorCode::WorkspaceUnbound);
            }
            assert!(response.extensions.contains_key("orientation"));
        }
    }
    assert!(!sentinel.exists());
    assert_eq!(
        socket_listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        target_listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let mut secret_remaining = [0u8; 10];
    secret_witness.read_exact(&mut secret_remaining).unwrap();
    assert_eq!(&secret_remaining, b"credential");
    let mut remaining = [0u8; 14];
    witness.read_exact(&mut remaining).unwrap();
    assert_eq!(&remaining, b"foreign-secret");
}
#[test]
fn orientation_formats_and_missing_input_are_typed() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    for format in ["text", "pretty"] {
        let o = run(t.path(), &state, &["--format", format, "status"]);
        assert!(o.status.success());
        assert!(
            String::from_utf8(o.stdout)
                .unwrap()
                .contains("scourge init PATH --engagement FILE")
        );
    }
    let response = json(run(t.path(), &state, &["--json", "init", "workspace"]), 3);
    assert_eq!(response.error.unwrap().code, ErrorCode::InputRequired);
    for args in [
        &["--json", "--workspace", ".", "status"][..],
        &["--json", "--engagement", "x", "engagement", "show"],
    ] {
        let response = json(run(t.path(), Path::new("relative-state"), args), 3);
        assert_eq!(response.error.unwrap().code, ErrorCode::WorkspaceUnbound);
        assert!(response.extensions.contains_key("orientation"));
    }
    let text = run(
        t.path(),
        Path::new("relative-state"),
        &["--format", "text", "--workspace", ".", "status"],
    );
    assert!(
        String::from_utf8(text.stderr)
            .unwrap()
            .contains("scourge init PATH --engagement FILE")
    );
    for args in [
        &["--json", "engagement", "show", "--help"][..],
        &["--json", "help", "engagement", "show"],
    ] {
        let response = json(run(t.path(), &state, args), 0);
        assert_eq!(response.command.unwrap().as_str(), "engagement show");
        assert!(
            response.extensions["help"]
                .as_str()
                .unwrap()
                .contains("Usage: scourge engagement show")
        );
    }
    let help = run(
        t.path(),
        &state,
        &["--format", "text", "engagement", "show", "--help"],
    );
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("Usage: scourge engagement show")
    );
}

#[test]
fn engagement_group_help_is_rendered_before_workspace_resolution() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("not-created");
    for args in [
        &["--json", "engagement", "--help"][..],
        &["--json", "--workspace", "missing", "engagement", "--help"],
        &["--json", "help", "engagement"],
    ] {
        let response = json(run(t.path(), &state, args), 0);
        assert_eq!(response.command.unwrap().as_str(), "engagement");
        assert_eq!(response.result.unwrap().as_str(), "help");
        let help = response.extensions["help"].as_str().unwrap();
        assert!(help.contains("Usage: scourge engagement"));
        assert!(help.contains("show") && help.contains("add"));
    }
    let text = run(
        t.path(),
        &state,
        &["--format", "text", "engagement", "--help"],
    );
    assert!(text.status.success());
    assert!(
        String::from_utf8(text.stdout)
            .unwrap()
            .contains("Usage: scourge engagement")
    );
    let usage = json(run(t.path(), &state, &["--json", "engagement"]), 2);
    assert_eq!(usage.error.unwrap().code, ErrorCode::UsageError);
    assert!(!state.exists());
}

#[test]
fn engagement_names_preserve_json_identity_and_escape_human_controls() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let root = t.path().join("root");
    let declaration = t.path().join("one.toml");
    fs::write(&declaration, E).unwrap();
    let root = root.to_str().unwrap();
    let file = declaration.to_str().unwrap();
    assert!(
        json(
            run(
                t.path(),
                &state,
                &["--json", "init", root, "--engagement", file]
            ),
            0
        )
        .ok
    );
    let name = "line\nforged\tescape\u{1b}";
    assert!(
        json(
            run(
                t.path(),
                &state,
                &[
                    "--json",
                    "--workspace",
                    root,
                    "engagement",
                    "add",
                    file,
                    "--name",
                    name
                ]
            ),
            0
        )
        .ok
    );
    let response = json(
        run(t.path(), &state, &["--json", "--workspace", root, "status"]),
        0,
    );
    assert!(
        response.extensions["engagements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(name))
    );
    for format in ["text", "pretty"] {
        let output = run(
            t.path(),
            &state,
            &["--format", format, "--workspace", root, "status"],
        );
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("line\\nforged\\tescape\\u{1b}"));
        assert!(!text.contains(name));
        assert!(!text.contains('\u{1b}'));
    }
}

#[cfg(unix)]
#[test]
fn unbound_add_does_not_open_a_fifo_or_its_symlink() {
    use std::os::unix::fs::symlink;
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    fs::create_dir(&state).unwrap();
    let fifo = t.path().join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let link = t.path().join("link");
    symlink(&fifo, &link).unwrap();
    for path in [&fifo, &link] {
        let response = json(
            run(
                t.path(),
                &state,
                &[
                    "--json",
                    "engagement",
                    "add",
                    path.to_str().unwrap(),
                    "--name",
                    "x",
                ],
            ),
            3,
        );
        assert_eq!(response.error.unwrap().code, ErrorCode::WorkspaceUnbound);
    }
}
