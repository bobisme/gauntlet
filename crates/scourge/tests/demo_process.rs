use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde_json::Value;

const README: &str = include_str!("../../../README.md");

struct Fixture {
    root: tempfile::TempDir,
    state: PathBuf,
    workspace: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        Self {
            state: root.path().join("state"),
            workspace: root.path().join("demo workspace"),
            root,
        }
    }

    fn run(&self, args: &[&str], exit: i32) -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_scourge"))
            .env_clear()
            .env("XDG_STATE_HOME", &self.state)
            .current_dir(self.root.path())
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(exit),
            "{:?} {} {}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stderr.is_empty());
        assert_eq!(out.stdout.iter().filter(|&&byte| byte == b'\n').count(), 1);
        let value: Value = scourge_core::wire::from_slice(&out.stdout).unwrap();
        assert_eq!(value["schema"], "scourge.response.v1");
        value
    }

    fn next(&self, response: &Value) -> Value {
        self.argv(&response["next"][0]["argv"])
    }

    fn argv(&self, argv: &Value) -> Value {
        let argv = argv.as_array().unwrap();
        assert_eq!(argv[0], "scourge");
        assert_eq!(argv[1], "--format");
        assert_eq!(argv[2], "json");
        let args: Vec<_> = argv[1..].iter().map(|arg| arg.as_str().unwrap()).collect();
        self.run(&args, 0)
    }
}

#[test]
fn demo_refuses_unqualified_executable_without_creating_state_or_executing_it() {
    let fixture = Fixture::new();
    let binary = fixture.root.path().join("teapot");
    fs::write(&binary, b"#!/bin/sh\ntouch started\n").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let value = fixture.run(
        &[
            "--json",
            "demo",
            fixture.workspace.to_str().unwrap(),
            "--teapot",
            binary.to_str().unwrap(),
        ],
        7,
    );
    assert_eq!(value["command"], "demo");
    assert_eq!(value["error"]["code"], "DEPENDENCY_UNAVAILABLE");
    assert_eq!(value["error"]["commit_status"], "not_committed");
    assert_eq!(value["effects"], "none");
    for key in ["workspace", "engagement", "run", "request_key", "finding"] {
        assert!(value[key].is_null(), "{key}");
    }
    assert!(!fixture.state.exists());
    assert!(!fixture.workspace.exists());
    assert!(!fixture.root.path().join("started").exists());
}

#[test]
fn demo_help_usage_and_workspace_collision_are_inert() {
    let fixture = Fixture::new();
    let help = fixture.run(&["--format", "json", "demo", "--help"], 0);
    assert!(
        help["help"]
            .as_str()
            .unwrap()
            .contains("scourge demo ./scourge-demo")
    );
    let missing = fixture.run(&["--format", "json", "demo"], 2);
    assert_eq!(missing["error"]["code"], "USAGE_ERROR");
    fs::create_dir(&fixture.workspace).unwrap();
    fs::write(fixture.workspace.join("scourge.toml"), b"operator content").unwrap();
    let collision = fixture.run(
        &[
            "--format",
            "json",
            "demo",
            fixture.workspace.to_str().unwrap(),
        ],
        3,
    );
    assert_eq!(collision["error"]["code"], "WORKSPACE_UNBOUND");
    assert_eq!(collision["error"]["commit_status"], "not_committed");
    assert_eq!(
        fs::read(fixture.workspace.join("scourge.toml")).unwrap(),
        b"operator content"
    );
    assert!(!fixture.state.exists());
}

struct Running<'a> {
    fixture: &'a Fixture,
    active: bool,
}

impl Running<'_> {
    fn stop(&mut self, argv: &Value) {
        let reply = self.fixture.argv(argv);
        self.active = false;
        assert_eq!(reply["result"], "demo-stopped");
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = Command::new(env!("CARGO_BIN_EXE_scourge"))
                .env_clear()
                .env("XDG_STATE_HOME", &self.fixture.state)
                .args(["--format", "json", "demo", "--stop", "--"])
                .arg(&self.fixture.workspace)
                .output();
        }
    }
}

fn qualified_path(key: &str) -> PathBuf {
    fs::canonicalize(std::env::var_os(key).unwrap_or_else(|| panic!("set {key}"))).unwrap()
}

fn assert_closed(address: SocketAddr) {
    assert!(TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err());
}

fn wait_closed(address: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture remained live"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "requires the exact qualified native executables and disposable loopback sockets"]
fn qualified_demo_follows_generated_argv_and_stops_owned_fixture() {
    let teapot = qualified_path("SCOURGE_TEAPOT_BIN");
    let investigation = qualified_path("SCOURGE_INVESTIGATION_BIN");
    let fixture = Fixture::new();
    let workspace = fixture.workspace.to_str().unwrap();
    let alias = format!(
        "//{}///demo workspace//",
        fixture
            .root
            .path()
            .display()
            .to_string()
            .trim_start_matches('/')
    );
    let original = b"# User text\n<!-- another tool's guide -->\n";
    fs::create_dir(&fixture.workspace).unwrap();
    fs::write(fixture.workspace.join("AGENTS.md"), original).unwrap();
    let start = fixture.run(
        &[
            "--format",
            "json",
            "demo",
            &alias,
            "--teapot",
            teapot.to_str().unwrap(),
            "--investigation",
            investigation.to_str().unwrap(),
        ],
        0,
    );
    let mut running = Running {
        fixture: &fixture,
        active: true,
    };
    assert_eq!(start["result"], "demo-ready");
    assert_eq!(start["workspace"], workspace);
    assert_eq!(
        start["demo"]["stop_argv"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        workspace
    );
    assert_eq!(start["engagement"], "demo");
    assert_eq!(start["effects"], "none");
    assert!(start["finding"].is_null() && start["run"].is_null());
    assert_eq!(start["managed_guide"]["status"], "installed");
    let guide = fs::read(fixture.workspace.join("AGENTS.md")).unwrap();
    assert!(guide.starts_with(original));
    assert_eq!(
        String::from_utf8_lossy(&guide)
            .matches("scourge:managed-start")
            .count(),
        1,
    );
    let origin = start["demo"]["target"].as_str().unwrap();
    let address: SocketAddr = origin.strip_prefix("http://").unwrap().parse().unwrap();
    assert_eq!(address.ip(), Ipv4Addr::LOCALHOST);
    assert!(TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok());
    let status = fixture.run(&["--json", "--workspace", &alias, "status"], 0);
    assert_eq!(status["workspace"], workspace);
    assert!(status["run"].is_null());
    let lead = fixture.next(&start);
    let lead_id = lead["lead"]["id"].as_str().unwrap();
    let plan = fixture.next(&lead);
    assert_eq!(plan["experiment"]["target_traffic"], false);
    assert_eq!(plan["experiment"]["pass_requests_spent"], 0);
    assert_eq!(plan["experiment"]["highest_status"], "verified");
    assert_eq!(plan["next"][0]["effects"], "plant");
    let verification = fixture.next(&plan);
    assert_eq!(verification["finding"]["status"], "verified");
    assert_eq!(verification["finding_caveats"]["after_owner_read"], false);
    assert_eq!(verification["run"]["cleanup"], "complete");
    let run_id = verification["run"]["id"].as_str().unwrap();
    let request_key = verification["request_key"].as_str().unwrap();
    let record = verification["verification"]["record_id"].as_str().unwrap();
    let finding_id = format!("finding:{lead_id}");
    let finding = fixture.run(
        &[
            "--json",
            "--workspace",
            workspace,
            "show",
            &finding_id,
            "--depth",
            "full",
        ],
        0,
    );
    assert_eq!(finding["finding_caveats"]["after_owner_read"], false);
    let full = fixture.run(
        &[
            "--json",
            "--workspace",
            workspace,
            "show",
            record,
            "--depth",
            "full",
        ],
        0,
    );
    assert_eq!(
        full["record"]["oracle_guide"],
        "docs/oracles/web.private-object-read.v1.md"
    );
    for args in [
        vec!["status", "--details", "setup"],
        vec!["list", "leads", "--limit", "10"],
        vec!["list", "runs", "--status", "finalized"],
        vec!["show", lead_id, "--depth", "summary"],
        vec!["show", run_id],
        vec!["run", "show", run_id],
        vec!["run", "show", "--request-key", request_key],
        vec!["doctor", "--engagement", "demo"],
        vec!["version"],
    ] {
        fixture.run(
            &[&["--json", "--workspace", workspace], args.as_slice()].concat(),
            0,
        );
    }
    let guide_witness = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/target/example/private-object-read-workflow.sh");
    let witness = Command::new("/bin/bash")
        .env_clear()
        .env("XDG_STATE_HOME", &fixture.state)
        .env("SCOURGE_BIN", env!("CARGO_BIN_EXE_scourge"))
        .env("PATH", "/usr/bin:/bin")
        .arg(guide_witness)
        .args([workspace, "demo"])
        .output()
        .unwrap();
    assert!(witness.status.success(), "{witness:?}");
    running.stop(&start["demo"]["stop_argv"]);
    assert_closed(address);
    assert!(Path::new(workspace).join("scourge.toml").is_file());
    assert!(!guide.is_empty());
}

#[test]
#[ignore = "requires the exact qualified native executables and disposable loopback sockets"]
fn committed_config_loss_stops_fixture_and_uses_private_fallback_control() {
    let teapot = qualified_path("SCOURGE_TEAPOT_BIN");
    let investigation = qualified_path("SCOURGE_INVESTIGATION_BIN");
    let fixture = Fixture::new();
    let workspace = fixture.workspace.to_str().unwrap();
    let start = fixture.run(
        &[
            "--format",
            "json",
            "demo",
            workspace,
            "--teapot",
            teapot.to_str().unwrap(),
            "--investigation",
            investigation.to_str().unwrap(),
        ],
        0,
    );
    let origin = start["demo"]["target"].as_str().unwrap();
    let address: SocketAddr = origin.strip_prefix("http://").unwrap().parse().unwrap();
    assert!(TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok());
    fs::remove_file(fixture.workspace.join("scourge.toml")).unwrap();
    wait_closed(address);

    let argv = start["demo"]["stop_argv"].as_array().unwrap();
    let args: Vec<_> = argv[1..].iter().map(|arg| arg.as_str().unwrap()).collect();
    let stopped = fixture.run(&args, 7);
    assert_eq!(stopped["error"]["code"], "DEPENDENCY_UNAVAILABLE");
    assert_eq!(stopped["error"]["commit_status"], "unknown");
    assert_eq!(stopped["workspace"], workspace);
}

#[test]
#[ignore = "requires the exact qualified native executables, jq and disposable loopback sockets"]
fn readme_tutorial_runs_in_a_fresh_directory() {
    let fixture = Fixture::new();
    let bin = fixture.root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    for (name, source) in [
        ("scourge", PathBuf::from(env!("CARGO_BIN_EXE_scourge"))),
        ("teapot", qualified_path("SCOURGE_TEAPOT_BIN")),
        ("investigation", qualified_path("SCOURGE_INVESTIGATION_BIN")),
    ] {
        std::os::unix::fs::symlink(source, bin.join(name)).unwrap();
    }
    let script = README
        .split_once("```sh\n")
        .unwrap()
        .1
        .split_once("\n```")
        .unwrap()
        .0;
    let output = Command::new("/bin/bash")
        .env_clear()
        .env("XDG_STATE_HOME", &fixture.state)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(fixture.root.path())
        .args(["-euo", "pipefail", "-c", script])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("demo  demo-stopped"));
}
