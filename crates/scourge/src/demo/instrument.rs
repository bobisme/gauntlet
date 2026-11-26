use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddr,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::fs::{Mode, OFlags, open};
use scourge_core::{
    canonical::Sha256Digest, teapot::BoundEngine, workspace::TeapotProjectAuthority,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::process::{self, OwnedChild};

const PIN: &str = include_str!("../../../../fixtures/contracts/manifest.json");
const MAX_BINARY: u64 = 384 * 1024 * 1024;
pub(super) const SESSIONS: [&str; 5] = [
    "alice",
    "bob",
    "alice_verify",
    "bob_verify",
    "scourge_anonymous",
];

pub(super) fn qualified_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let pin: serde_json::Value = serde_json::from_str(PIN)?;
    let file = File::from(open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(process::invalid());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BINARY + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BINARY
        || Some(Sha256Digest::of(&bytes).as_str()) != pin["binary_sha256"].as_str()
    {
        return Err(process::invalid());
    }
    Ok(bytes)
}

pub(super) struct Instrument {
    pub(super) paths: TeapotProjectAuthority,
    pub(super) pass: PathBuf,
}

impl Instrument {
    pub(super) fn new(home: &Path, runtime: &Path) -> Self {
        Self {
            paths: TeapotProjectAuthority {
                executable: home.join("teapot"),
                project: home.join("project"),
                home: home.to_owned(),
                config_home: None,
                data_home: None,
                state_home: None,
                cache_home: None,
                runtime_dir: Some(runtime.to_owned()),
                wrapper: false,
            },
            pass: home.join("demo.pass.toml"),
        }
    }

    pub(super) fn stage(&self, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&self.paths.executable)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::create_dir(&self.paths.project)?;
        Ok(())
    }

    fn command(&self, words: &[&str]) -> Command {
        let mut command = Command::new(&self.paths.executable);
        command
            .env_clear()
            .env("HOME", &self.paths.home)
            .env(
                "XDG_RUNTIME_DIR",
                self.paths.runtime_dir.as_ref().expect("runtime"),
            )
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .current_dir(&self.paths.project)
            .arg("--project")
            .arg(&self.paths.project)
            .arg("--json")
            .args(words);
        command
    }

    pub(super) fn configure(
        &self,
        target: SocketAddr,
        expires: OffsetDateTime,
        cookies: &[String; 4],
    ) -> io::Result<Sha256Digest> {
        let from = (OffsetDateTime::now_utc() - time::Duration::minutes(1))
            .format(&Rfc3339)
            .map_err(io::Error::other)?;
        let until = expires.format(&Rfc3339).map_err(io::Error::other)?;
        let port = target.port();
        let pass = format!(
            r#"format = 1
id = "pass.development-fixture"
name = "Scourge local tutorial"

[approval]
owner = "Scourge demo"
reference = "owned-loopback-fixture"
operator = "Scourge demo"
valid_from = "{from}"
valid_until = "{until}"
revoked = false

[[destination]]
label = "owned-loopback"
address = "127.0.0.1"
protocol = "tcp"
ports = [{port}]

[ceilings]
requests = 2000
"#
        );
        let mut pass_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.pass)?;
        pass_file.write_all(pass.as_bytes())?;
        pass_file.sync_all()?;
        process::native(&mut self.command(&["projects", "init"]), None)?;
        process::native(&mut self.command(&["scope", "add", "127.0.0.1"]), None)?;
        process::native(
            &mut self.command(&["config", "set", "pass.relay", "block"]),
            None,
        )?;
        process::native(
            &mut self.command(&["config", "set", "pass.required", "true"]),
            None,
        )?;
        for (name, cookie) in SESSIONS.into_iter().zip(cookies) {
            process::native(
                &mut self.command(&[
                    "sessions",
                    "create",
                    name,
                    "--domain",
                    "127.0.0.1",
                    "--cookie",
                    "scourge_session=-",
                ]),
                Some(cookie),
            )?;
        }
        process::native(
            &mut self.command(&["sessions", "create", "scourge_anonymous"]),
            None,
        )?;
        self.install_macros(target)?;
        Ok(Sha256Digest::of(pass.as_bytes()))
    }

    fn install_macros(&self, target: SocketAddr) -> io::Result<()> {
        let directory = self.paths.project.join(".teapot/macros");
        fs::create_dir_all(&directory)?;
        for (name, route) in [
            ("order", "orders"),
            ("invoice", "invoices"),
            ("tenant-note", "tenant-notes"),
            ("bulletin", "bulletins"),
            ("catalog-entry", "catalog"),
            ("private-report", "private-reports"),
            ("cached-report", "cached-reports"),
            ("login-report", "login-reports"),
            ("stale-report", "stale-reports"),
            ("forbidden-report", "forbidden-reports"),
            ("echo-report", "echo-reports"),
            ("expiring-report", "expiring-reports"),
        ] {
            let body = format!(
                "format = 1\n\n[[steps]]\nstate_changing = true\n[steps.request]\nmethod = \"POST\"\nurl = \"http://{target}/app/api/{route}\"\n"
            );
            fs::write(directory.join(format!("create-{name}.toml")), body)?;
        }
        Ok(())
    }

    pub(super) fn start(&self) -> io::Result<OwnedChild> {
        let _ = qualified_bytes(&self.paths.executable)?;
        let mut command = self.command(&[
            "proxy",
            "start",
            "--listen",
            "127.0.0.1:0",
            "--lock-policy",
            "--pass",
            self.pass.to_str().ok_or_else(process::invalid)?,
        ]);
        let supervisor = rustix::process::getpid();
        // SAFETY: the pre-exec closure only calls Linux process syscalls and
        // constructs an OS error. The second check closes the parent-exit race.
        unsafe {
            command.pre_exec(move || {
                rustix::process::set_parent_process_death_signal(Some(
                    rustix::process::Signal::KILL,
                ))?;
                if rustix::process::getppid() != Some(supervisor) {
                    return Err(io::Error::from_raw_os_error(
                        rustix::io::Errno::CHILD.raw_os_error(),
                    ));
                }
                Ok(())
            });
        }
        OwnedChild::spawn(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
    }

    pub(super) fn ready(&self, owned_pid: u32) -> io::Result<BoundEngine> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(reply) = process::native(&mut self.command(&["proxy", "status"]), None)
                && let Some(status) = reply["proxy"]["engine"].as_object()
            {
                let value = serde_json::Value::Object(status.clone());
                let listener: SocketAddr = value["listener"]
                    .as_str()
                    .and_then(|text| text.parse().ok())
                    .ok_or_else(process::invalid)?;
                if value["pid"].as_u64() != Some(u64::from(owned_pid))
                    || value["project"].as_str() != self.paths.project.to_str()
                    || value["pass"].as_str() != self.pass.to_str()
                    || value["mode"] != "regular"
                    || value["policy_locked"] != true
                    || listener.ip() != std::net::Ipv4Addr::LOCALHOST
                {
                    return Err(process::invalid());
                }
                let pass = process::native(&mut self.command(&["pass", "show"]), None)?;
                if pass["pass"]["relay"] != "block" || pass["pass"]["required"] != true {
                    return Err(process::invalid());
                }
                return Ok(BoundEngine {
                    instance: value["instance"]
                        .as_str()
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(process::invalid)?,
                    project_id: value["project_id"]
                        .as_str()
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(process::invalid)?,
                    enforced: value["enforced"].as_bool().ok_or_else(process::invalid)?,
                    policy_locked: value["policy_locked"]
                        .as_bool()
                        .ok_or_else(process::invalid)?,
                });
            }
            if Instant::now() >= deadline {
                return Err(process::invalid());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub(super) fn stop(&self) -> io::Result<()> {
        process::native(&mut self.command(&["proxy", "stop"]), None).map(|_| ())
    }
}
