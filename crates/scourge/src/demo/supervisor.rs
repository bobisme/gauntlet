use std::{
    collections::HashSet,
    env,
    ffi::OsStr,
    fs, io,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use scourge_core::{
    canonical::Sha256Digest,
    workspace::{self, DemoControl},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    instrument::Instrument,
    process::{self, OwnedChild},
};

const CHILD: &str = "--_scourge-demo-fixture";
const BOOT: Duration = Duration::from_secs(45);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    home: PathBuf,
    workspace: PathBuf,
    state: PathBuf,
    expires: i64,
    token: Uuid,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fixture {
    pub(super) address: SocketAddr,
    pub(super) runtime: PathBuf,
    pub(super) cookies: [String; 4],
}

pub(super) struct Supervisor {
    child: Option<OwnedChild>,
    input: Option<ChildStdin>,
    output: ChildStdout,
}

impl Supervisor {
    pub(super) fn start(
        home: &Path,
        workspace: &Path,
        state: &Path,
        expires: OffsetDateTime,
        token: Uuid,
    ) -> io::Result<(Self, Fixture)> {
        let mut child = OwnedChild::spawn(
            Command::new(env::current_exe()?)
                .arg(CHILD)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null()),
        )?;
        let input = child.child().stdin.take().ok_or_else(process::invalid)?;
        let output = child.child().stdout.take().ok_or_else(process::invalid)?;
        let mut service = Self {
            child: Some(child),
            input: Some(input),
            output,
        };
        service.send(&Bootstrap {
            home: home.to_owned(),
            workspace: workspace.to_owned(),
            state: state.to_owned(),
            expires: expires.unix_timestamp(),
            token,
        })?;
        let fixture: Fixture = process::receive(&mut service.output, BOOT)?;
        if fixture.address.ip() != Ipv4Addr::LOCALHOST
            || fixture.address.port() == 0
            || !fixture.runtime.is_absolute()
        {
            return Err(process::invalid());
        }
        Ok((service, fixture))
    }

    pub(super) fn start_engine(&mut self) -> io::Result<u32> {
        self.send(&Stage::Start)?;
        process::receive(&mut self.output, BOOT)
    }

    pub(super) fn keep(mut self) -> io::Result<()> {
        let armed = self
            .send(&Stage::Commit)
            .and_then(|()| process::receive::<bool>(&mut self.output, Duration::from_secs(2)));
        // The prepared intent owns the child now. Even a lost response
        // leaves its authenticated control endpoint available to a retry.
        self.child.take().expect("supervisor").detach();
        armed.and_then(|ack| if ack { Ok(()) } else { Err(process::invalid()) })
    }

    fn send(&mut self, request: &impl Serialize) -> io::Result<()> {
        process::send(self.input.as_mut().ok_or_else(process::invalid)?, request)
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // EOF makes the supervisor stop its owned engine and remove the
        // transient socket directory. Let it unwind before forcing cleanup.
        self.input.take();
        if let Some(child) = self.child.as_ref() {
            let deadline = Instant::now() + Duration::from_secs(2);
            while child.running().unwrap_or(false) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
enum Stage {
    Start,
    Commit,
}

pub fn run_fixture_child_if_requested() -> Option<u8> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new(CHILD)) || arguments.next().is_some() {
        return None;
    }
    Some(if child_main().is_ok() { 0 } else { 1 })
}

fn child_main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let spec: Bootstrap = process::receive(&mut input, BOOT)?;
    let home = private_home(&spec)?;
    let _lease = workspace::demo_supervisor_lease(&home)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if spec.expires <= now || spec.expires > now + 8 * 60 * 60 {
        return Err(process::invalid());
    }
    // The native Unix control socket's platform length limit is independent
    // of the operator's state path or the workspace's name.
    let runtime = tempfile::Builder::new()
        .prefix("scourge-demo-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
    let socket = runtime.path().join("stop.sock");
    let control = DemoControl {
        socket: socket.clone(),
        token: spec.token,
        expires: spec.expires,
    };
    let stop = UnixListener::bind(&socket)?;
    stop.set_nonblocking(true)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (app, cookies) = scourge_fixture::demo_app(
        Uuid::new_v4().to_string(),
        [Uuid::new_v4().to_string(), Uuid::new_v4().to_string()],
    );
    listener.set_nonblocking(true)?;
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let fixture = thread::spawn(move || -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener)?;
            ready_tx.send(()).map_err(io::Error::other)?;
            tokio::select! {
                result = axum::serve(listener, app) => result,
                _ = stopped => Ok(()),
            }
        })
    });
    ready_rx.recv_timeout(BOOT).map_err(io::Error::other)?;
    process::send(
        &mut output,
        &Fixture {
            address,
            runtime: runtime.path().to_owned(),
            cookies,
        },
    )?;
    if process::receive::<Stage>(&mut input, BOOT)? != Stage::Start {
        return Err(process::invalid());
    }
    let instrument = Instrument::new(&home, runtime.path());
    let mut engine = instrument.start()?;
    process::send(&mut output, &engine.child().id())?;
    let commit = process::receive::<Stage>(&mut input, BOOT);
    let mut anchor = workspace::demo_pending(&spec.workspace, &spec.state, &control)
        .ok_or_else(process::invalid)?;
    if !engine.running()? || fixture.is_finished() {
        return Err(process::invalid());
    }
    // If the parent died after the authority was committed, keep the
    // already-published runtime. The same private endpoint can still stop it.
    if matches!(commit, Ok(Stage::Commit)) {
        let _ = process::send(&mut output, &true);
    }
    // No output descriptor from the public command is inherited by the
    // engine or fixture. This pipe was private to startup.
    drop(output);
    let stop_client = wait_for_stop(&stop, &engine, &fixture, &spec, &mut anchor)?;
    if engine.running()? {
        let _ = instrument.stop();
    }
    drop(engine);
    let _ = shutdown.send(());
    fixture.join().map_err(|_| process::invalid())??;
    if let Some((mut client, request)) = stop_client {
        process::send(&mut client, &proof(spec.token, &request, b"stopped"))?;
    }
    Ok(())
}

fn private_home(spec: &Bootstrap) -> io::Result<PathBuf> {
    let home = fs::canonicalize(&spec.home)?;
    let metadata = fs::symlink_metadata(&spec.home)?;
    if home != spec.home
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || !spec.workspace.is_absolute()
        || home.starts_with(&spec.workspace)
        || home.parent() != Some(spec.state.join("scourge").as_path())
    {
        return Err(process::invalid());
    }
    Ok(home)
}

fn wait_for_stop(
    stop: &UnixListener,
    engine: &OwnedChild,
    fixture: &thread::JoinHandle<io::Result<()>>,
    spec: &Bootstrap,
    anchor: &mut workspace::DemoAnchor,
) -> io::Result<Option<(UnixStream, Request)>> {
    let mut activated = false;
    let mut nonces = HashSet::new();
    while engine.running()?
        && !fixture.is_finished()
        && OffsetDateTime::now_utc().unix_timestamp() < spec.expires
        && anchor.current()
    {
        if activated && !anchor.healthy() {
            break;
        }
        match stop.accept() {
            Ok((mut client, _)) => {
                let Some(request) = receive_authenticated(&mut client, spec.token, &mut nonces)
                else {
                    continue;
                };
                if request.action == Action::Stop {
                    return Ok(Some((client, request)));
                }
                let label = if request.action == Action::Activate {
                    if !anchor.activate() {
                        continue;
                    }
                    activated = true;
                    b"activated".as_slice()
                } else {
                    b"ready".as_slice()
                };
                let _ = process::send(&mut client, &proof(spec.token, &request, label));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
            Err(error) => return Err(error),
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(None)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub(super) enum Action {
    Ping,
    Activate,
    Stop,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: Action,
    nonce: Uuid,
    proof: Sha256Digest,
}

fn proof(token: Uuid, request: &Request, label: &[u8]) -> Sha256Digest {
    let action: &[u8] = match request.action {
        Action::Ping => b"ping",
        Action::Activate => b"activate",
        Action::Stop => b"stop",
    };
    Sha256Digest::of(
        &[
            b"scourge demo control v1 ",
            label,
            action,
            request.nonce.as_bytes(),
            token.as_bytes(),
        ]
        .concat(),
    )
}

fn authenticated(token: Uuid, request: &Request, label: &[u8], observed: &Sha256Digest) -> bool {
    observed == &proof(token, request, label)
}

fn receive_authenticated(
    stream: &mut UnixStream,
    token: Uuid,
    nonces: &mut HashSet<Uuid>,
) -> Option<Request> {
    // The listener is a public local boundary. EOF, truncation, oversized
    // frames, timeouts, and decode failures belong to this client only.
    let request: Request = process::receive(stream, Duration::from_secs(1)).ok()?;
    if !authenticated(token, &request, b"request", &request.proof) || !nonces.insert(request.nonce)
    {
        return None;
    }
    Some(request)
}

pub(super) fn command(control: &DemoControl, action: Action) -> io::Result<()> {
    command_stream(UnixStream::connect(&control.socket)?, control, action)
}

fn command_stream(mut stream: UnixStream, control: &DemoControl, action: Action) -> io::Result<()> {
    let mut request = Request {
        action,
        nonce: Uuid::new_v4(),
        proof: Sha256Digest::of(b""),
    };
    request.proof = proof(control.token, &request, b"request");
    process::send(&mut stream, &request)?;
    let (label, wait): (&[u8], Duration) = match action {
        Action::Ping => (b"ready", Duration::from_secs(2)),
        Action::Activate => (b"activated", Duration::from_secs(2)),
        Action::Stop => (b"stopped", Duration::from_secs(12)),
    };
    let reply: Sha256Digest = process::receive(&mut stream, wait)?;
    if !authenticated(control.token, &request, label, &reply) {
        return Err(process::invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn control(path: PathBuf) -> DemoControl {
        DemoControl {
            socket: path,
            expires: 4_102_444_800,
            token: Uuid::new_v4(),
        }
    }

    #[test]
    fn control_authentication_binds_token_nonce_action_and_reply_stage() {
        let token = Uuid::new_v4();
        let mut request = Request {
            action: Action::Stop,
            nonce: Uuid::new_v4(),
            proof: Sha256Digest::of(b""),
        };
        request.proof = proof(token, &request, b"request");
        assert!(authenticated(token, &request, b"request", &request.proof));
        assert!(!authenticated(
            Uuid::new_v4(),
            &request,
            b"request",
            &request.proof
        ));

        let reply = proof(token, &request, b"stopped");
        assert!(authenticated(token, &request, b"stopped", &reply));
        assert!(!authenticated(token, &request, b"ready", &reply));

        let original_nonce = request.nonce;
        request.nonce = Uuid::new_v4();
        assert!(!authenticated(token, &request, b"stopped", &reply));
        request.nonce = original_nonce;
        request.action = Action::Ping;
        assert!(!authenticated(token, &request, b"stopped", &reply));
    }

    #[test]
    fn stop_never_succeeds_for_missing_or_refused_socket() {
        let temp = tempfile::tempdir().unwrap();
        let missing = control(temp.path().join("missing.sock"));
        assert!(command(&missing, Action::Stop).is_err());

        let refused_path = temp.path().join("refused.sock");
        fs::write(&refused_path, b"not a control socket").unwrap();
        assert!(command(&control(refused_path), Action::Stop).is_err());
    }

    #[test]
    fn authenticated_nonce_replay_is_rejected_over_a_real_socket() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let token = Uuid::new_v4();
        let mut request = Request {
            action: Action::Ping,
            nonce: Uuid::new_v4(),
            proof: Sha256Digest::of(b""),
        };
        request.proof = proof(token, &request, b"request");
        let mut seen = HashSet::new();

        let mut first = UnixStream::connect(&path).unwrap();
        process::send(&mut first, &request).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        assert_eq!(
            receive_authenticated(&mut accepted, token, &mut seen)
                .unwrap()
                .nonce,
            request.nonce
        );

        let mut replay = UnixStream::connect(&path).unwrap();
        process::send(&mut replay, &request).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        assert!(receive_authenticated(&mut accepted, token, &mut seen).is_none());
    }

    #[test]
    fn malformed_eof_and_oversized_clients_do_not_poison_the_listener() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let token = Uuid::new_v4();
        let mut seen = HashSet::new();

        let eof = UnixStream::connect(&path).unwrap();
        drop(eof);
        let (mut accepted, _) = listener.accept().unwrap();
        assert!(receive_authenticated(&mut accepted, token, &mut seen).is_none());

        let mut truncated = UnixStream::connect(&path).unwrap();
        truncated.write_all(b"{\"action\":\n").unwrap();
        drop(truncated);
        let (mut accepted, _) = listener.accept().unwrap();
        assert!(receive_authenticated(&mut accepted, token, &mut seen).is_none());

        let mut oversized = UnixStream::connect(&path).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        let writer = thread::spawn(move || {
            let _ = oversized.write_all(&vec![b'x'; 1024 * 1024 + 1]);
            let _ = oversized.write_all(b"\n");
        });
        assert!(receive_authenticated(&mut accepted, token, &mut seen).is_none());
        // receive() stops at the frame limit without draining the peer. Close
        // the accepted endpoint before joining so a slow writer cannot remain
        // blocked on a full socket buffer.
        drop(accepted);
        writer.join().unwrap();

        let mut request = Request {
            action: Action::Ping,
            nonce: Uuid::new_v4(),
            proof: Sha256Digest::of(b""),
        };
        request.proof = proof(token, &request, b"request");
        let mut valid = UnixStream::connect(&path).unwrap();
        process::send(&mut valid, &request).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        assert_eq!(
            receive_authenticated(&mut accepted, token, &mut seen)
                .unwrap()
                .nonce,
            request.nonce
        );
    }
}
