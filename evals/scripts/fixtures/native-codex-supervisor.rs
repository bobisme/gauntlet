//! Fixed worker supervisor for the credential-free native Codex boundary.
//!
//! This is intentionally a standalone std-only program.  The qualification
//! compiles it for `x86_64-unknown-linux-musl`, so the resulting static binary
//! can be mounted read-only into the pinned Debian worker image.  It owns only
//! the two admitted loopback-to-Unix routes, feeds one bounded stdin prompt to
//! the exact mounted Codex binary, and tears the whole Codex process group down
//! before exiting.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const CODEX: &str = "/opt/scourge-bin/codex";
const MODEL_SOCKET: &str = "/gateway/model.sock";
const PROXY_SOCKET: &str = "/gateway/proxy.sock";
const MODEL_PORT: u16 = 18080;
const MAX_PROMPT_BYTES: usize = 256 * 1024;
const MAX_BRIDGES: usize = 32;
const RUN_TIMEOUT: Duration = Duration::from_secs(900);
const TERM_GRACE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(20);
const IO_POLL: Duration = Duration::from_millis(250);

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;
const SIGKILL: i32 = 9;
const WNOHANG: i32 = 1;

static STOP: AtomicBool = AtomicBool::new(false);
static CHILD_GROUP: AtomicI32 = AtomicI32::new(0);
static EXTERNAL_SIGNAL: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" {
    fn signal(signal: i32, handler: usize) -> usize;
    fn kill(pid: i32, signal: i32) -> i32;
    fn geteuid() -> u32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

extern "C" fn relay_signal(number: i32) {
    EXTERNAL_SIGNAL.compare_exchange(0, number, Ordering::SeqCst, Ordering::SeqCst).ok();
    STOP.store(true, Ordering::SeqCst);
    let group = CHILD_GROUP.load(Ordering::SeqCst);
    if group > 0 {
        // SAFETY: kill is async-signal-safe and the stored process group is a
        // positive child PID created by this process.
        unsafe { kill(-group, number) };
    }
}

#[derive(Clone)]
struct Route {
    port: u16,
    socket: &'static str,
}

struct RouteCounters {
    active: AtomicUsize,
    accepted: AtomicU64,
    refused: AtomicU64,
    client_to_unix_bytes: AtomicU64,
    unix_to_client_bytes: AtomicU64,
}

struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            block: [0; 64],
            block_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total_len = self.total_len.checked_add(input.len() as u64).expect("sha length");
        if self.block_len != 0 {
            let count = (64 - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + count].copy_from_slice(&input[..count]);
            self.block_len += count;
            input = &input[count..];
            if self.block_len == 64 {
                let block = self.block;
                self.compress(&block);
                self.block_len = 0;
            }
        }
        while input.len() >= 64 {
            let mut block = [0_u8; 64];
            block.copy_from_slice(&input[..64]);
            self.compress(&block);
            input = &input[64..];
        }
        self.block[..input.len()].copy_from_slice(input);
        self.block_len = input.len();
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_len = self.total_len.checked_mul(8).expect("sha bit length");
        self.block[self.block_len] = 0x80;
        self.block_len += 1;
        if self.block_len > 56 {
            self.block[self.block_len..].fill(0);
            let block = self.block;
            self.compress(&block);
            self.block = [0; 64];
        } else {
            self.block[self.block_len..56].fill(0);
        }
        self.block[56..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.block;
        self.compress(&block);
        let mut output = [0_u8; 32];
        for (chunk, word) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
        ];
        let mut words = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().expect("word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut h] = self.state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(sum1).wrapping_add(choose)
                .wrapping_add(K[index]).wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h=g; g=f; f=e; e=d.wrapping_add(temp1); d=c; c=b; b=a; a=temp1.wrapping_add(temp2);
        }
        for (slot, value) in self.state.iter_mut().zip([a,b,c,d,e,f,g,h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex(&digest.finish())
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut reader = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 { break; }
        digest.update(&buffer[..count]);
    }
    Ok(hex(&digest.finish()))
}

fn valid_digest(value: &OsStr) -> Option<String> {
    let text = value.to_str()?;
    (text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        .then(|| text.to_owned())
}

fn parse_arguments() -> Result<(String, String, Vec<OsString>), String> {
    let mut input = env::args_os().skip(1);
    if input.next().as_deref() != Some(OsStr::new("--self-sha256")) {
        return Err("missing self pin".into());
    }
    let self_pin = valid_digest(&input.next().ok_or("missing self digest")?)
        .ok_or("invalid self digest")?;
    if input.next().as_deref() != Some(OsStr::new("--codex-sha256")) {
        return Err("missing Codex pin".into());
    }
    let codex_pin = valid_digest(&input.next().ok_or("missing Codex digest")?)
        .ok_or("invalid Codex digest")?;
    if input.next().as_deref() != Some(OsStr::new("--")) {
        return Err("missing command delimiter".into());
    }
    if input.next().as_deref() != Some(OsStr::new(CODEX)) {
        return Err("unexpected Codex path".into());
    }
    let command: Vec<OsString> = input.collect();
    if command.is_empty() || command.last().map(OsString::as_os_str) != Some(OsStr::new("-")) {
        return Err("Codex command must end in stdin prompt".into());
    }
    Ok((self_pin, codex_pin, command))
}

fn exact_environment() -> Result<(BTreeMap<String, String>, Option<u16>), String> {
    let expected: BTreeMap<String, String> = [
        ("CODEX_HOME", "/runtime/codex-home"),
        ("HOME", "/runtime/home"),
        ("HOSTNAME", "scourge-worker"),
        ("LANG", "C.UTF-8"),
        ("NO_COLOR", "1"),
        ("PATH", "/opt/scourge-bin:/usr/bin:/bin"),
        ("TERM", "dumb"),
        ("TMPDIR", "/runtime/tmp"),
        ("XDG_CACHE_HOME", "/runtime/cache"),
        ("XDG_CONFIG_HOME", "/runtime/config"),
        ("XDG_DATA_HOME", "/runtime/data"),
        ("XDG_RUNTIME_DIR", "/runtime/run"),
        ("XDG_STATE_HOME", "/runtime/state"),
    ].into_iter().map(|(key, value)| (key.into(), value.into())).collect();
    let mut observed = BTreeMap::new();
    for (key, value) in env::vars_os() {
        let key = key.into_string().map_err(|_| "non-UTF-8 environment name")?;
        let value = value.into_string().map_err(|_| "non-UTF-8 environment value")?;
        if observed.insert(key, value).is_some() {
            return Err("duplicate environment name".into());
        }
    }
    let proxy = match observed.remove("M0_PROXY_PORT") {
        None => None,
        Some(text) => {
            if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid proxy port".into());
            }
            let port: u16 = text.parse().map_err(|_| "invalid proxy port")?;
            if port == MODEL_PORT { return Err("proxy port collides with model port".into()); }
            Some(port)
        }
    };
    if observed != expected { return Err("effective environment mismatch".into()); }
    let mut complete = expected;
    if let Some(port) = proxy { complete.insert("M0_PROXY_PORT".into(), port.to_string()); }
    Ok((complete, proxy))
}

fn validate_socket(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "missing gateway socket")?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { geteuid() };
    if !metadata.file_type().is_socket() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o600 {
        return Err("unsafe gateway socket".into());
    }
    Ok(())
}

fn copy_tcp_to_unix(
    mut source: TcpStream,
    mut destination: UnixStream,
    stop: Arc<AtomicBool>,
    bytes: Arc<RouteCounters>,
) -> io::Result<()> {
    let mut buffer = [0_u8; 65_536];
    while !stop.load(Ordering::SeqCst) {
        match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                destination.write_all(&buffer[..count])?;
                bytes.client_to_unix_bytes.fetch_add(count as u64, Ordering::SeqCst);
            }
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => continue,
            Err(error) => return Err(error),
        }
    }
    let _ = destination.shutdown(Shutdown::Write);
    Ok(())
}

fn copy_unix_to_tcp(
    mut source: UnixStream,
    mut destination: TcpStream,
    stop: Arc<AtomicBool>,
    bytes: Arc<RouteCounters>,
) -> io::Result<()> {
    let mut buffer = [0_u8; 65_536];
    while !stop.load(Ordering::SeqCst) {
        match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                destination.write_all(&buffer[..count])?;
                bytes.unix_to_client_bytes.fetch_add(count as u64, Ordering::SeqCst);
            }
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => continue,
            Err(error) => return Err(error),
        }
    }
    let _ = destination.shutdown(Shutdown::Write);
    Ok(())
}

fn fail_route(stop: &Arc<AtomicBool>, fatal: &Arc<AtomicBool>, counters: &RouteCounters) {
    counters.refused.fetch_add(1, Ordering::SeqCst);
    fatal.store(true, Ordering::SeqCst);
    stop.store(true, Ordering::SeqCst);
    STOP.store(true, Ordering::SeqCst);
}

fn bridge(
    client: TcpStream,
    route: Route,
    stop: Arc<AtomicBool>,
    fatal: Arc<AtomicBool>,
    counters: Arc<RouteCounters>,
) {
    let upstream = match UnixStream::connect(route.socket) {
        Ok(stream) => stream,
        Err(_) => {
            fail_route(&stop, &fatal, &counters);
            counters.active.fetch_sub(1, Ordering::SeqCst);
            return;
        }
    };
    let _ = client.set_read_timeout(Some(IO_POLL));
    let _ = client.set_write_timeout(Some(IO_POLL));
    let _ = upstream.set_read_timeout(Some(IO_POLL));
    let _ = upstream.set_write_timeout(Some(IO_POLL));
    let left_client = match client.try_clone() { Ok(stream) => stream, Err(_) => { fail_route(&stop, &fatal, &counters); counters.active.fetch_sub(1, Ordering::SeqCst); return; } };
    let left_upstream = match upstream.try_clone() { Ok(stream) => stream, Err(_) => { fail_route(&stop, &fatal, &counters); counters.active.fetch_sub(1, Ordering::SeqCst); return; } };
    let left_stop = Arc::clone(&stop);
    let left_counters = Arc::clone(&counters);
    let left = thread::spawn(move || copy_tcp_to_unix(left_client, left_upstream, left_stop, left_counters));
    let right_result = copy_unix_to_tcp(upstream, client, Arc::clone(&stop), Arc::clone(&counters));
    let left_result = left.join();
    if right_result.is_err() || !matches!(left_result, Ok(Ok(()))) {
        fail_route(&stop, &fatal, &counters);
    }
    counters.active.fetch_sub(1, Ordering::SeqCst);
}

fn listener_thread(
    listener: TcpListener,
    route: Route,
    stop: Arc<AtomicBool>,
    fatal: Arc<AtomicBool>,
    counters: Arc<RouteCounters>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client, address)) => {
                if !address.ip().is_loopback() || counters.active.fetch_add(1, Ordering::SeqCst) >= MAX_BRIDGES {
                    counters.active.fetch_sub(1, Ordering::SeqCst);
                    fail_route(&stop, &fatal, &counters);
                    let _ = client.shutdown(Shutdown::Both);
                    break;
                }
                counters.accepted.fetch_add(1, Ordering::SeqCst);
                let child_stop = Arc::clone(&stop);
                let child_counters = Arc::clone(&counters);
                let child_fatal = Arc::clone(&fatal);
                let child_route = route.clone();
                thread::spawn(move || bridge(client, child_route, child_stop, child_fatal, child_counters));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(_) => { fail_route(&stop, &fatal, &counters); break; }
        }
    }
}

fn bind_route(route: &Route) -> Result<TcpListener, String> {
    validate_socket(Path::new(route.socket))?;
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, route.port))
        .map_err(|_| "loopback bind failed")?;
    listener.set_nonblocking(true).map_err(|_| "nonblocking listener failed")?;
    Ok(listener)
}

fn terminate_group(group: i32, signal_number: i32) {
    if group > 0 {
        // SAFETY: the group was created from the direct child PID.
        unsafe { kill(-group, signal_number) };
    }
}

fn reap_group(group: i32) {
    loop {
        let mut status = 0_i32;
        // SAFETY: status points to writable storage and the negative PID is
        // the exact child process group created by this supervisor.
        let result = unsafe { waitpid(-group, &mut status, WNOHANG) };
        if result <= 0 { break; }
    }
}

fn group_exists(group: i32) -> bool {
    reap_group(group);
    if group <= 0 { return false; }
    // SAFETY: signal zero performs an existence/permission probe only.
    unsafe { kill(-group, 0) == 0 }
}

fn wait_group_gone(group: i32, duration: Duration) -> bool {
    let deadline = Instant::now() + duration;
    while group_exists(group) {
        if Instant::now() >= deadline { return false; }
        thread::sleep(POLL);
    }
    true
}

fn quiesce_group(group: i32) -> (bool, bool) {
    if !group_exists(group) { return (true, false); }
    terminate_group(group, SIGTERM);
    if wait_group_gone(group, TERM_GRACE) { return (true, false); }
    terminate_group(group, SIGKILL);
    (wait_group_gone(group, TERM_GRACE), true)
}

struct WaitOutcome {
    status: ExitStatus,
    timed_out: bool,
    sigkill_escalated: bool,
}

fn wait_child_with_limits(
    child: &mut Child,
    run_timeout: Duration,
    term_grace: Duration,
) -> io::Result<WaitOutcome> {
    let started = Instant::now();
    let mut timed_out = false;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(WaitOutcome { status, timed_out, sigkill_escalated: false });
        }
        if STOP.load(Ordering::SeqCst) || started.elapsed() >= run_timeout {
            timed_out = started.elapsed() >= run_timeout;
            terminate_group(child.id() as i32, SIGTERM);
            let deadline = Instant::now() + term_grace;
            loop {
                if let Some(status) = child.try_wait()? {
                    return Ok(WaitOutcome {
                        status,
                        timed_out,
                        sigkill_escalated: false,
                    });
                }
                if Instant::now() >= deadline { break; }
                thread::sleep(POLL);
            }
            terminate_group(child.id() as i32, SIGKILL);
            return child.wait().map(|status| WaitOutcome {
                status,
                timed_out,
                sigkill_escalated: true,
            });
        }
        thread::sleep(POLL);
    }
}

fn wait_child(child: &mut Child) -> io::Result<WaitOutcome> {
    wait_child_with_limits(child, RUN_TIMEOUT, TERM_GRACE)
}

fn write_environment(environment: &BTreeMap<String, String>) -> Result<(), String> {
    let mut bytes = Vec::new();
    for (key, value) in environment {
        bytes.extend_from_slice(key.as_bytes());
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    fs::create_dir_all("/runtime/artifacts").map_err(|_| "artifact directory unavailable")?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut output = options.open("/runtime/artifacts/worker-environ.bin")
        .map_err(|_| "environment artifact exists")?;
    output.write_all(&bytes).map_err(|_| "environment artifact write failed")?;
    output.sync_all().map_err(|_| "environment artifact sync failed".to_owned())
}

struct Receipt<'a> {
    self_pin: &'a str,
    codex_pin: &'a str,
    prompt_bytes: usize,
    prompt_sha256: &'a str,
    prompt_write_complete: bool,
    prompt_write_timed_out: bool,
    proxy: Option<u16>,
    status: ExitStatus,
    timed_out: bool,
    interrupted: i32,
    fatal: bool,
    model: &'a RouteCounters,
    proxy_counters: Option<&'a RouteCounters>,
    routes_inactive: bool,
    process_group_quiescent: bool,
    sigkill_escalated: bool,
}

fn route_receipt(port: Option<u16>, socket: Option<&str>, counters: Option<&RouteCounters>) -> String {
    match (port, socket, counters) {
        (Some(port), Some(socket), Some(counters)) => format!(
            "{{\"loopback_port\":{port},\"unix_socket\":\"{socket}\",\"sessions\":{},\"refused\":{},\"client_to_unix_bytes\":{},\"unix_to_client_bytes\":{},\"active\":{}}}",
            counters.accepted.load(Ordering::SeqCst),
            counters.refused.load(Ordering::SeqCst),
            counters.client_to_unix_bytes.load(Ordering::SeqCst),
            counters.unix_to_client_bytes.load(Ordering::SeqCst),
            counters.active.load(Ordering::SeqCst),
        ),
        _ => "{\"loopback_port\":null,\"unix_socket\":null,\"sessions\":0,\"refused\":0,\"client_to_unix_bytes\":0,\"unix_to_client_bytes\":0,\"active\":0}".into(),
    }
}

fn write_receipt(value: Receipt<'_>) -> Result<(), String> {
    let exit_code = value.status.code().map(|code| code.to_string()).unwrap_or_else(|| "null".into());
    let signal = value.status.signal().map(|number| number.to_string()).unwrap_or_else(|| "null".into());
    let interrupted = if value.interrupted == 0 { "null".into() } else { value.interrupted.to_string() };
    let model = route_receipt(Some(MODEL_PORT), Some(MODEL_SOCKET), Some(value.model));
    let proxy = route_receipt(value.proxy, value.proxy.map(|_| PROXY_SOCKET), value.proxy_counters);
    let body = format!(
        "{{\"schema\":\"scourge.native-codex-supervisor\",\"schema_version\":1,\"self_sha256\":\"{}\",\"codex_sha256\":\"{}\",\"prompt\":{{\"bytes\":{},\"sha256\":\"{}\",\"write_complete\":{},\"write_timed_out\":{}}},\"routes\":{{\"model\":{},\"proxy\":{}}},\"codex\":{{\"exit_code\":{},\"signal\":{},\"timed_out\":{},\"interrupted_by_signal\":{}}},\"fatal_route_failure\":{},\"teardown\":{{\"routes_inactive\":{},\"process_group_quiescent\":{},\"sigkill_escalated\":{},\"complete\":{}}}}}\n",
        value.self_pin, value.codex_pin, value.prompt_bytes, value.prompt_sha256,
        value.prompt_write_complete, value.prompt_write_timed_out, model, proxy,
        exit_code, signal, value.timed_out, interrupted, value.fatal,
        value.routes_inactive, value.process_group_quiescent, value.sigkill_escalated,
        value.routes_inactive && value.process_group_quiescent,
    );
    let temporary = PathBuf::from("/runtime/artifacts/.native-codex-supervisor.json.tmp");
    let destination = Path::new("/runtime/artifacts/native-codex-supervisor.json");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut output = options.open(&temporary).map_err(|_| "receipt temporary exists")?;
    output.write_all(body.as_bytes()).map_err(|_| "receipt write failed")?;
    output.sync_all().map_err(|_| "receipt sync failed")?;
    fs::rename(&temporary, destination).map_err(|_| "receipt publish failed".to_owned())?;
    File::open("/runtime/artifacts")
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "receipt directory sync failed".to_owned())
}

fn run() -> Result<i32, String> {
    let (self_pin, codex_pin, codex_args) = parse_arguments()?;
    let actual_self = sha256_file(Path::new("/proc/self/exe")).map_err(|_| "self pin read failed")?;
    let actual_codex = sha256_file(Path::new(CODEX)).map_err(|_| "Codex pin read failed")?;
    if actual_self != self_pin { return Err("supervisor digest mismatch".into()); }
    if actual_codex != codex_pin { return Err("Codex digest mismatch".into()); }
    let (environment, proxy) = exact_environment()?;
    write_environment(&environment)?;

    let mut prompt = Vec::new();
    io::stdin().take((MAX_PROMPT_BYTES + 1) as u64).read_to_end(&mut prompt)
        .map_err(|_| "prompt read failed")?;
    if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES || std::str::from_utf8(&prompt).is_err() || prompt.contains(&0) {
        return Err("invalid bounded prompt".into());
    }
    let prompt_bytes = prompt.len();
    let prompt_sha256 = sha256_bytes(&prompt);

    let model_route = Route { port: MODEL_PORT, socket: MODEL_SOCKET };
    let proxy_route = proxy.map(|port| Route { port, socket: PROXY_SOCKET });
    let model_counters = Arc::new(RouteCounters {
        active: AtomicUsize::new(0), accepted: AtomicU64::new(0), refused: AtomicU64::new(0),
        client_to_unix_bytes: AtomicU64::new(0), unix_to_client_bytes: AtomicU64::new(0),
    });
    let proxy_counters = proxy_route.as_ref().map(|_| Arc::new(RouteCounters {
        active: AtomicUsize::new(0), accepted: AtomicU64::new(0), refused: AtomicU64::new(0),
        client_to_unix_bytes: AtomicU64::new(0), unix_to_client_bytes: AtomicU64::new(0),
    }));
    let mut listeners = vec![(
        bind_route(&model_route)?, model_route, Arc::clone(&model_counters)
    )];
    if let (Some(route), Some(counters)) = (proxy_route, proxy_counters.as_ref()) {
        listeners.push((bind_route(&route)?, route, Arc::clone(counters)));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let fatal = Arc::new(AtomicBool::new(false));
    let mut listener_threads = Vec::new();
    for (listener, route, counters) in listeners {
        let thread_stop = Arc::clone(&stop);
        let thread_fatal = Arc::clone(&fatal);
        listener_threads.push(thread::spawn(move || listener_thread(
            listener, route, thread_stop, thread_fatal, counters
        )));
    }

    let mut command = Command::new(CODEX);
    command.args(&codex_args).stdin(Stdio::piped()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    command.process_group(0);
    let mut child = command.spawn().map_err(|_| "Codex spawn failed")?;
    let group = child.id() as i32;
    CHILD_GROUP.store(group, Ordering::SeqCst);
    let mut input = child.stdin.take().ok_or("Codex stdin unavailable")?;
    let (writer_sender, writer_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = input.write_all(&prompt).and_then(|()| input.flush());
        let _ = writer_sender.send(result);
    });
    let wait = wait_child(&mut child).map_err(|_| "Codex wait failed")?;
    let (process_group_quiescent, quiesce_sigkill_escalated) = quiesce_group(group);
    let sigkill_escalated = wait.sigkill_escalated || quiesce_sigkill_escalated;
    let (prompt_write_complete, prompt_write_timed_out) = match writer_receiver.recv_timeout(TERM_GRACE) {
        Ok(Ok(())) => (true, false),
        Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => (false, false),
        Err(mpsc::RecvTimeoutError::Timeout) => (false, true),
    };
    if !prompt_write_complete {
        fatal.store(true, Ordering::SeqCst);
    }
    CHILD_GROUP.store(0, Ordering::SeqCst);
    stop.store(true, Ordering::SeqCst);
    for handle in listener_threads {
        if handle.join().is_err() { fatal.store(true, Ordering::SeqCst); }
    }
    let deadline = Instant::now() + TERM_GRACE;
    while (
        model_counters.active.load(Ordering::SeqCst)
        + proxy_counters.as_ref().map_or(0, |row| row.active.load(Ordering::SeqCst))
    ) != 0 && Instant::now() < deadline { thread::sleep(POLL); }
    let routes_inactive = model_counters.active.load(Ordering::SeqCst) == 0
        && proxy_counters.as_ref().map_or(true, |row| row.active.load(Ordering::SeqCst) == 0);
    let interrupted = EXTERNAL_SIGNAL.load(Ordering::SeqCst);
    let fatal_failure = fatal.load(Ordering::SeqCst);
    write_receipt(Receipt {
        self_pin: &self_pin, codex_pin: &codex_pin, prompt_bytes,
        prompt_sha256: &prompt_sha256, prompt_write_complete, prompt_write_timed_out,
        proxy, status: wait.status,
        timed_out: wait.timed_out, interrupted, fatal: fatal_failure, model: &model_counters,
        proxy_counters: proxy_counters.as_deref(), routes_inactive,
        process_group_quiescent, sigkill_escalated,
    })?;
    if !routes_inactive { return Err("bridge teardown incomplete".into()); }
    if !process_group_quiescent { return Err("Codex process group survived teardown".into()); }
    if !prompt_write_complete || fatal_failure || wait.timed_out
        || interrupted != 0 || !wait.status.success()
    {
        return Err("supervised Codex run did not settle".into());
    }
    Ok(0)
}

fn main() {
    // SAFETY: these handlers only set atomics and call async-signal-safe kill.
    unsafe {
        signal(SIGINT, relay_signal as *const () as usize);
        signal(SIGTERM, relay_signal as *const () as usize);
    }
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("native Codex supervisor refused: {error}");
            std::process::exit(70);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    #[test]
    fn timeout_tracks_direct_child_sigkill_and_group_quiescence() {
        STOP.store(false, Ordering::SeqCst);
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("trap '' TERM; printf 'ready\\n'; while :; do sleep 60; done")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        command.process_group(0);
        let mut child = command.spawn().expect("spawn TERM-ignoring direct child");
        let group = child.id() as i32;
        let mut ready = String::new();
        BufReader::new(child.stdout.take().expect("child stdout"))
            .read_line(&mut ready)
            .expect("read child readiness");
        assert_eq!(ready, "ready\n");

        let outcome = wait_child_with_limits(
            &mut child,
            Duration::from_millis(40),
            Duration::from_millis(40),
        ).expect("wait for bounded timeout");
        assert!(outcome.timed_out);
        assert!(outcome.sigkill_escalated);
        assert_eq!(outcome.status.signal(), Some(SIGKILL));
        let (quiescent, later_escalation) = quiesce_group(group);
        assert!(quiescent);
        assert!(!later_escalation);
        STOP.store(false, Ordering::SeqCst);
    }
}
