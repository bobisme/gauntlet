use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::{fd::AsFd, unix::process::CommandExt},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::{
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    io::Errno,
    process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid},
};

use super::super::{BackendDiagnostic, BackendFault, BackendStatus, EvidenceError, Result};

// Deliberately a sibling of, not a reuse of, `teapot::process`: this runner
// needs replayable stdin for control requests and blob ingestion, returns the
// evidence lane's typed failures, and retries `ETXTBSY` for its staged
// executable. It enforces the same contract as the Teapot runner: a private
// process group, a deadline, a per-stream byte cap, and kill-before-reap so a
// numeric group ID is never signalled after it can be recycled.
const STDERR_LIMIT: usize = 64 * 1024;
const IDLE_POLL: Duration = Duration::from_millis(2);

#[derive(Debug)]
pub(super) struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    /// Captured stderr, within [`STDERR_LIMIT`]. It is evidence about a failed
    /// child only; callers reduce it to a redacted diagnostic rather than
    /// exposing it.
    pub stderr: Vec<u8>,
}

pub(super) fn run(
    command: &mut Command,
    stdin: Option<&File>,
    deadline: Instant,
    stdout_limit: usize,
) -> Result<Output> {
    if Instant::now() >= deadline {
        return Err(EvidenceError::timeout());
    }
    let mut child = spawn(command, stdin, deadline)?;
    let group = Pid::from_child(&child);
    let capture = collect(&mut child, group, deadline, stdout_limit);
    // The leader has not been reaped yet, so its process group cannot be
    // recycled. Decide whether it had already finished before signalling the
    // group: that status is the backend's own result, while a status produced
    // by this runner's kill is not evidence about the backend.
    let finished = leader_finished(group);
    // Stop any remaining group members before reaping the leader.
    let killed = match kill_process_group(group, Signal::KILL) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(error) => {
            let _ = child.kill();
            Err(io::Error::from(error))
        }
    };
    let status = child.wait();
    killed?;
    let status = status?;
    match capture.fault {
        // A leader that had already finished keeps the status it exited with,
        // even when a descendant holding an inherited pipe ended the capture.
        Some(fault) => Err(fault.failure(finished.then_some(&status), &capture.stderr)),
        None => Ok(Output {
            status,
            stdout: capture.stdout,
            stderr: capture.stderr,
        }),
    }
}

/// Report whether the leader has exited, without reaping it.
///
/// `WNOWAIT` keeps the leader waitable, so its process group ID cannot be
/// recycled before this runner signals the group, and the status read after
/// that signal is the backend's own.
fn leader_finished(pid: Pid) -> bool {
    match waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Ok(status) => status.is_some(),
        // No status is observable, so none is claimed.
        Err(_) => false,
    }
}

/// Which bounded condition ended capture of one child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// The deadline expired while the leader or a descendant held a pipe.
    Timeout,
    /// A captured stream exceeded its byte cap.
    OutputTooLarge,
    /// The child handle did not carry a pipe this runner owns.
    MissingPipe,
    /// Configuring or reading a captured stream failed.
    Io(io::ErrorKind),
}

impl Fault {
    /// The typed failure for this fault, carrying the native status when the
    /// leader had already been observed to finish.
    fn failure(self, status: Option<&ExitStatus>, stderr: &[u8]) -> EvidenceError {
        let fault = match self {
            Self::Timeout => BackendFault::Timeout,
            Self::OutputTooLarge => BackendFault::OutputTooLarge,
            Self::MissingPipe | Self::Io(_) => BackendFault::Terminated,
        };
        let diagnostic = BackendDiagnostic::new(status.and_then(BackendStatus::of), fault, stderr);
        match self {
            Self::Timeout => EvidenceError::BackendTimeout { diagnostic },
            Self::OutputTooLarge => EvidenceError::BackendOutputTooLarge { diagnostic },
            // A capture failure that happens after the leader finished is still
            // the backend's failure and keeps that status; without a status the
            // pre-existing mapping stands.
            Self::MissingPipe if status.is_none() => EvidenceError::Backend,
            Self::Io(kind) if status.is_none() => EvidenceError::Io(kind),
            Self::MissingPipe | Self::Io(_) => EvidenceError::BackendFailed { diagnostic },
        }
    }
}

/// Spawn with re-readable stdin. `ETXTBSY` is retried: this process writes and
/// closes the verified executable, but a concurrently forked sibling can
/// briefly inherit the write descriptor, and Linux refuses to exec an inode
/// with an outstanding writer. The staging directory is private to this
/// principal, so no other principal can hold that writer open. Retrying is
/// bounded by the caller's deadline and never substitutes other bytes.
fn spawn(command: &mut Command, stdin: Option<&File>, deadline: Instant) -> Result<Child> {
    loop {
        let stdio = match stdin {
            None => Stdio::null(),
            Some(file) => {
                let mut file = file;
                file.seek(SeekFrom::Start(0))?;
                Stdio::from(file.try_clone()?)
            }
        };
        let attempt = command
            .stdin(stdio)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn();
        match attempt {
            Ok(child) => return Ok(child),
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(EvidenceError::timeout());
                }
                thread::sleep(IDLE_POLL.min(remaining));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn collect(child: &mut Child, pid: Pid, deadline: Instant, stdout_limit: usize) -> Capture {
    let mut capture = Capture {
        stdout: Vec::new(),
        stderr: Vec::new(),
        fault: None,
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        capture.fault = Some(Fault::MissingPipe);
        return capture;
    };
    let mut stdout = match Pipe::new(stdout, stdout_limit) {
        Ok(pipe) => pipe,
        Err(error) => {
            capture.fault = Some(Fault::Io(error.kind()));
            return capture;
        }
    };
    let mut stderr = match Pipe::new(stderr, STDERR_LIMIT) {
        Ok(pipe) => pipe,
        Err(error) => {
            capture.fault = Some(Fault::Io(error.kind()));
            return capture;
        }
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            capture.fault = Some(Fault::Timeout);
            return capture;
        }
        let stdout_progress = match stdout.drain(Some(&mut capture.stdout)) {
            Ok(progress) => progress,
            Err(fault) => {
                capture.fault = Some(fault);
                return capture;
            }
        };
        let stderr_progress = match stderr.drain(Some(&mut capture.stderr)) {
            Ok(progress) => progress,
            Err(fault) => {
                capture.fault = Some(fault);
                return capture;
            }
        };
        if stdout.closed && stderr.closed {
            match waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            ) {
                Ok(Some(_)) => return capture,
                Ok(None) | Err(Errno::INTR) => {}
                Err(error) => {
                    capture.fault = Some(Fault::Io(io::Error::from(error).kind()));
                    return capture;
                }
            }
        }
        if !stdout_progress && !stderr_progress {
            thread::sleep(IDLE_POLL.min(remaining));
        }
    }
}

/// What one bounded capture produced before the leader was reaped.
struct Capture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    fault: Option<Fault>,
}

struct Pipe<R> {
    reader: R,
    limit: usize,
    read: usize,
    closed: bool,
}

impl<R: Read + AsFd> Pipe<R> {
    fn new(reader: R, limit: usize) -> io::Result<Self> {
        let flags = fcntl_getfl(&reader).map_err(io::Error::from)?;
        fcntl_setfl(&reader, flags | OFlags::NONBLOCK).map_err(io::Error::from)?;
        Ok(Self {
            reader,
            limit,
            read: 0,
            closed: false,
        })
    }

    /// Drain what is available, keeping at most `limit` bytes. `output` receives
    /// the retained bytes of a stream whose contents this runner needs.
    fn drain(&mut self, output: Option<&mut Vec<u8>>) -> std::result::Result<bool, Fault> {
        if self.closed {
            return Ok(false);
        }
        let mut buffer = [0; 8192];
        let available = (self.limit - self.read + 1).min(buffer.len());
        match self.reader.read(&mut buffer[..available]) {
            Ok(0) => {
                self.closed = true;
                Ok(true)
            }
            Ok(count) if count > self.limit - self.read => Err(Fault::OutputTooLarge),
            Ok(count) => {
                self.read += count;
                if let Some(output) = output {
                    if output.capacity() < self.read {
                        let target = (output.capacity() * 2).clamp(self.read, self.limit);
                        output.reserve_exact(target - output.len());
                    }
                    output.extend_from_slice(&buffer[..count]);
                }
                Ok(true)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(Fault::Io(error.kind())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write as _, os::unix::fs::PermissionsExt as _};

    use super::*;

    /// The leader exits 7 at once and a descendant keeps the inherited pipes
    /// open, trying to leave a marker after a second.
    const LEADER_EXITS_FIRST: &str = "import os, sys, time\n\
        pid = os.fork()\n\
        if pid == 0:\n\
        \x20   time.sleep(1)\n\
        \x20   open(sys.argv[1], 'w').close()\n\
        \x20   os._exit(0)\n\
        os._exit(7)\n";

    /// The leader exits 0 at once. A descendant lets the runner observe that
    /// exit and then overruns the cap of the stream named by `sys.argv[1]`,
    /// which is 4096 bytes for stdout and the fixed stderr cap otherwise.
    const DESCENDANT_OVERFLOWS: &str = "import os, sys, time\n\
        fd = int(sys.argv[1])\n\
        size = 5000 if fd == 1 else 70000\n\
        pid = os.fork()\n\
        if pid == 0:\n\
        \x20   time.sleep(0.15)\n\
        \x20   os.write(fd, b'x' * size)\n\
        \x20   os._exit(0)\n\
        os._exit(0)\n";

    fn python(script: &str, timeout: Duration, limit: usize) -> Result<Output> {
        run(
            Command::new("/usr/bin/python3").args(["-c", script]),
            None,
            Instant::now() + timeout,
            limit,
        )
    }

    #[test]
    fn unfinished_child_times_out_with_or_without_a_valid_reply() {
        for script in [
            "import time; time.sleep(30)",
            "import time; print('{}', flush=True); time.sleep(30)",
        ] {
            let start = Instant::now();
            match python(script, Duration::from_millis(100), 4096) {
                Err(EvidenceError::BackendTimeout { diagnostic }) => {
                    assert_eq!(diagnostic.fault, BackendFault::Timeout);
                    // The only status available is this runner's own kill.
                    assert_eq!(diagnostic.status, None);
                }
                other => panic!("an unfinished child must time out, got {other:?}"),
            }
            assert!(start.elapsed() < Duration::from_secs(3));
        }
    }

    #[test]
    fn both_streams_are_bounded_and_drained() {
        let timeout = Duration::from_secs(3);
        for fd in [1, 2] {
            // The child cannot finish writing, so no status may be reported.
            let script = format!("import os, time; os.write({fd}, b'x' * 200000); time.sleep(30)");
            match python(&script, timeout, 4096) {
                Err(EvidenceError::BackendOutputTooLarge { diagnostic }) => {
                    assert_eq!(diagnostic.fault, BackendFault::OutputTooLarge);
                    assert_eq!(diagnostic.status, None, "fd {fd}");
                }
                other => panic!("expected an output limit on fd {fd}, got {other:?}"),
            }
        }
        let reply = python(
            "import os; os.write(2, b'x' * 60000); os.write(1, b'y' * 90000)",
            timeout,
            90000,
        )
        .unwrap();
        assert!(reply.status.success());
        assert_eq!(reply.stdout, vec![b'y'; 90000]);
        assert_eq!(reply.stderr, vec![b'x'; 60000]);
    }

    #[test]
    fn leader_status_survives_a_descendant_holding_an_inherited_pipe() {
        let scratch = tempfile::tempdir().unwrap();
        let marker = scratch.path().join("descendant");
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", LEADER_EXITS_FIRST]).arg(&marker);
        let started = Instant::now();
        match run(
            &mut command,
            None,
            Instant::now() + Duration::from_millis(300),
            4096,
        ) {
            Err(EvidenceError::BackendTimeout { diagnostic }) => {
                assert_eq!(diagnostic.fault, BackendFault::Timeout);
                // The leader exited before the deadline, so its own status is
                // preserved instead of being replaced by this runner's kill.
                assert_eq!(diagnostic.status, Some(BackendStatus::Exited(7)));
                assert_eq!(diagnostic.stderr_bytes, 0);
                assert_eq!(diagnostic.stderr_excerpt, "");
            }
            other => panic!("expected a backend timeout, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "a descendant holding the pipes delayed the timeout"
        );
        thread::sleep(Duration::from_secs(1));
        assert!(!marker.exists(), "the descendant outlived the group kill");
    }

    #[test]
    fn capture_overflow_keeps_a_status_observed_first() {
        for fd in [1, 2] {
            let mut command = Command::new("/usr/bin/python3");
            command
                .args(["-c", DESCENDANT_OVERFLOWS])
                .arg(fd.to_string());
            match run(
                &mut command,
                None,
                Instant::now() + Duration::from_secs(5),
                4096,
            ) {
                Err(EvidenceError::BackendOutputTooLarge { diagnostic }) => {
                    assert_eq!(diagnostic.fault, BackendFault::OutputTooLarge);
                    assert_eq!(diagnostic.status, Some(BackendStatus::Exited(0)), "fd {fd}");
                }
                other => panic!("expected an output limit on fd {fd}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_completed_child_keeps_its_streams_for_the_caller() {
        let reply = python(
            "import sys; sys.stderr.write('backend diagnostic\\n'); sys.exit(4)",
            Duration::from_secs(5),
            1024,
        )
        .unwrap();
        assert_eq!(reply.status.code(), Some(4));
        assert_eq!(reply.stdout, b"");
        assert_eq!(
            reply.stderr, b"backend diagnostic\n",
            "stderr must reach the caller instead of being discarded"
        );
    }

    #[test]
    fn re_readable_stdin_is_replayed_to_a_child() {
        let mut stdin = tempfile::tempfile().unwrap();
        stdin.write_all(b"scourge input").unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", "import sys; sys.stdout.write(sys.stdin.read())"]);
        let output = run(
            &mut command,
            Some(&stdin),
            Instant::now() + Duration::from_secs(5),
            1024,
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"scourge input");
    }

    #[test]
    fn an_outstanding_writer_is_retried_within_the_deadline() {
        let scratch = tempfile::tempdir().unwrap();
        let executable = scratch.path().join("executable");
        fs::write(&executable, fs::read("/usr/bin/printf").unwrap()).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let ready = scratch.path().join("ready");
        // Hold a writer open exactly as the staging writer does before it
        // closes the descriptor and restricts the mode.
        let mut holder = Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import os, sys, time; os.open(sys.argv[1], os.O_WRONLY); os.chmod(sys.argv[1], 0o500); open(sys.argv[2], 'w').close(); time.sleep(0.5)",
            ])
            .arg(&executable)
            .arg(&ready)
            .spawn()
            .unwrap();
        let opened = Instant::now();
        while !ready.exists() {
            assert!(opened.elapsed() < Duration::from_secs(5));
            thread::sleep(Duration::from_millis(5));
        }
        let started = Instant::now();
        let mut retry = Command::new(&executable);
        retry.arg("retried");
        let output = run(
            &mut retry,
            None,
            Instant::now() + Duration::from_secs(10),
            1024,
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"retried");
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "the first exec did not observe the outstanding writer"
        );
        holder.wait().unwrap();
    }

    #[test]
    fn timeout_stops_group_members_with_inherited_pipes() {
        let scratch = tempfile::tempdir().unwrap();
        let marker = scratch.path().join("orphan");
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", LEADER_EXITS_FIRST]).arg(&marker);
        match run(
            &mut command,
            None,
            Instant::now() + Duration::from_millis(200),
            4096,
        ) {
            Err(EvidenceError::BackendTimeout { diagnostic }) => {
                assert_eq!(diagnostic.status, Some(BackendStatus::Exited(7)));
            }
            other => panic!("expected a backend timeout, got {other:?}"),
        }
        thread::sleep(Duration::from_secs(1));
        assert!(!marker.exists());
    }

    /// Count every descriptor this process holds. Re-executed in a
    /// single-threaded child so concurrently running tests cannot perturb it.
    #[test]
    fn bounded_runs_release_every_captured_stream() {
        const CHILD: &str = "SCOURGE_TEST_TRANSPORT_DESCRIPTORS";
        fn descriptors() -> usize {
            fs::read_dir("/proc/self/fd").unwrap().count()
        }
        if std::env::var_os(CHILD).is_none() {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "evidence::transport::process::tests::bounded_runs_release_every_captured_stream",
                ])
                .env(CHILD, "1");
            let output = run(
                &mut command,
                None,
                Instant::now() + Duration::from_secs(20),
                64 * 1024,
            )
            .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        // Warm up lazily initialised state before the first measurement.
        python(
            "import sys; sys.stderr.write('warm\\n'); sys.exit(4)",
            Duration::from_secs(5),
            1024,
        )
        .unwrap();
        let before = descriptors();
        for _ in 0..4 {
            let refused = python(
                "import sys; sys.stderr.write('boom\\n'); sys.exit(4)",
                Duration::from_secs(5),
                1024,
            )
            .unwrap();
            assert_eq!(refused.status.code(), Some(4));
            assert!(matches!(
                python(
                    "import os; os.write(1, b'x' * 5000)",
                    Duration::from_secs(5),
                    4096
                ),
                Err(EvidenceError::BackendOutputTooLarge { .. })
            ));
            assert!(matches!(
                python(
                    "import time; time.sleep(30)",
                    Duration::from_millis(50),
                    1024
                ),
                Err(EvidenceError::BackendTimeout { .. })
            ));
        }
        assert_eq!(descriptors(), before, "a captured stream descriptor leaked");
    }
}
