use std::{
    io,
    process::{Command, Output},
    time::Duration,
};

#[cfg(target_os = "linux")]
use super::{OutputStream, TransportFailure};
#[cfg(target_os = "linux")]
use std::process::ExitStatus;

pub(super) const LIMITS: Limits = Limits {
    stdout: super::MAX_SUBPROCESS_STREAM_BYTES,
    stderr: super::MAX_SUBPROCESS_STREAM_BYTES,
    deadline: super::SUBPROCESS_DEADLINE,
};

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) stdout: usize,
    pub(super) stderr: usize,
    pub(super) deadline: Duration,
}

#[derive(Debug)]
pub(super) enum RunError {
    Spawn(io::ErrorKind),
    #[cfg(target_os = "linux")]
    Capture {
        kind: TransportFailure,
        status: Option<ExitStatus>,
    },
}

#[cfg(not(target_os = "linux"))]
pub(super) fn run(_: &mut Command, limits: Limits) -> Result<Output, RunError> {
    let _ = (limits.stdout, limits.stderr, limits.deadline);
    Err(RunError::Spawn(io::ErrorKind::Unsupported))
}

#[cfg(target_os = "linux")]
pub(super) use linux::run;

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io::{ErrorKind, Read},
        os::{fd::AsFd, unix::process::CommandExt},
        process::{Child, Stdio},
        time::Instant,
    };

    use rustix::{
        event::{PollFd, PollFlags, Timespec, poll},
        fs::{OFlags, fcntl_getfl, fcntl_setfl},
        io::{Errno, retry_on_intr},
        process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid},
    };

    use super::*;

    pub(in super::super) fn run(command: &mut Command, limits: Limits) -> Result<Output, RunError> {
        let deadline = Instant::now() + limits.deadline;
        let child = command
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| RunError::Spawn(error.kind()))?;
        let mut process = Process::new(child);
        let pipes = collect(&mut process, deadline, limits);
        let (status, clean) = process.kill_and_reap();
        match (pipes, status, clean) {
            (Ok((stdout, stderr)), Some(status), true) => Ok(Output {
                status,
                stdout,
                stderr,
            }),
            (Err(kind), status, _) => Err(RunError::Capture { kind, status }),
            (Ok(_), status, _) => Err(RunError::Capture {
                kind: TransportFailure::Io,
                status,
            }),
        }
    }

    struct Process {
        child: Child,
        group: Pid,
        reaped: bool,
    }

    impl Process {
        fn new(child: Child) -> Self {
            Self {
                group: Pid::from_child(&child),
                child,
                reaped: false,
            }
        }

        fn exited(&mut self) -> Result<bool, TransportFailure> {
            // Keep the leader waitable until group cleanup. Reaping here could
            // allow the numeric group ID to be reused before we signal it.
            let flags = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
            match retry_on_intr(|| waitid(WaitId::Pid(self.group), flags)) {
                Ok(status) => Ok(status.is_some()),
                Err(Errno::CHILD) => {
                    self.reaped = true;
                    Err(TransportFailure::Io)
                }
                Err(_) => Err(TransportFailure::Io),
            }
        }

        fn kill_and_reap(&mut self) -> (Option<ExitStatus>, bool) {
            // Avoid signalling a numeric group ID after an external reaper
            // or a SIGCHLD disposition has already consumed the leader.
            let leader_exited = self.exited().unwrap_or(false);
            if self.reaped {
                return (None, false);
            }
            // Also terminate helpers that inherited the pipes or outlived
            // their wrapper. A trusted wrapper must keep helpers in this group.
            let signalled = matches!(
                kill_process_group(self.group, Signal::KILL),
                Ok(()) | Err(Errno::SRCH)
            );
            let direct = leader_exited || self.child.kill().is_ok();
            let status = self.child.wait().ok();
            self.reaped = true;
            (status, signalled && direct)
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            if !self.reaped {
                self.kill_and_reap();
            }
        }
    }

    fn collect(
        process: &mut Process,
        deadline: Instant,
        limits: Limits,
    ) -> Result<(Vec<u8>, Vec<u8>), TransportFailure> {
        let mut stdout = Pipe::new(
            process.child.stdout.take(),
            limits.stdout,
            OutputStream::Stdout,
        )?;
        let mut stderr = Pipe::new(
            process.child.stderr.take(),
            limits.stderr,
            OutputStream::Stderr,
        )?;
        let mut chunk = [0; 16 * 1024];

        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(TransportFailure::Timeout);
            }

            if stdout.source.is_none() && stderr.source.is_none() {
                if process.exited()? {
                    return Ok((stdout.bytes, stderr.bytes));
                }
                // Pipes may close while the child continues running.
                std::thread::sleep(left.min(Duration::from_millis(10)));
                continue;
            }

            let (read_stdout, read_stderr) =
                ready(stdout.source.as_ref(), stderr.source.as_ref(), left)?;

            // One chunk per ready pipe keeps both streams moving and checks
            // the deadline even while a child writes continuously.
            if read_stdout {
                stdout.read_chunk(&mut chunk)?;
            }
            if read_stderr {
                stderr.read_chunk(&mut chunk)?;
            }
        }
    }

    fn ready(
        stdout: Option<&impl AsFd>,
        stderr: Option<&impl AsFd>,
        left: Duration,
    ) -> Result<(bool, bool), TransportFailure> {
        let timeout = Timespec::try_from(left).map_err(|_| TransportFailure::Io)?;
        let active = PollFlags::IN;
        let poll_one = |fd: PollFd<'_>| {
            let mut fds = [fd];
            poll_ready(&mut fds, &timeout)?;
            Ok::<bool, TransportFailure>(!fds[0].revents().is_empty())
        };
        match (stdout, stderr) {
            (Some(out), Some(err)) => {
                let mut fds = [PollFd::new(out, active), PollFd::new(err, active)];
                poll_ready(&mut fds, &timeout)?;
                Ok((!fds[0].revents().is_empty(), !fds[1].revents().is_empty()))
            }
            (Some(out), None) => Ok((poll_one(PollFd::new(out, active))?, false)),
            (None, Some(err)) => Ok((false, poll_one(PollFd::new(err, active))?)),
            (None, None) => unreachable!("one pipe is still open"),
        }
    }

    fn poll_ready(fds: &mut [PollFd<'_>], timeout: &Timespec) -> Result<(), TransportFailure> {
        match poll(fds, Some(timeout)) {
            Ok(_) | Err(Errno::INTR) => Ok(()),
            Err(_) => Err(TransportFailure::Io),
        }
    }

    struct Pipe<R> {
        source: Option<R>,
        bytes: Vec<u8>,
        limit: usize,
        stream: OutputStream,
    }

    impl<R: AsFd + Read> Pipe<R> {
        fn new(
            source: Option<R>,
            limit: usize,
            stream: OutputStream,
        ) -> Result<Self, TransportFailure> {
            let source = source.ok_or(TransportFailure::Io)?;
            let flags = fcntl_getfl(&source).map_err(|_| TransportFailure::Io)?;
            fcntl_setfl(&source, flags | OFlags::NONBLOCK).map_err(|_| TransportFailure::Io)?;
            Ok(Self {
                source: Some(source),
                bytes: Vec::new(),
                limit,
                stream,
            })
        }

        fn read_chunk(&mut self, chunk: &mut [u8]) -> Result<(), TransportFailure> {
            let room = self.limit - self.bytes.len();
            let size = chunk.len().min(room.saturating_add(1));
            let source = self.source.as_mut().ok_or(TransportFailure::Io)?;
            match source.read(&mut chunk[..size]) {
                Ok(0) => self.source = None,
                Ok(n) if n > room => return Err(TransportFailure::OutputLimit(self.stream)),
                Ok(n) => {
                    let needed = self.bytes.len() + n;
                    if needed > self.bytes.capacity() {
                        let capacity = self
                            .bytes
                            .capacity()
                            .saturating_mul(2)
                            .max(needed)
                            .min(self.limit);
                        self.bytes
                            .try_reserve_exact(capacity - self.bytes.len())
                            .map_err(|_| TransportFailure::Io)?;
                    }
                    self.bytes.extend_from_slice(&chunk[..n]);
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) => {}
                Err(_) => return Err(TransportFailure::Io),
            }
            Ok(())
        }
    }
}
