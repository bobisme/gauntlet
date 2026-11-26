use std::{
    io::{self, Read, Write},
    os::{fd::AsFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{self, OFlags},
    process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid},
};
use serde::{Serialize, de::DeserializeOwned};

const LIMIT: usize = 1024 * 1024;
const WAIT: Duration = Duration::from_secs(10);

pub(super) struct OwnedChild(Option<Child>);

impl OwnedChild {
    pub(super) fn spawn(command: &mut Command) -> io::Result<Self> {
        let mut retries = 0;
        loop {
            match command.process_group(0).spawn() {
                Ok(child) => return Ok(Self(Some(child))),
                Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy && retries < 10 => {
                    retries += 1;
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(super) fn child(&mut self) -> &mut Child {
        self.0.as_mut().expect("owned child")
    }

    fn status(&self) -> io::Result<Option<rustix::process::WaitIdStatus>> {
        let pid = Pid::from_child(self.0.as_ref().expect("owned child"));
        let flags = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
        Ok(rustix::io::retry_on_intr(|| {
            waitid(WaitId::Pid(pid), flags)
        })?)
    }

    pub(super) fn running(&self) -> io::Result<bool> {
        Ok(self.status()?.is_none())
    }

    pub(super) fn detach(mut self) {
        self.0.take();
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.is_some() && self.status().is_ok() {
            let child = self.child();
            let _ = kill_process_group(Pid::from_child(child), Signal::KILL);
            let _ = child.wait();
        }
    }
}

pub(super) fn native(command: &mut Command, input: Option<&str>) -> io::Result<serde_json::Value> {
    let mut child = OwnedChild::spawn(
        command
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null()),
    )?;
    if let Some(input) = input {
        let mut stdin = child.child().stdin.take().ok_or_else(invalid)?;
        stdin.write_all(input.as_bytes())?;
    }
    let mut stdout = child.child().stdout.take().ok_or_else(invalid)?;
    let deadline = Instant::now() + WAIT;
    let bytes = read_bounded(&mut stdout, deadline, false)?;
    let status = loop {
        if let Some(status) = child.status()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        thread::sleep(Duration::from_millis(10));
    };
    if status.exit_status() != Some(0) {
        return Err(invalid());
    }
    let value: serde_json::Value =
        scourge_core::wire::from_slice(&bytes).map_err(io::Error::other)?;
    if value
        .as_object()
        .is_none_or(|envelope| envelope.contains_key("error"))
    {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn send(pipe: &mut impl Write, item: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *pipe, item)?;
    pipe.write_all(b"\n")?;
    pipe.flush()
}

pub(super) fn receive<T: DeserializeOwned>(
    pipe: &mut (impl Read + AsFd),
    wait: Duration,
) -> io::Result<T> {
    let line = read_bounded(pipe, Instant::now() + wait, true)?;
    scourge_core::wire::from_slice(&line).map_err(io::Error::other)
}

fn read_bounded(
    pipe: &mut (impl Read + AsFd),
    deadline: Instant,
    line: bool,
) -> io::Result<Vec<u8>> {
    let flags = fs::fcntl_getfl(&*pipe)?;
    fs::fcntl_setfl(&*pipe, flags | OFlags::NONBLOCK)?;
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timeout());
        }
        match pipe.read(&mut chunk) {
            Ok(0) if !line => return Ok(bytes),
            Ok(0) => return Err(invalid()),
            Ok(size) => {
                bytes.extend_from_slice(&chunk[..size]);
                if bytes.len() > LIMIT {
                    return Err(invalid());
                }
                if line && bytes.ends_with(b"\n") {
                    return Ok(bytes);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let mut fds = [PollFd::new(&*pipe, PollFlags::IN)];
                poll(
                    &mut fds,
                    Some(&Timespec {
                        tv_sec: remaining.as_secs().try_into().unwrap_or(i64::MAX),
                        tv_nsec: remaining.subsec_nanos().into(),
                    }),
                )?;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn invalid() -> io::Error {
    io::Error::other("invalid local demo process response")
}

fn timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "local demo process timed out")
}
