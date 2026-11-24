mod process;

use std::{
    ffi::OsStr,
    fs::{self, DirBuilder, File, OpenOptions, Permissions, TryLockError},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use rustix::fs::{Mode, OFlags, open};
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;

use super::{
    ACTOR, BackendDiagnostic, BackendFault, BackendStatus, EvidenceError, InvestigationIdentity,
    MAX_ARTIFACT_BYTES, Result, field, matches_field,
};
use crate::{canonical::Sha256Digest, json_input};

const QUALIFICATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/contracts/evidence/investigation-conformance.json"
));
// Requalification includes reviewing the withdrawal semantics of this source.
const SUPPORTED_SOURCE: &str = "6a0c5ed843d0f4870910d3a926298890290c916e";
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_CONTROL_BYTES: usize = 512 * 1024;
const MAX_ATTACH_CONTROL_BYTES: usize = 64 * 1024;
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const STAGING_WAIT: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
struct Qualification {
    investigation: InvestigationIdentity,
}

pub(super) struct Investigation {
    scratch: TempDir,
    executable: File,
    workspace: PathBuf,
    import_root: PathBuf,
    pub identity: InvestigationIdentity,
}

impl Investigation {
    pub fn new(executable: &Path, workspace: &Path, import_root: &Path) -> Result<Self> {
        let qualification: Qualification = serde_json::from_str(QUALIFICATION)
            .map_err(|_| EvidenceError::UnqualifiedInvestigation)?;
        let identity = qualification.investigation;
        let file = File::from(
            open(
                executable,
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        if !file.metadata()?.is_file() || identity.source_commit != SUPPORTED_SOURCE {
            return Err(EvidenceError::UnqualifiedInvestigation);
        }
        let mut bytes = Vec::new();
        file.take(MAX_EXECUTABLE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_EXECUTABLE_BYTES
            || Sha256Digest::of(&bytes) != identity.binary_sha256
        {
            return Err(EvidenceError::UnqualifiedInvestigation);
        }
        // Invoke a private snapshot of the checked bytes, even if the selected
        // executable path is subsequently replaced.
        let scratch = private_scratch()?;
        let executable = write_executable(&scratch, &bytes)?;
        let backend = Self {
            scratch,
            executable,
            workspace: std::path::absolute(workspace)?,
            import_root: std::path::absolute(import_root)?,
            identity,
        };
        let output = process::run(
            backend.executable_command().arg("--version"),
            None,
            Instant::now() + VERSION_TIMEOUT,
            1024,
        )?;
        if !output.status.success()
            || output.stdout != format!("investigation {}\n", backend.identity.version).as_bytes()
        {
            return Err(EvidenceError::UnqualifiedInvestigation);
        }
        Ok(backend)
    }

    pub fn initialize(&self) -> Result<()> {
        if !self.import_root.exists() {
            DirBuilder::new().mode(0o700).create(&self.import_root)?;
        }
        self.check_import_root()?;
        if !self.workspace.join("investigation.toml").exists() {
            let args = [
                OsStr::new("init"),
                self.workspace.as_os_str(),
                OsStr::new("--no-vault"),
                OsStr::new("--import-root"),
                self.import_root.as_os_str(),
            ];
            let reply = self.run(self.command(false).args(args), None, self.deadline())?;
            matches_field(&reply, "result", "initialized")?;
        }
        self.check_config()
    }

    pub fn check_config(&self) -> Result<()> {
        self.check_import_root()?;
        let reply = self.call(&["config", "get", "import_roots"], None)?;
        matches_field(&reply, "result", "config")?;
        let roots: Vec<PathBuf> = field(&reply["setting"], "value")?;
        if roots.as_slice() != [self.import_root.as_path()] {
            return Err(EvidenceError::ImportRoot);
        }
        Ok(())
    }

    fn check_import_root(&self) -> Result<()> {
        let meta = fs::symlink_metadata(&self.import_root)?;
        if !meta.is_dir()
            || meta.permissions().mode() & 0o077 != 0
            || self.import_root.canonicalize()? != self.import_root
        {
            return Err(EvidenceError::ImportRoot);
        }
        Ok(())
    }

    fn executable_command(&self) -> Command {
        // Keep the verified inode open through exec. A later rename of the
        // staging file or the operator's source path cannot change it.
        let mut command = Command::new(format!("/proc/self/fd/{}", self.executable.as_raw_fd()));
        command.env_clear().current_dir(self.scratch.path());
        command
    }

    fn command(&self, use_workspace: bool) -> Command {
        let mut command = self.executable_command();
        command.args(["--format", "json", "--actor", ACTOR]);
        if use_workspace {
            command.arg("--workspace").arg(&self.workspace);
        }
        command
    }

    pub fn call(&self, args: &[&str], payload: Option<&Value>) -> Result<Value> {
        self.call_until(args, payload, self.deadline())
    }

    pub fn deadline(&self) -> Instant {
        Instant::now() + COMMAND_TIMEOUT
    }

    pub fn call_until(
        &self,
        args: &[&str],
        payload: Option<&Value>,
        deadline: Instant,
    ) -> Result<Value> {
        let stdin = payload
            .map(|payload| self.input(&control_bytes(payload, MAX_CONTROL_BYTES)?))
            .transpose()?;
        self.run(self.command(true).args(args), stdin.as_ref(), deadline)
    }

    pub fn ingest(&self, request: &Value, bytes: &[u8]) -> Result<Value> {
        // The manifest and exact source bytes travel separately. The logical
        // input name stays stable, while the manifest path is transport only.
        let control = control_bytes(request, MAX_CONTROL_BYTES)?;
        check_blob_size(bytes)?;
        let mut manifest = tempfile::NamedTempFile::new_in(self.scratch.path())?;
        manifest.write_all(&control)?;
        let mut command = self.command(true);
        command.args(["ingest", "--input"]).arg(manifest.path());
        let stdin = self.input(bytes)?;
        self.run(&mut command, Some(&stdin), self.deadline())
    }

    pub fn attach(&self, path: &str, request: &Value, bytes: &[u8]) -> Result<Value> {
        // Serialize staging and cleanup between bridge processes. Investigation
        // includes the relative path in the capture item request digest.
        let control = control_bytes(request, MAX_ATTACH_CONTROL_BYTES)?;
        check_blob_size(bytes)?;
        self.check_config()?;
        let directory = File::open(&self.import_root)?;
        lock_until(&directory, Instant::now() + STAGING_WAIT)?;
        let stdin = self.input(&control)?;
        let location = self.import_root.join(path);
        let mut file = tempfile::NamedTempFile::new_in(&self.import_root)?;
        file.write_all(bytes)?;
        file.persist(&location).map_err(|error| error.error)?;
        let result = self.run(
            self.command(true)
                .args(["capture", "attach", "--input", "-"]),
            Some(&stdin),
            self.deadline(),
        );
        let cleanup = fs::remove_file(location);
        let reply = result?;
        cleanup?;
        Ok(reply)
    }

    fn run(&self, command: &mut Command, stdin: Option<&File>, deadline: Instant) -> Result<Value> {
        interpret(process::run(command, stdin, deadline, MAX_RESPONSE_BYTES)?)
    }

    fn input(&self, bytes: &[u8]) -> Result<File> {
        let mut file = tempfile::tempfile_in(self.scratch.path())?;
        file.write_all(bytes)?;
        Ok(file)
    }
}

/// Interpret one bounded child result.
///
/// A child that exited unsuccessfully without a complete protocol error reply
/// is a backend failure, not a protocol mistake: the typed failure carries its
/// native status and a bounded, redacted view of its captured stderr, so a
/// crash, a stderr-only diagnostic, or a truncated `ok: false` reply is never
/// reported as `Protocol`. A malformed reply from a child that exited
/// successfully is still `Protocol`, because that is exactly what it is.
fn interpret(output: process::Output) -> Result<Value> {
    let Ok(reply) = json_input::parse(&output.stdout, None) else {
        return Err(failed(&output));
    };
    match (output.status.success(), reply.get("ok")) {
        // Successful capture commands use bare typed receipts.
        (true, None) if reply.is_object() => Ok(reply),
        (true, Some(Value::Bool(true))) => {
            matches_field(&reply, "schema_version", "inv.response.v1")?;
            Ok(reply)
        }
        // A nonzero `ok: false` reply is only mapped through a complete error
        // envelope; anything less keeps the observed status and diagnostics.
        (false, Some(Value::Bool(false))) => {
            Err(refused(&reply).unwrap_or_else(|| failed(&output)))
        }
        // Neither a receipt nor an error envelope: only a child that exited
        // successfully can be blamed for that alone.
        _ => Err(failed(&output)),
    }
}

/// Map a complete Investigation error envelope to its typed failure.
///
/// Returns `None` unless the reply really is an `inv.response.v1` envelope
/// with a string `error.code`, so a malformed nonzero reply can be reported as
/// a backend failure with its status rather than as a protocol mistake.
fn refused(reply: &Value) -> Option<EvidenceError> {
    if reply.get("schema_version")?.as_str()? != "inv.response.v1" {
        return None;
    }
    let code = reply["error"]["code"].as_str()?;
    Some(match code {
        "UNKNOWN_REFERENCE" | "UNKNOWN_CASE" => EvidenceError::Missing,
        "IDEMPOTENCY_KEY_REUSED" | "REVISION_CONFLICT" => EvidenceError::Conflict,
        "INVALID_INPUT"
            if reply["error"]["path"]
                .as_str()
                .is_some_and(|path| path.starts_with("/validate_as")) =>
        {
            EvidenceError::InvalidJson
        }
        "INVALID_INPUT" => EvidenceError::InvalidInput,
        "INTEGRITY_FAILURE" | "HASH_MISMATCH" => EvidenceError::Integrity,
        "GATE_FAILED" => EvidenceError::Refused,
        _ => EvidenceError::Backend,
    })
}

/// The failure for a reply this bridge cannot accept.
fn failed(output: &process::Output) -> EvidenceError {
    if output.status.success() {
        // The backend claims success, so the fault is in the reply itself.
        return EvidenceError::Protocol;
    }
    EvidenceError::BackendFailed {
        diagnostic: BackendDiagnostic::new(
            BackendStatus::of(&output.status),
            BackendFault::Terminated,
            &output.stderr,
        ),
    }
}

fn private_scratch() -> Result<TempDir> {
    // Ignore an ambient TMPDIR: the verified executable and every control blob
    // is staged here, so the parent must be one this principal controls.
    private_scratch_in(Path::new("/tmp"))
}

fn private_scratch_in(parent: &Path) -> Result<TempDir> {
    let metadata = fs::symlink_metadata(parent)?;
    let mode = metadata.mode();
    let shared = mode & 0o022 != 0;
    // A parent writable by others must be sticky, and owned by this principal
    // or by the system root, so no other principal can replace our entry.
    if !metadata.is_dir()
        || (shared
            && (mode & 0o1000 == 0
                || (metadata.uid() != fs::metadata("/")?.uid()
                    && metadata.uid() != rustix::process::getuid().as_raw())))
    {
        return Err(EvidenceError::ScratchUnsafe);
    }
    let scratch = tempfile::Builder::new()
        .prefix("scourge-investigation-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(parent)?;
    // The mode is requested at creation, before the entry is exposed, and is
    // set again so a restrictive umask cannot remove owner access later.
    fs::set_permissions(scratch.path(), Permissions::from_mode(0o700))?;
    Ok(scratch)
}

fn write_executable(scratch: &TempDir, bytes: &[u8]) -> Result<File> {
    let path = scratch.path().join("investigation");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(bytes)?;
    file.set_permissions(Permissions::from_mode(0o500))?;
    file.sync_all()?;
    let checked = file.metadata()?;
    drop(file);
    // Reopen without following links and confirm the admitted inode is the one
    // whose bytes were written and restricted.
    let executable = File::from(
        open(
            &path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let admitted = executable.metadata()?;
    if checked.dev() != admitted.dev() || checked.ino() != admitted.ino() {
        return Err(EvidenceError::UnqualifiedInvestigation);
    }
    Ok(executable)
}

fn lock_until(directory: &File, deadline: Instant) -> Result<()> {
    loop {
        match directory.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::Error(error)) => return Err(error.into()),
            Err(TryLockError::WouldBlock) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(EvidenceError::StagingBusy);
        }
        thread::sleep(Duration::from_millis(10).min(remaining));
    }
}

fn check_blob_size(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        Err(EvidenceError::TooLarge)
    } else {
        Ok(())
    }
}

fn control_bytes(value: &Value, limit: usize) -> Result<Vec<u8>> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
        exceeded: bool,
    }

    impl Write for Bounded {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            if input.len() > self.limit - self.bytes.len() {
                self.exceeded = true;
                return Err(io::Error::other("control limit exceeded"));
            }
            let required = self.bytes.len() + input.len();
            if self.bytes.capacity() < required {
                let target = (self.bytes.capacity() * 2).clamp(required, self.limit);
                self.bytes.reserve_exact(target - self.bytes.len());
            }
            self.bytes.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut output = Bounded {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    serde_json::to_writer(&mut output, value).map_err(|_| {
        if output.exceeded {
            EvidenceError::RequestTooLarge
        } else {
            EvidenceError::Protocol
        }
    })?;
    Ok(output.bytes)
}

#[cfg(test)]
mod tests {
    use std::{os::unix::process::ExitStatusExt as _, process::ExitStatus};

    use serde_json::json;

    use super::*;

    /// Run one throwaway child through the bounded runner and interpret it the
    /// way every Investigation call is interpreted.
    fn run_script(script: &str) -> Result<Value> {
        interpret(process::run(
            Command::new("/usr/bin/python3").args(["-c", script]),
            None,
            Instant::now() + Duration::from_secs(10),
            MAX_RESPONSE_BYTES,
        )?)
    }

    #[test]
    fn a_stderr_only_failure_is_a_typed_backend_failure() {
        const STDERR: &[u8] = b"error: cannot open workspace\n";
        match run_script(
            "import sys; sys.stderr.write('error: cannot open workspace\\n'); sys.exit(3)",
        ) {
            Err(EvidenceError::BackendFailed { diagnostic }) => {
                assert_eq!(diagnostic.status, Some(BackendStatus::Exited(3)));
                assert_eq!(diagnostic.fault, BackendFault::Terminated);
                assert_eq!(diagnostic.stderr_bytes, STDERR.len());
                assert_eq!(diagnostic.stderr_digest, Sha256Digest::of(STDERR));
                assert_eq!(diagnostic.stderr_excerpt, "error: cannot open workspace");
            }
            other => panic!("a stderr-only crash must not become Protocol: {other:?}"),
        }
    }

    #[test]
    fn a_signalled_child_without_a_code_keeps_its_signal() {
        match run_script("import os, signal; os.kill(os.getpid(), signal.SIGKILL)") {
            Err(EvidenceError::BackendFailed { diagnostic }) => {
                assert_eq!(diagnostic.status, Some(BackendStatus::Signaled(9)));
                assert_eq!(diagnostic.fault, BackendFault::Terminated);
                assert_eq!(diagnostic.stderr_bytes, 0);
            }
            other => panic!("a signalled child must keep its signal: {other:?}"),
        }
    }

    #[test]
    fn a_malformed_reply_is_only_a_protocol_error_when_the_child_succeeded() {
        match run_script("print('not a receipt')") {
            Err(EvidenceError::Protocol) => {}
            other => panic!("a malformed successful reply stays Protocol: {other:?}"),
        }
        // A nonzero exit is never accepted as a successful receipt.
        match run_script("print('{}'); raise SystemExit(5)") {
            Err(EvidenceError::BackendFailed { diagnostic }) => {
                assert_eq!(diagnostic.status, Some(BackendStatus::Exited(5)));
            }
            other => panic!("a nonzero exit must not be accepted as success: {other:?}"),
        }
    }

    #[test]
    fn a_protocol_error_envelope_keeps_its_typed_mapping() {
        match run_script(
            "import json, sys; print(json.dumps({'schema_version': 'inv.response.v1', 'ok': False, 'error': {'code': 'UNKNOWN_REFERENCE'}})); sys.exit(1)",
        ) {
            Err(EvidenceError::Missing) => {}
            other => panic!("a well-formed error envelope keeps its type: {other:?}"),
        }
    }

    /// One completed child result with an exact status, stdout and stderr.
    fn synthetic(code: i32, stdout: &str, stderr: &str) -> process::Output {
        process::Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    /// Require a typed backend failure that kept the observed exit and stderr.
    fn assert_backend_failed(output: process::Output, code: i32, stderr: &str) {
        match interpret(output) {
            Err(EvidenceError::BackendFailed { diagnostic }) => {
                assert_eq!(diagnostic.status, Some(BackendStatus::Exited(code)));
                assert_eq!(diagnostic.fault, BackendFault::Terminated);
                assert_eq!(diagnostic.stderr_bytes, stderr.len());
                assert_eq!(
                    diagnostic.stderr_digest,
                    Sha256Digest::of(stderr.as_bytes())
                );
            }
            other => panic!("a nonzero reply without a complete envelope: {other:?}"),
        }
    }

    #[test]
    fn an_incomplete_error_envelope_keeps_the_status_and_stderr() {
        const STDERR: &str = "backend failure\n";
        // Missing schema, missing or non-object `error`, missing string code:
        // none of these is a complete envelope, so none is blamed on the
        // protocol when the child itself failed.
        for reply in [
            r#"{"ok": false}"#,
            r#"{"schema_version": "inv.response.v1", "ok": false}"#,
            r#"{"schema_version": "inv.response.v1", "ok": false, "error": {}}"#,
            r#"{"schema_version": "inv.response.v1", "ok": false, "error": "boom"}"#,
            r#"{"schema_version": "inv.response.v1", "ok": false, "error": null}"#,
        ] {
            assert_backend_failed(synthetic(5, reply, STDERR), 5, STDERR);
        }
    }

    #[test]
    fn a_wrong_schema_or_code_type_in_a_nonzero_reply_is_a_backend_failure() {
        const STDERR: &str = "backend failure\n";
        for reply in [
            r#"{"schema_version": "inv.response.v2", "ok": false, "error": {"code": "UNKNOWN_REFERENCE"}}"#,
            r#"{"schema_version": "inv.error.v1", "ok": false, "error": {"code": "INVALID_INPUT"}}"#,
            r#"{"ok": false, "error": {"code": "UNKNOWN_REFERENCE"}}"#,
            r#"{"schema_version": "inv.response.v1", "ok": false, "error": {"code": 42}}"#,
            r#"{"schema_version": "inv.response.v1", "ok": false, "error": {"code": null}}"#,
            r#"{"schema_version": "inv.response.v1", "ok": false, "error": {"code": ["INVALID_INPUT"]}}"#,
        ] {
            assert_backend_failed(synthetic(1, reply, STDERR), 1, STDERR);
        }
    }

    #[test]
    fn a_nonzero_receipt_shaped_reply_is_still_a_failure() {
        const STDERR: &str = "backend failure\n";
        for reply in [
            r#"{"schema_version": "inv.response.v1", "ok": true}"#,
            r#"{"ok": true, "result": {"roots": []}}"#,
            r#"{"result": {"roots": []}}"#,
        ] {
            assert_backend_failed(synthetic(5, reply, STDERR), 5, STDERR);
        }
    }

    #[test]
    fn a_complete_error_envelope_keeps_its_mapping_under_a_nonzero_status() {
        let cases = [
            ("UNKNOWN_REFERENCE", EvidenceError::Missing),
            ("UNKNOWN_CASE", EvidenceError::Missing),
            ("IDEMPOTENCY_KEY_REUSED", EvidenceError::Conflict),
            ("REVISION_CONFLICT", EvidenceError::Conflict),
            ("INVALID_INPUT", EvidenceError::InvalidInput),
            ("INTEGRITY_FAILURE", EvidenceError::Integrity),
            ("HASH_MISMATCH", EvidenceError::Integrity),
            ("GATE_FAILED", EvidenceError::Refused),
            ("SOMETHING_NEW", EvidenceError::Backend),
        ];
        for (code, expected) in cases {
            let reply = format!(
                r#"{{"schema_version": "inv.response.v1", "ok": false, "error": {{"code": "{code}"}}}}"#
            );
            match interpret(synthetic(1, &reply, "boom\n")) {
                Err(error) => assert_eq!(
                    std::mem::discriminant(&error),
                    std::mem::discriminant(&expected),
                    "{code} must keep its typed mapping, got {error:?}"
                ),
                Ok(value) => panic!("{code} must not be accepted: {value}"),
            }
        }
    }

    #[test]
    fn a_malformed_reply_from_a_successful_child_stays_a_protocol_error() {
        // Exit zero means the child claims the call worked, so a reply this
        // bridge cannot read is a protocol mistake, not a backend failure.
        for reply in [
            "not a reply",
            r#"{"ok": false}"#,
            r#"{"ok": false, "error": {"code": 42}}"#,
            r#"{"schema_version": "inv.response.v2", "ok": false, "error": {"code": "UNKNOWN_REFERENCE"}}"#,
            r#"{"schema_version": "inv.response.v2", "ok": true}"#,
        ] {
            assert!(
                matches!(
                    interpret(synthetic(0, reply, "noise\n")),
                    Err(EvidenceError::Protocol)
                ),
                "{reply} from a successful child must stay Protocol"
            );
        }
    }

    #[test]
    fn a_nonzero_child_with_an_incomplete_envelope_keeps_its_status_live() {
        match run_script(
            "import sys\nsys.stdout.write('{\"ok\": false}\\n')\nsys.stderr.write('backend failure\\n')\nsys.exit(5)",
        ) {
            Err(EvidenceError::BackendFailed { diagnostic }) => {
                assert_eq!(diagnostic.status, Some(BackendStatus::Exited(5)));
                assert_eq!(diagnostic.fault, BackendFault::Terminated);
                assert_eq!(diagnostic.stderr_bytes, b"backend failure\n".len());
                assert_eq!(diagnostic.stderr_excerpt, "backend failure");
            }
            other => panic!("an incomplete nonzero envelope must keep its status: {other:?}"),
        }
    }

    #[test]
    fn diagnostics_are_bounded_and_redacted() {
        assert_eq!(
            super::super::redact(b"error: bad\r\n\tinput\n"),
            "error: bad input"
        );
        let long = super::super::redact(&[b'a'; 4096]);
        assert_eq!(long.len(), super::super::MAX_DIAGNOSTIC_CHARS);
        assert!(long.bytes().all(|byte| byte == b'a'));

        // Every byte value, including escapes and controls, reaches the
        // diagnostic only as a length, a digest and a printable excerpt.
        let stderr: Vec<u8> = (0..=255u8)
            .chain(vec![b'x'; 4096])
            .chain(b"\x1b[2J\x07\n".to_vec())
            .collect();
        let output = process::Output {
            status: ExitStatus::from_raw(9),
            stdout: Vec::new(),
            stderr: stderr.clone(),
        };
        let Err(EvidenceError::BackendFailed { diagnostic }) = interpret(output) else {
            panic!("a signalled child must fail as a backend failure");
        };
        assert_eq!(diagnostic.status, Some(BackendStatus::Signaled(9)));
        assert_eq!(diagnostic.stderr_bytes, stderr.len());
        assert_eq!(diagnostic.stderr_digest, Sha256Digest::of(&stderr));
        assert!(diagnostic.stderr_excerpt.len() <= super::super::MAX_DIAGNOSTIC_CHARS);
        assert!(
            diagnostic
                .stderr_excerpt
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' '),
            "the excerpt kept a non-printable byte: {:?}",
            diagnostic.stderr_excerpt
        );
        let summary = diagnostic.to_string();
        assert!(summary.contains("terminated by signal 9"));
        assert!(summary.contains(&format!("stderr {} bytes", stderr.len())));
        assert!(!summary.contains('\x1b') && !summary.contains('\u{7}'));
    }

    #[test]
    fn control_size_counts_serialized_bytes_and_refuses_overflow() {
        assert_eq!(control_bytes(&json!("text"), 6).unwrap(), b"\"text\"");
        assert!(matches!(
            control_bytes(&json!("x".repeat(MAX_CONTROL_BYTES)), MAX_CONTROL_BYTES),
            Err(EvidenceError::RequestTooLarge)
        ));
        assert!(matches!(
            control_bytes(
                &json!("\x00".repeat(MAX_ATTACH_CONTROL_BYTES / 2)),
                MAX_ATTACH_CONTROL_BYTES
            ),
            Err(EvidenceError::RequestTooLarge)
        ));
    }

    #[test]
    fn contended_staging_lock_times_out_and_can_be_retried() {
        let scratch = private_scratch().unwrap();
        let held = File::open(scratch.path()).unwrap();
        held.try_lock().unwrap();
        let contender = File::open(scratch.path()).unwrap();
        let timeout = Duration::from_millis(75);
        assert!(matches!(
            lock_until(&contender, Instant::now() + timeout),
            Err(EvidenceError::StagingBusy)
        ));
        drop(held);
        lock_until(&contender, Instant::now() + timeout).unwrap();
    }

    #[test]
    fn only_a_private_or_sticky_owned_scratch_parent_is_used() {
        let parent = tempfile::tempdir().unwrap();
        for shared in [0o777, 0o770] {
            fs::set_permissions(parent.path(), Permissions::from_mode(shared)).unwrap();
            assert!(matches!(
                private_scratch_in(parent.path()),
                Err(EvidenceError::ScratchUnsafe)
            ));
        }
        // Sticky protection is enough when this principal owns the parent.
        fs::set_permissions(parent.path(), Permissions::from_mode(0o1777)).unwrap();
        let scratch = private_scratch_in(parent.path()).unwrap();
        assert_eq!(fs::metadata(scratch.path()).unwrap().mode() & 0o777, 0o700);
        fs::set_permissions(parent.path(), Permissions::from_mode(0o700)).unwrap();
        let scratch = private_scratch_in(parent.path()).unwrap();
        assert_eq!(fs::metadata(scratch.path()).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn snapshot_permissions_and_invocation_survive_entry_replacement() {
        const CHILD: &str = "SCOURGE_TEST_PRIVATE_SNAPSHOT";
        if std::env::var_os(CHILD).is_none() {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "umask 000; exec \"$@\"", "scourge-test"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "evidence::transport::tests::snapshot_permissions_and_invocation_survive_entry_replacement",
                ])
                .env(CHILD, "1");
            let output = process::run(
                &mut command,
                None,
                Instant::now() + Duration::from_secs(5),
                16 * 1024,
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

        let scratch = private_scratch().unwrap();
        assert_eq!(fs::metadata(scratch.path()).unwrap().mode() & 0o777, 0o700);
        let original_bytes = fs::read("/usr/bin/printf").unwrap();
        let executable = write_executable(&scratch, &original_bytes).unwrap();
        assert_eq!(executable.metadata().unwrap().mode() & 0o777, 0o500);
        let private_entry = scratch.path().join("investigation");
        let replacement = scratch.path().join("replacement");
        fs::write(&replacement, "different executable bytes").unwrap();
        fs::rename(replacement, &private_entry).unwrap();
        assert_eq!(
            fs::read(&private_entry).unwrap(),
            b"different executable bytes"
        );
        let backend = Investigation {
            scratch,
            executable,
            workspace: PathBuf::new(),
            import_root: PathBuf::new(),
            identity: InvestigationIdentity {
                version: "fixture".into(),
                source_commit: "fixture".into(),
                binary_sha256: Sha256Digest::of(&original_bytes),
            },
        };
        let output = process::run(
            backend.executable_command().arg("verified bytes"),
            None,
            Instant::now() + Duration::from_secs(2),
            1024,
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"verified bytes");
    }
}
