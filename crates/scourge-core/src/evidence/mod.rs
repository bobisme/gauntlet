//! Scourge's local evidence interface backed by the qualified Investigation CLI.

mod capture;
mod lineage;
mod transport;

use std::{fmt, ops::Range, path::Path, process::ExitStatus, time::Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub use capture::{
    Attachment, Capture, CaptureHandle, CaptureState, Completion, Finalized, Original,
};
use transport::Investigation;

use crate::workspace::InvestigationAuthority;
use crate::{canonical::Sha256Digest, ids::ArtifactId, wire::Artifact as ArtifactRef};

const ACTOR: &str = "agent:scourge";
const CASE_KEY: &str = "scourge/evidence/case-v1";
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXCERPT_BYTES: usize = 32 * 1024;

type Result<T> = std::result::Result<T, EvidenceError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationIdentity {
    pub version: String,
    pub source_commit: String,
    pub binary_sha256: Sha256Digest,
}

/// Native status of an Investigation child, when this bridge observed it.
///
/// A status produced by the bridge's own kill is never reported: it says
/// nothing about the backend. An unobserved status stays absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendStatus {
    /// The child exited normally with this code.
    Exited(i32),
    /// The child was terminated by this signal and reported no exit code.
    Signaled(i32),
}

impl BackendStatus {
    /// Read the native status of a terminated child, or `None` when it has
    /// no exit code and no terminating signal.
    pub(crate) fn of(status: &ExitStatus) -> Option<Self> {
        use std::os::unix::process::ExitStatusExt as _;

        if let Some(signal) = status.signal() {
            return Some(Self::Signaled(signal));
        }
        status.code().map(Self::Exited)
    }
}

/// Which bounded condition ended an Investigation child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFault {
    /// The child terminated unsuccessfully: a nonzero exit or a fatal signal.
    Terminated,
    /// The call deadline expired while the leader or a descendant held a pipe.
    Timeout,
    /// A captured stream exceeded its byte cap.
    OutputTooLarge,
}

/// Bounded, redacted evidence about one failed Investigation child.
///
/// Raw backend bytes are never exposed. Captured stderr is reduced to its
/// exact length, a digest of those bytes and one redacted single line, so an
/// operator keeps actionable failure evidence without echoing untrusted
/// content, terminal escapes or binary data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendDiagnostic {
    /// The native status, when it was observed before this bridge ended the
    /// child. A status caused by the bridge's own kill is never included.
    pub status: Option<BackendStatus>,
    /// What ended the child or its capture.
    pub fault: BackendFault,
    /// Captured stderr bytes, within the existing stream cap.
    pub stderr_bytes: usize,
    /// Digest of exactly those captured stderr bytes.
    pub stderr_digest: Sha256Digest,
    /// A redacted, single-line, length-capped prefix of the captured stderr.
    pub stderr_excerpt: String,
}

impl BackendDiagnostic {
    pub(super) fn new(status: Option<BackendStatus>, fault: BackendFault, stderr: &[u8]) -> Self {
        Self {
            status,
            fault,
            stderr_bytes: stderr.len(),
            stderr_digest: Sha256Digest::of(stderr),
            stderr_excerpt: redact(stderr),
        }
    }
}

impl fmt::Display for BackendDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.fault {
            BackendFault::Terminated => "the child terminated unsuccessfully",
            BackendFault::Timeout => "the deadline expired",
            BackendFault::OutputTooLarge => "a captured stream exceeded its byte cap",
        })?;
        f.write_str("; ")?;
        match self.status {
            Some(BackendStatus::Exited(code)) => write!(f, "exit code {code}")?,
            Some(BackendStatus::Signaled(signal)) => write!(f, "terminated by signal {signal}")?,
            None => f.write_str("exit status not observed")?,
        }
        write!(
            f,
            "; stderr {} bytes sha256:{}",
            self.stderr_bytes,
            self.stderr_digest.as_str()
        )?;
        if !self.stderr_excerpt.is_empty() {
            write!(f, "; stderr {:?}", self.stderr_excerpt)?;
        }
        Ok(())
    }
}

/// Longest redacted stderr excerpt kept in a [`BackendDiagnostic`].
const MAX_DIAGNOSTIC_CHARS: usize = 200;

/// Reduce captured stderr to one line of printable ASCII.
///
/// Everything that is not an ASCII graphic character or a space becomes a
/// single space, so control bytes, terminal escapes and binary data are never
/// echoed. The result is length-capped.
fn redact(bytes: &[u8]) -> String {
    let mut text = String::new();
    for character in String::from_utf8_lossy(bytes).chars() {
        if character.is_ascii_graphic() {
            text.push(character);
        } else if !text.is_empty() && !text.ends_with(' ') {
            text.push(' ');
        }
        if text.len() >= MAX_DIAGNOSTIC_CHARS {
            break;
        }
    }
    text.truncate(MAX_DIAGNOSTIC_CHARS);
    text.truncate(text.trim_end().len());
    text
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("Investigation executable did not match the qualified build")]
    UnqualifiedInvestigation,
    #[error("the Investigation import root must be the configured private directory")]
    ImportRoot,
    #[error("the Investigation workspace is outside its approved case root or uses an unsafe path")]
    CaseRoot,
    #[error("evidence or capture not found")]
    Missing,
    #[error("evidence request or capture state conflicts")]
    Conflict,
    #[error("invalid evidence request")]
    InvalidInput,
    #[error("invalid evidence byte range")]
    InvalidRange,
    #[error("invalid or over-limit strict JSON evidence")]
    InvalidJson,
    #[error("evidence byte limit exceeded")]
    TooLarge,
    #[error("evidence digest or retained inventory did not match")]
    Integrity,
    #[error("evidence snapshot changed during the read")]
    ChangedSnapshot,
    #[error("the complete current evidence lineage could not be established")]
    LineageUnverified,
    #[error("evidence control request exceeds the transport limit")]
    RequestTooLarge,
    #[error("Investigation exceeded the response size limit ({diagnostic})")]
    BackendOutputTooLarge { diagnostic: BackendDiagnostic },
    #[error("Investigation did not exit before the evidence deadline ({diagnostic})")]
    BackendTimeout { diagnostic: BackendDiagnostic },
    #[error("the evidence staging directory remained locked")]
    StagingBusy,
    #[error("the evidence scratch parent is not private enough to stage the executable")]
    ScratchUnsafe,
    #[error("evidentiary use refused for {artifact:?}: {state}")]
    Withdrawn {
        artifact: ArtifactId,
        state: Withdrawal,
    },
    #[error("Investigation refused the evidence operation")]
    Refused,
    #[error("Investigation could not complete the evidence operation")]
    Backend,
    #[error("Investigation failed ({diagnostic})")]
    BackendFailed { diagnostic: BackendDiagnostic },
    #[error("Investigation returned an unexpected evidence response")]
    Protocol,
    #[error("evidence transport I/O failed ({0})")]
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for EvidenceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl EvidenceError {
    /// Classification for readers and writers of run evidence.
    pub const fn code(&self) -> crate::wire::ErrorCode {
        use crate::wire::ErrorCode;
        match self {
            Self::UnqualifiedInvestigation
            | Self::ImportRoot
            | Self::BackendOutputTooLarge { .. }
            | Self::BackendTimeout { .. }
            | Self::StagingBusy
            | Self::ScratchUnsafe
            | Self::Backend
            | Self::BackendFailed { .. }
            | Self::Io(_) => ErrorCode::DependencyUnavailable,
            Self::InvalidInput
            | Self::InvalidRange
            | Self::InvalidJson
            | Self::TooLarge
            | Self::RequestTooLarge
            | Self::Refused => ErrorCode::EvidenceIncomplete,
            Self::Missing
            | Self::Conflict
            | Self::CaseRoot
            | Self::Integrity
            | Self::ChangedSnapshot
            | Self::LineageUnverified
            | Self::Withdrawn { .. }
            | Self::Protocol => ErrorCode::IntegrityFailure,
        }
    }

    /// A deadline that expired before this bridge observed a child status.
    pub(super) fn timeout() -> Self {
        Self::BackendTimeout {
            diagnostic: BackendDiagnostic::new(None, BackendFault::Timeout, &[]),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdrawal {
    Partial,
    Entire,
}

impl fmt::Display for Withdrawal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Partial => "partially withdrawn",
            Self::Entire => "withdrawn",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub reference: ArtifactRef,
    pub revision: u64,
    pub size_bytes: usize,
    pub source_id: String,
    pub lineage: Vec<Lineage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lineage {
    pub input: ArtifactRef,
    pub revision: u64,
    pub transformation: String,
    pub version: String,
}

/// The excerpt bytes are evidence and deliberately omitted from Debug.
pub struct Read {
    pub artifact: Artifact,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for Read {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Read")
            .field("artifact", &self.artifact)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    EngagementManifest,
    Experiment,
    VerificationRecord,
    Redaction,
}

impl RecordKind {
    fn title(self) -> &'static str {
        match self {
            Self::EngagementManifest => "Scourge engagement manifest",
            Self::Experiment => "Scourge experiment",
            Self::VerificationRecord => "Scourge verification record",
            Self::Redaction => "Scourge redaction",
        }
    }
}

pub struct RecordRequest<'a> {
    /// The durable publication intent ID, or an equivalent stable caller key.
    pub key: &'a str,
    pub kind: RecordKind,
    pub bytes: &'a [u8],
    pub inputs: &'a [ArtifactRef],
    pub transformation: &'a str,
    pub version: &'a str,
}

/// One private Investigation workspace and recording case per Scourge workspace.
pub struct Evidence {
    backend: Investigation,
    case_id: String,
    #[cfg(test)]
    execution_effects: Option<crate::execution_effects::ExecutionEffects>,
    #[cfg(test)]
    probe_artifact: Option<Artifact>,
}

impl Evidence {
    /// Set up the Investigation workspace and its record case. Repeating
    /// initialization with the same paths reuses the original case receipt.
    pub fn initialize(binary: &Path, workspace: &Path, import_root: &Path) -> Result<Self> {
        let backend = Investigation::new(binary, workspace, import_root)?;
        Self::initialize_backend(backend)
    }

    /// Read and authenticate the exact admitted executable without starting it.
    pub fn qualified_executable_bytes(executable: &Path) -> Result<Vec<u8>> {
        Investigation::checked_executable(executable).map(|(_, bytes)| bytes)
    }

    /// Provision an existing operator-owned set of directories for a runtime.
    pub fn initialize_qualified(authority: &InvestigationAuthority) -> Result<Self> {
        Self::initialize_backend(Investigation::qualified(authority)?)
    }

    fn initialize_backend(backend: Investigation) -> Result<Self> {
        backend.initialize()?;
        let reply = backend.call(
            &[
                "case",
                "new",
                "Scourge evidence",
                "--mode",
                "record",
                "--command-id",
                CASE_KEY,
            ],
            None,
        )?;
        Self::from_case_receipt(backend, &reply)
    }

    /// Reopen an initialized workspace using only the stored case receipt.
    pub fn open(binary: &Path, workspace: &Path, import_root: &Path) -> Result<Self> {
        Self::reopen(Investigation::new(binary, workspace, import_root)?)
    }

    pub(crate) fn open_qualified(authority: &InvestigationAuthority) -> Result<Self> {
        Self::reopen(Investigation::qualified(authority)?)
    }

    fn reopen(backend: Investigation) -> Result<Self> {
        backend.check_config()?;
        let reply = backend.call(&["receipt", CASE_KEY], None)?;
        Self::from_case_receipt(backend, &reply)
    }

    fn from_case_receipt(backend: Investigation, reply: &Value) -> Result<Self> {
        matches_field(reply, "command_id", CASE_KEY)?;
        let created: [RecordRef; 1] = field(reply, "created")?;
        let [case] = created;
        if case.revision != 1 || !full_id(&case.id, "case_") {
            return Err(EvidenceError::Protocol);
        }
        Ok(Self {
            backend,
            case_id: case.id,
            #[cfg(test)]
            execution_effects: None,
            #[cfg(test)]
            probe_artifact: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn execution_probe(
        reference: ArtifactRef,
        effects: crate::execution_effects::ExecutionEffects,
    ) -> Self {
        Self {
            backend: Investigation::execution_probe(),
            case_id: "case_execution_probe".to_owned(),
            execution_effects: Some(effects),
            probe_artifact: Some(Artifact {
                reference,
                revision: 1,
                size_bytes: 1,
                source_id: "execution-probe".to_owned(),
                lineage: Vec::new(),
            }),
        }
    }

    pub fn investigation(&self) -> &InvestigationIdentity {
        &self.backend.identity
    }

    /// Compare the exact selection used to open this backend without calling it.
    pub(crate) fn matches_authority(&self, authority: &InvestigationAuthority) -> bool {
        self.backend.authority.as_ref() == Some(authority)
    }

    #[cfg(test)]
    pub(crate) fn inert_fixture(authority: Option<InvestigationAuthority>) -> Self {
        Self {
            backend: Investigation::inert_fixture(authority),
            case_id: "offline fixture".into(),
            execution_effects: None,
            probe_artifact: None,
        }
    }

    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Read the current evidence checkpoint from an existing case artifact.
    pub fn checkpoint_for(&self, id: &ArtifactId) -> Result<serde_json::Value> {
        snapshot(&self.show(id.as_str())?)
    }

    /// Check current evidentiary use and return an immutable reference, size,
    /// source and ordered transform inputs. Unknown states fail closed.
    pub fn describe(&self, id: &ArtifactId) -> Result<Artifact> {
        #[cfg(test)]
        if let Some(effects) = &self.execution_effects {
            effects.evidence_access();
            return self
                .probe_artifact
                .as_ref()
                .filter(|artifact| &artifact.reference.artifact_id == id)
                .cloned()
                .ok_or(EvidenceError::Integrity);
        }
        self.artifact_snapshot(id).map(|(artifact, _)| artifact)
    }

    pub fn read(&self, id: &ArtifactId) -> Result<Read> {
        self.read_checked(id, |_| Ok(()))
    }

    pub fn read_range(&self, id: &ArtifactId, part: Range<usize>) -> Result<Read> {
        let (artifact, head) = self.artifact_snapshot(id)?;
        self.read_bytes(artifact, &head, Some(part), false)
    }

    /// Validate as strict JSON through Investigation and return the exact
    /// original spelling and whitespace instead of a reserialization.
    pub fn read_json(&self, id: &ArtifactId) -> Result<Read> {
        let (artifact, head) = self.artifact_snapshot(id)?;
        self.read_bytes(artifact, &head, None, true)
    }

    /// Check the retained metadata before allocating or requesting bytes.
    pub(crate) fn read_checked(
        &self,
        id: &ArtifactId,
        check: impl FnOnce(&Artifact) -> Result<()>,
    ) -> Result<Read> {
        let (artifact, head) = self.artifact_snapshot(id)?;
        check(&artifact)?;
        self.read_bytes(artifact, &head, None, false)
    }

    fn artifact_snapshot(&self, id: &ArtifactId) -> Result<(Artifact, Value)> {
        self.artifact_snapshot_until(id, self.backend.deadline())
    }

    fn artifact_snapshot_until(
        &self,
        id: &ArtifactId,
        deadline: Instant,
    ) -> Result<(Artifact, Value)> {
        if !full_id(id.as_str(), "art_") {
            return Err(EvidenceError::InvalidInput);
        }
        let response = self.show_until(id.as_str(), deadline)?;
        let head = snapshot(&response)?;
        self.check_lineage(id, &response, &head, deadline)?;
        let header = &response["record"]["header"];
        let record: RecordRef = serde_json::from_value(header.clone()).map_err(bad_reply)?;
        if record.id != id.as_str() || record.revision == 0 {
            return Err(EvidenceError::Protocol);
        }
        let body = &response["record"]["body"];
        matches_field(body, "availability", "retained")?;
        let size_bytes: usize = field(body, "size_bytes")?;
        let reference = ArtifactRef {
            artifact_id: id.clone(),
            digest: digest(body, "digest")?,
        };
        let source_id = field(&body["source"], "id")?;
        let transforms: Vec<Transform> = field(body, "transforms")?;
        let lineage = transforms
            .into_iter()
            .map(Transform::lineage)
            .collect::<Result<_>>()?;
        Ok((
            Artifact {
                reference,
                revision: record.revision,
                size_bytes,
                source_id,
                lineage,
            },
            head,
        ))
    }

    fn read_bytes(
        &self,
        artifact: Artifact,
        head: &Value,
        part: Option<Range<usize>>,
        json: bool,
    ) -> Result<Read> {
        if artifact.size_bytes > MAX_ARTIFACT_BYTES {
            return Err(EvidenceError::TooLarge);
        }
        if json {
            let selector =
                json!({"type": "json_pointer", "pointer": "", "parser": "serde_json-strict-v1"});
            let reply = self
                .select(&artifact, head, selector)
                .map_err(|error| match error {
                    EvidenceError::InvalidInput => EvidenceError::InvalidJson,
                    error => error,
                })?;
            matches_field(&reply, "availability", "json_value")?;
        }
        let whole = part.is_none();
        let part = match part {
            Some(part) if part.start >= part.end || part.end > artifact.size_bytes => {
                return Err(EvidenceError::InvalidRange);
            }
            Some(part) => part,
            None => 0..artifact.size_bytes,
        };
        let mut bytes = Vec::with_capacity(part.len());
        if whole && part.len() <= MAX_EXCERPT_BYTES {
            let reply = self.select(&artifact, head, json!({"type": "whole"}))?;
            extend(&mut bytes, reply, part)?;
        } else {
            for start in (part.start..part.end).step_by(MAX_EXCERPT_BYTES) {
                let end = (start + MAX_EXCERPT_BYTES).min(part.end);
                let selector = json!({"type": "byte_range", "start": start, "end": end});
                extend(
                    &mut bytes,
                    self.select(&artifact, head, selector)?,
                    start..end,
                )?;
            }
        }
        if whole && Sha256Digest::of(&bytes) != artifact.reference.digest {
            return Err(EvidenceError::Integrity);
        }
        Ok(Read { artifact, bytes })
    }

    fn select(&self, artifact: &Artifact, head: &Value, selector: Value) -> Result<Value> {
        let id = &artifact.reference.artifact_id;
        let request = json!({
            "schema_version": "inv.selector.v1",
            "artifact_digest": hash(&artifact.reference.digest),
            "selector": selector,
        });
        let reply = self.backend.call(
            &[
                "--case",
                &self.case_id,
                "evidence",
                "read",
                id.as_str(),
                "--selector-file",
                "-",
            ],
            Some(&request),
        )?;
        matches_field(&reply, "result", "evidence_read")?;
        // `artifact_snapshot` already completed the whole-lineage check. This
        // bounded report can only add a refusal; the snapshot equality below
        // is what prevents a use-only change from slipping in afterwards.
        require_use(id, &reply)?;
        let read: RecordRef = field(&reply, "artifact")?;
        if read.id != id.as_str() || reply["selector"] != request {
            return Err(EvidenceError::Protocol);
        }
        if read.revision != artifact.revision || snapshot(&reply)? != *head {
            return Err(EvidenceError::ChangedSnapshot);
        }
        Ok(reply["excerpt"].clone())
    }

    /// Create a derivative from existing, digest-bound artifacts. Redaction is
    /// a derivative operation and never overwrites or lowers the classification
    /// of any input.
    pub fn record(&self, request: RecordRequest<'_>) -> Result<Artifact> {
        self.record_in("record", request)
    }

    pub(crate) fn record_verification_publication(
        &self,
        request: RecordRequest<'_>,
    ) -> Result<Artifact> {
        self.record_in("verification-publication", request)
    }

    fn record_in(&self, namespace: &str, request: RecordRequest<'_>) -> Result<Artifact> {
        let key = command_key(namespace, request.key)?;
        if request.inputs.is_empty() {
            return Err(EvidenceError::InvalidInput);
        }
        if request.inputs.len() > 256
            || request.transformation.len() > 256
            || request.version.len() > 256
            || request
                .inputs
                .iter()
                .any(|input| input.artifact_id.as_str().len() > 40)
        {
            return Err(EvidenceError::RequestTooLarge);
        }
        if request.bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(EvidenceError::TooLarge);
        }
        let mut inputs = Vec::with_capacity(request.inputs.len());
        let mut lineage = Vec::with_capacity(request.inputs.len());
        let mut input_head = None;
        let deadline = self.backend.deadline();
        for reference in request.inputs {
            let (artifact, head) =
                self.artifact_snapshot_until(&reference.artifact_id, deadline)?;
            if input_head.as_ref().is_some_and(|prior| *prior != head) {
                return Err(EvidenceError::ChangedSnapshot);
            }
            input_head = Some(head);
            if artifact.reference.digest != reference.digest {
                return Err(EvidenceError::Integrity);
            }
            lineage.push(Lineage {
                input: reference.clone(),
                revision: artifact.revision,
                transformation: request.transformation.into(),
                version: request.version.into(),
            });
            inputs.push(json!({
                "artifact_ref": {"id": reference.artifact_id, "revision": artifact.revision},
                "digest": hash(&reference.digest),
            }));
        }
        let expected = Sha256Digest::of(request.bytes);
        let format = if request.kind == RecordKind::Redaction {
            "text/plain"
        } else {
            "application/json"
        };
        let mut wire = json!({
            "schema_version": "inv.ingest.v1",
            "command_id": key,
            "actor": ACTOR,
            "case_id": self.case_id,
            "source": {"title": request.kind.title(), "format": format},
            "content": {"kind": "stdin", "name": "scourge-derived-artifact"},
            "derived_from": {
                "transformation": request.transformation, "version": request.version, "inputs": inputs,
            },
        });
        if request.kind != RecordKind::Redaction {
            wire["validate_as"] = json!("strict_json");
        }
        let receipt = self.backend.ingest(&wire, request.bytes)?;
        matches_field(&receipt, "command_id", &key)?;
        let [item]: [Value; 1] = field(&receipt, "items")?;
        matches_field(&item, "outcome", "derived")?;
        let artifact = self.describe(&field(&item, "artifact_id")?)?;
        if artifact.reference.digest != expected
            || artifact.size_bytes != request.bytes.len()
            || artifact.lineage != lineage
        {
            return Err(EvidenceError::Integrity);
        }
        Ok(artifact)
    }

    /// Recover the durable receipt for a record write without resubmitting its
    /// bytes. The caller supplies the same stable key used by [`Self::record`].
    /// This is a local Investigation receipt/read path; it cannot start target
    /// traffic or turn an arbitrary record-shaped artifact into a receipt.
    pub fn recover_record(&self, key: &str) -> Result<Option<Artifact>> {
        self.recover_record_in("record", key)
    }

    pub(crate) fn recover_verification_publication(&self, key: &str) -> Result<Option<Artifact>> {
        self.recover_record_in("verification-publication", key)
    }

    fn recover_record_in(&self, namespace: &str, key: &str) -> Result<Option<Artifact>> {
        let key = command_key(namespace, key)?;
        let reply = self.backend.call(&["receipt", &key], None)?;
        matches_field(&reply, "command_id", &key)?;
        match reply["result"].as_str() {
            Some("not_found_at_snapshot") => return Ok(None),
            Some("committed" | "already_committed") => {}
            _ => return Err(EvidenceError::Protocol),
        }
        // A generic receipt lists every retained Artifact created by the
        // transaction. Ingest also retains its canonical manifest, so the
        // record is not identified by transaction-artifact cardinality. The
        // durable `artifact:0` client reference is the same identity from
        // which the original ingest response constructed `items[0]`.
        let created: Vec<RecordChange> = field(&reply, "created")?;
        let mut items = created
            .iter()
            .filter(|change| change.client_ref.as_deref() == Some("artifact:0"));
        let item = items.next().ok_or(EvidenceError::Protocol)?;
        if items.next().is_some() || !full_id(&item.id, "art_") || item.revision == 0 {
            return Err(EvidenceError::Protocol);
        }

        let receipts: Vec<ReceiptArtifact> = field(&reply, "artifacts")?;
        let mut selected = None;
        for receipt in receipts {
            if !full_id(&receipt.artifact.id, "art_") || receipt.artifact.revision == 0 {
                return Err(EvidenceError::Protocol);
            }
            let digest = parse_digest(&receipt.digest)?;
            let size_bytes = usize::try_from(receipt.size_bytes).map_err(bad_reply)?;
            if receipt.artifact.id == item.id
                && receipt.artifact.revision == item.revision
                && selected.replace((digest, size_bytes)).is_some()
            {
                return Err(EvidenceError::Protocol);
            }
        }
        let (digest, size_bytes) = selected.ok_or(EvidenceError::Protocol)?;
        let id: ArtifactId = item.id.parse().map_err(bad_reply)?;
        let artifact = self.describe(&id)?;
        if artifact.reference.artifact_id != id
            || artifact.reference.digest != digest
            || artifact.revision != item.revision
            || artifact.size_bytes != size_bytes
        {
            return Err(EvidenceError::Integrity);
        }
        Ok(Some(artifact))
    }

    fn show(&self, id: &str) -> Result<Value> {
        self.show_until(id, self.backend.deadline())
    }

    fn show_until(&self, id: &str, deadline: Instant) -> Result<Value> {
        let reply = self.backend.call_until(
            &["--case", &self.case_id, "show", id, "--depth", "full"],
            None,
            deadline,
        )?;
        matches_field(&reply, "result", "record_shown")?;
        matches_field(&reply, "id", id)?;
        matches_field(&reply["record"]["header"], "case_id", &self.case_id)?;
        Ok(reply)
    }
}

#[derive(Clone, Deserialize)]
struct RecordRef {
    id: String,
    revision: u64,
}

#[derive(Deserialize)]
struct RecordChange {
    id: String,
    revision: u64,
    client_ref: Option<String>,
}

#[derive(Deserialize)]
struct ReceiptArtifact {
    artifact: RecordRef,
    digest: String,
    size_bytes: u64,
}

#[derive(Deserialize)]
struct Transform {
    input: RecordRef,
    input_digest: String,
    transformation: String,
    version: String,
}

impl Transform {
    fn lineage(self) -> Result<Lineage> {
        if !full_id(&self.input.id, "art_") || self.input.revision == 0 {
            return Err(EvidenceError::Protocol);
        }
        Ok(Lineage {
            input: ArtifactRef {
                artifact_id: self.input.id.parse().map_err(bad_reply)?,
                digest: parse_digest(&self.input_digest)?,
            },
            revision: self.input.revision,
            transformation: self.transformation,
            version: self.version,
        })
    }
}

fn reported_withdrawal(reply: &Value) -> Result<Option<Withdrawal>> {
    let use_state = &reply["evidentiary_use"];
    let withdrawals = use_state["withdrawals"]
        .as_array()
        .ok_or(EvidenceError::Protocol)?;
    let state = match use_state["state"].as_str() {
        Some("in_use") if withdrawals.is_empty() => return Ok(None),
        Some("partially_withdrawn") if !withdrawals.is_empty() => Withdrawal::Partial,
        Some("withdrawn") if !withdrawals.is_empty() => Withdrawal::Entire,
        _ => return Err(EvidenceError::Protocol),
    };
    Ok(Some(state))
}

fn require_use(id: &ArtifactId, reply: &Value) -> Result<()> {
    match reported_withdrawal(reply)? {
        None => Ok(()),
        Some(state) => Err(EvidenceError::Withdrawn {
            artifact: id.clone(),
            state,
        }),
    }
}

fn extend(bytes: &mut Vec<u8>, excerpt: Value, part: Range<usize>) -> Result<()> {
    let start: usize = field(&excerpt, "start")?;
    let end: usize = field(&excerpt, "end")?;
    let data = match excerpt["availability"].as_str() {
        Some("text") => field::<String>(&excerpt, "text")?.into_bytes(),
        Some("binary") => STANDARD
            .decode(field::<String>(&excerpt, "bytes_base64")?)
            .map_err(bad_reply)?,
        _ => return Err(EvidenceError::Protocol),
    };
    if (start..end) != part || data.len() != part.len() {
        return Err(EvidenceError::Integrity);
    }
    bytes.extend(data);
    Ok(())
}

fn snapshot(reply: &Value) -> Result<Value> {
    let head = &reply["snapshot"];
    digest(head, "head_hash")?;
    field::<u64>(head, "sequence")?;
    Ok(head.clone())
}

fn field<T: DeserializeOwned>(value: &Value, key: &str) -> Result<T> {
    serde_json::from_value(value.get(key).ok_or(EvidenceError::Protocol)?.clone())
        .map_err(bad_reply)
}

fn matches_field(value: &Value, key: &str, expected: &str) -> Result<()> {
    if value[key].as_str() == Some(expected) {
        Ok(())
    } else {
        Err(EvidenceError::Protocol)
    }
}

fn bad_reply<T>(_: T) -> EvidenceError {
    EvidenceError::Protocol
}

pub(crate) fn full_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|payload| {
        payload.len() == 36
            && uuid::Uuid::parse_str(payload).is_ok_and(|id| id.to_string() == payload)
    })
}

fn command_key(operation: &str, key: &str) -> Result<String> {
    if key.trim().is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
        return Err(EvidenceError::InvalidInput);
    }
    Ok(format!(
        "scourge/{operation}/{}",
        Sha256Digest::of(key.as_bytes()).as_str()
    ))
}

fn hash(digest: &Sha256Digest) -> String {
    format!("sha256:{}", digest.as_str())
}

fn parse_digest(value: &str) -> Result<Sha256Digest> {
    value
        .strip_prefix("sha256:")
        .ok_or(EvidenceError::Protocol)?
        .parse()
        .map_err(bad_reply)
}

fn digest(value: &Value, key: &str) -> Result<Sha256Digest> {
    parse_digest(value[key].as_str().ok_or(EvidenceError::Protocol)?)
}

/// Canonical derivation metadata for retained verification records.
pub const VERIFICATION_TRANSFORMATION: &str =
    "evaluate compiled oracle and build verification record";
/// Version paired with [`VERIFICATION_TRANSFORMATION`].
pub const VERIFICATION_TRANSFORMATION_VERSION: &str = "scourge.verification.v1";
