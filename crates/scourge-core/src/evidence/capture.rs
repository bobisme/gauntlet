use serde::Serialize;
use serde_json::{Value, json};

use super::{
    ACTOR, ArtifactRef, Evidence, EvidenceError, InvestigationIdentity, MAX_ARTIFACT_BYTES,
    RecordRef, Result as EvidenceResult, bad_reply, command_key, digest, field, full_id, hash,
    matches_field,
};
use crate::{
    canonical::Sha256Digest,
    ids::{RunId, text_type},
};

const PROTOCOL: &str = "inv.capture.v1";

text_type!(
    CaptureHandle,
    "Investigation capture handle",
    |value: &str| full_id(value, "handle_")
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub handle: CaptureHandle,
    pub investigation_run_id: String,
    pub investigation: InvestigationIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub key: String,
    pub position: u64,
    pub digest: Sha256Digest,
    pub size_bytes: usize,
    pub request_digest: Sha256Digest,
    pub accepted_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Original {
    pub attachment: Attachment,
    pub artifact: ArtifactRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalized {
    pub complete: bool,
    pub original_artifacts: Vec<Original>,
    pub manifest_digest: Sha256Digest,
    pub missing_positions: Vec<u64>,
    pub transaction_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureState {
    pub capture: Capture,
    pub last_position: Option<u64>,
    pub attachments: Vec<Attachment>,
    pub finalized: Option<Finalized>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    Complete,
    Partial,
    Interrupted,
}

impl Evidence {
    /// Declare a capture without performing any producer action. Retrying the
    /// same Scourge run ID returns the original Investigation handle.
    pub fn capture(&self, run: &RunId) -> EvidenceResult<Capture> {
        #[cfg(test)]
        if let Some(effects) = &self.execution_effects {
            effects.evidence_capture();
            return Ok(Capture {
                handle: "handle_00000000-0000-0000-0000-000000000000"
                    .parse()
                    .unwrap(),
                investigation_run_id: format!("probe-{}", run.as_str()),
                investigation: self.investigation().clone(),
            });
        }
        let key = command_key("capture/begin", run.as_str())?;
        let request = json!({
            "key": key,
            "actor": ACTOR,
            "producer": {"name": "scourge", "version": env!("CARGO_PKG_VERSION")},
            "external_run_id": run,
            "intent": {"label": "Scourge evidence capture"},
            "case": {"kind": "existing", "case_id": self.case_id},
            "protocol": PROTOCOL,
            "metadata": {"scourge_investigation": self.investigation()},
        });
        let reply = self
            .backend
            .call(&["capture", "begin", "--input", "-"], Some(&request))?;
        matches_field(&reply, "protocol", PROTOCOL)?;
        matches_field(&reply["commit"], "command_id", &key)?;
        self.capture_reference(&reply, Some(run))
    }

    /// Attach original output to one capture position. Investigation verifies
    /// the exact bytes before it acknowledges a durable staging receipt.
    pub fn attach(
        &self,
        capture: &Capture,
        position: u64,
        key: &str,
        bytes: &[u8],
    ) -> EvidenceResult<Attachment> {
        #[cfg(test)]
        if let Some(effects) = &self.execution_effects {
            effects.evidence_attachment();
            return Ok(Attachment {
                key: key.to_owned(),
                position,
                digest: Sha256Digest::of(bytes),
                size_bytes: bytes.len(),
                request_digest: Sha256Digest::of(b"execution probe attachment"),
                accepted_at: "1970-01-01T00:00:00Z".to_owned(),
            });
        }
        if position == 0 || key.is_empty() {
            return Err(EvidenceError::InvalidInput);
        }
        if key.len() > 256 {
            return Err(EvidenceError::RequestTooLarge);
        }
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(EvidenceError::TooLarge);
        }
        if capture.investigation != *self.investigation() {
            return Err(EvidenceError::UnqualifiedInvestigation);
        }
        let sha256 = Sha256Digest::of(bytes);
        let path = format!(
            "scourge-{}",
            Sha256Digest::of(
                &serde_json::to_vec(&(&capture.handle, key, &sha256)).map_err(bad_reply)?
            )
            .as_str()
        );
        let request = json!({
            "handle": capture.handle, "position": position, "key": key,
            "role": "original-output", "source": {"kind": "file", "path": path},
            "expected_digest": hash(&sha256), "expected_size_bytes": bytes.len(),
        });
        let receipt = self.backend.attach(&path, &request, bytes)?;
        let item = attachment(&receipt, capture)?;
        if item.position != position
            || item.key != key
            || item.digest != sha256
            || item.size_bytes != bytes.len()
        {
            return Err(EvidenceError::Integrity);
        }
        Ok(item)
    }

    /// Seal a declared inventory. Complete capture requires Investigation's
    /// strict inventory gate. Partial/interrupted capture preserves gaps.
    pub fn finalize(
        &self,
        capture: &Capture,
        expected_position: Option<u64>,
        completion: Completion,
        item_keys: &[&str],
    ) -> EvidenceResult<Finalized> {
        #[cfg(test)]
        if let Some(effects) = &self.execution_effects {
            effects.evidence_finalize();
            return Ok(Finalized {
                complete: completion == Completion::Complete,
                original_artifacts: Vec::new(),
                manifest_digest: Sha256Digest::of(b"execution probe manifest"),
                missing_positions: Vec::new(),
                transaction_id: format!("probe-{}", capture.handle.as_str()),
            });
        }
        if item_keys.len() > 100_000
            || item_keys.iter().any(|key| key.len() > 256)
            || item_keys.iter().map(|key| key.len() + 3).sum::<usize>()
                > super::transport::MAX_CONTROL_BYTES
        {
            return Err(EvidenceError::RequestTooLarge);
        }
        if capture.investigation != *self.investigation() {
            return Err(EvidenceError::UnqualifiedInvestigation);
        }
        let key = command_key("capture/finalize", capture.handle.as_str())?;
        let request = json!({
            "handle": capture.handle, "key": key, "expected_last_position": expected_position,
            "completion": completion, "strict_artifact_inventory": completion == Completion::Complete,
            "execution": {"state": "unknown"}, "declared_artifacts": item_keys,
            "metadata": {"scourge_investigation": self.investigation()},
        });
        let receipt = self
            .backend
            .call(&["capture", "finalize", "--input", "-"], Some(&request))?;
        matches_field(&receipt["commit"], "command_id", &key)?;
        let state = self.recover(&capture.handle)?;
        let finalized = state.finalized.ok_or(EvidenceError::Integrity)?;
        if state.capture != *capture
            || finalized.transaction_id != field::<String>(&receipt["commit"], "transaction_id")?
            || finalized.manifest_digest != digest(&receipt, "manifest_digest")?
        {
            return Err(EvidenceError::Integrity);
        }
        Ok(finalized)
    }

    /// Recover only the accepted prefix. A staged attachment has no published
    /// Artifact ID until Investigation commits the capture manifest.
    pub fn recover(&self, handle: &CaptureHandle) -> EvidenceResult<CaptureState> {
        self.recover_capture(handle, None)
    }

    pub(crate) fn recover_for_run(
        &self,
        handle: &CaptureHandle,
        run: &RunId,
    ) -> EvidenceResult<CaptureState> {
        self.recover_capture(handle, Some(run))
    }

    fn recover_capture(
        &self,
        handle: &CaptureHandle,
        run: Option<&RunId>,
    ) -> EvidenceResult<CaptureState> {
        let reply = self
            .backend
            .call(&["capture", "recover", "--handle", handle.as_str()], None)?;
        let handles: Vec<Value> = field(&reply, "handles")?;
        let item = match handles.as_slice() {
            [item] => item,
            [] => return Err(EvidenceError::Missing),
            _ => return Err(EvidenceError::Protocol),
        };
        if let Some(run) = run {
            matches_field(item, "external_run_id", run.as_str())?;
            matches_field(&item["producer"], "name", "scourge")?;
        }
        let capture = self.capture_reference(item, run)?;
        if capture.handle != *handle {
            return Err(EvidenceError::Integrity);
        }
        let retained_run = self.show(&capture.investigation_run_id)?;
        let body = &retained_run["record"]["body"];
        matches_field(&body["capture"], "handle", handle.as_str())?;
        matches_field(&body["capture"], "protocol", PROTOCOL)?;
        if let Some(run) = run {
            matches_field(body, "external_ref", run.as_str())?;
            matches_field(body, "producer", ACTOR)?;
        }
        let pinned: InvestigationIdentity =
            field(&body["capture"]["metadata"], "scourge_investigation")?;
        if pinned != capture.investigation {
            return Err(EvidenceError::UnqualifiedInvestigation);
        }
        let attachments = field::<Vec<Value>>(item, "artifacts")?
            .iter()
            .map(|value| attachment(value, &capture))
            .collect::<EvidenceResult<Vec<_>>>()?;
        let last_position = optional(item, "last_position")?;
        if attachments.last().map(|item| item.position) != last_position
            || attachments
                .iter()
                .enumerate()
                .any(|(offset, item)| item.position != offset as u64 + 1)
        {
            return Err(EvidenceError::Integrity);
        }
        let finalized = match item["seal"].as_str() {
            Some("open") if item.get("finalized").is_none() => None,
            Some("finalized") => Some(read_finalized(
                &capture,
                &attachments,
                &item["finalized"],
                &body["capture_finalization"],
            )?),
            _ => return Err(EvidenceError::Protocol),
        };
        Ok(CaptureState {
            capture,
            last_position,
            attachments,
            finalized,
        })
    }

    fn capture_reference(
        &self,
        reply: &Value,
        expected_run: Option<&RunId>,
    ) -> EvidenceResult<Capture> {
        matches_field(reply, "case_id", &self.case_id)?;
        if let Some(run) = expected_run {
            matches_field(reply, "external_run_id", run.as_str())?;
        }
        let investigation_run_id = field::<String>(reply, "run_id")?;
        if !full_id(&investigation_run_id, "run_") {
            return Err(EvidenceError::Protocol);
        }
        Ok(Capture {
            handle: field(reply, "handle")?,
            investigation_run_id,
            investigation: self.investigation().clone(),
        })
    }
}

fn attachment(value: &Value, capture: &Capture) -> EvidenceResult<Attachment> {
    matches_field(value, "role", "original-output")?;
    if value["availability"] == "missing" {
        return Err(EvidenceError::Integrity);
    }
    matches_field(value, "availability", "staged")?;
    let receipt = &value["receipt"];
    matches_field(receipt, "handle", capture.handle.as_str())?;
    matches_field(receipt, "run_id", &capture.investigation_run_id)?;
    if !matches!(
        receipt["result"].as_str(),
        Some("accepted" | "already_accepted")
    ) {
        return Err(EvidenceError::Protocol);
    }
    Ok(Attachment {
        key: field(receipt, "key")?,
        position: field(receipt, "position")?,
        digest: digest(value, "digest")?,
        size_bytes: field(value, "size_bytes")?,
        request_digest: digest(receipt, "request_digest")?,
        accepted_at: field(receipt, "accepted_at")?,
    })
}

fn read_finalized(
    capture: &Capture,
    attachments: &[Attachment],
    receipt: &Value,
    manifest: &Value,
) -> EvidenceResult<Finalized> {
    matches_field(receipt, "handle", capture.handle.as_str())?;
    matches_field(receipt, "run_id", &capture.investigation_run_id)?;
    let finalization: String = field(receipt, "finalization")?;
    matches_field(manifest, "finalization", &finalization)?;
    let complete = match finalization.as_str() {
        "finalized" => true,
        "finalized_partial" => false,
        _ => return Err(EvidenceError::Protocol),
    };
    let manifest_digest = digest(receipt, "manifest_digest")?;
    if manifest_digest != digest(&manifest["manifest"], "digest")? {
        return Err(EvidenceError::Integrity);
    }
    let inventory: Vec<Value> = field(manifest, "artifacts")?;
    let mut originals = Vec::with_capacity(attachments.len());
    for entry in inventory {
        let retention = &entry["retention"];
        match retention["state"].as_str() {
            Some("retained") => {}
            Some("missing") if !complete => continue,
            _ => return Err(EvidenceError::Integrity),
        }
        let item = attachments
            .get(originals.len())
            .ok_or(EvidenceError::Integrity)?;
        let key: String = field(&entry, "key")?;
        if key != item.key
            || field::<u64>(&entry, "position")? != item.position
            || digest(retention, "digest")? != item.digest
            || field::<usize>(retention, "size_bytes")? != item.size_bytes
        {
            return Err(EvidenceError::Integrity);
        }
        let identity: RecordRef = field(retention, "artifact_ref")?;
        if identity.revision != 1 || !full_id(&identity.id, "art_") {
            return Err(EvidenceError::Protocol);
        }
        originals.push(Original {
            attachment: item.clone(),
            artifact: ArtifactRef {
                artifact_id: identity.id.parse().map_err(bad_reply)?,
                digest: item.digest.clone(),
            },
        });
    }
    if originals.len() != attachments.len() {
        return Err(EvidenceError::Integrity);
    }
    Ok(Finalized {
        complete,
        original_artifacts: originals,
        manifest_digest,
        missing_positions: optional(receipt, "missing_positions")?.unwrap_or_default(),
        transaction_id: field(&receipt["commit"], "transaction_id")?,
    })
}

fn optional<T: serde::de::DeserializeOwned>(value: &Value, key: &str) -> EvidenceResult<Option<T>> {
    match value.get(key) {
        Some(value) => serde_json::from_value(value.clone()).map_err(bad_reply),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{execution_effects::ExecutionEffects, wire::Artifact};

    fn probe(effects: ExecutionEffects) -> Evidence {
        Evidence::execution_probe(
            Artifact {
                artifact_id: "art_capture_probe".parse().unwrap(),
                digest: Sha256Digest::of(b"capture probe"),
            },
            effects,
        )
    }

    #[test]
    fn capture_begin_reference_requires_the_exact_external_run() {
        let effects = ExecutionEffects::default();
        let evidence = probe(effects.clone());
        let expected: RunId = "R-expected".parse().unwrap();
        let reply = json!({
            "case_id": "case_execution_probe",
            "external_run_id": "R-other",
            "run_id": "run_12345678-1234-4234-8234-123456789abc",
            "handle": "handle_12345678-1234-4234-8234-123456789abc",
        });
        assert!(matches!(
            evidence.capture_reference(&reply, Some(&expected)),
            Err(EvidenceError::Protocol)
        ));
        assert_eq!(effects.snapshot(), Default::default());
    }
}
