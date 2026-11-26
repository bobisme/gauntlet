//! Retained audit evidence for a referenced send whose outcome is unresolved.

use super::{
    Instrument, RefusalTarget, RequestKey, RoundError, RunId, RunStep, SendOptions, Sha256Digest,
    Teapot, WireText, canonical, pre_dispatch_reference,
    runtime_matches_request_reference_instrument,
};
use crate::{
    evidence::Original,
    teapot::{RequestLookupState, decode_retained_request_lookup},
    wire::Effect,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

const MAX_AUTHORITY_BYTES: usize = 131_072;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DispatchFailureAuthority {
    pub(super) schema: String,
    pub(super) reference: WireText,
    pub(super) run_id: RunId,
    pub(super) request_key: RequestKey,
    pub(super) step_number: u64,
    pub(super) step: WireText,
    pub(super) request_digest: Sha256Digest,
    pub(super) action_index: u64,
    pub(super) argv_digest: Sha256Digest,
    pub(super) instrument_digest: Sha256Digest,
    pub(super) target_digest: Sha256Digest,
    pub(super) lookup_digest: Sha256Digest,
    pub(super) instrument: Instrument,
    pub(super) target: RefusalTarget,
    pub(super) native_state: RequestLookupState,
    pub(super) native_reason: Option<WireText>,
    pub(super) lookup_base64: String,
}

impl canonical::sealed::Sealed for DispatchFailureAuthority {}

impl DispatchFailureAuthority {
    pub(super) const SCHEMA: &str = "scourge.dispatch-failure-authority.v1";

    pub(super) fn encode(self, teapot: &Teapot) -> Result<DispatchFailure, RoundError> {
        let bytes = canonical::to_vec(&self).map_err(|_| RoundError::Wire)?;
        let authority = Self::decode(&bytes, teapot).ok_or(RoundError::CaptureMismatch)?;
        Ok(DispatchFailure { authority, bytes })
    }

    fn decode(bytes: &[u8], teapot: &Teapot) -> Option<Self> {
        if bytes.len() > MAX_AUTHORITY_BYTES {
            return None;
        }
        let authority: Self = canonical::from_slice(bytes).ok()?;
        if canonical::to_vec(&authority).ok()? != bytes
            || authority.schema != Self::SCHEMA
            || authority.action_index == 0
            || !authority.target.valid()
            || !runtime_matches_request_reference_instrument(teapot, &authority.instrument)
            || Sha256Digest::of(&canonical::to_vec(&authority.instrument).ok()?)
                != authority.instrument_digest
            || Sha256Digest::of(&canonical::to_vec(&authority.target).ok()?)
                != authority.target_digest
        {
            return None;
        }
        let reference = pre_dispatch_reference(
            &authority.run_id,
            &authority.request_key,
            authority.step_number,
            &authority.step,
            &authority.request_digest,
            authority.action_index,
            &authority.instrument_digest,
            &authority.target_digest,
        )
        .ok()?;
        if reference != authority.reference {
            return None;
        }
        let target = &authority.target;
        let argv_digest = teapot
            .send_argv_digest(
                target.method,
                &target.url,
                &target.session,
                SendOptions {
                    headers: &target.headers,
                    body: target.body.as_deref(),
                    ..SendOptions::default()
                },
                reference.as_str(),
            )
            .ok()?;
        let lookup_bytes = STANDARD.decode(&authority.lookup_base64).ok()?;
        let lookup = decode_retained_request_lookup(
            &lookup_bytes,
            reference.as_str(),
            &authority.instrument.engine_instance,
        )?;
        if argv_digest != authority.argv_digest
            || Sha256Digest::of(&lookup_bytes) != authority.lookup_digest
            || lookup.proves_not_sent()
            || lookup.state != authority.native_state
            || lookup.reason != authority.native_reason
        {
            return None;
        }
        Some(authority)
    }
}

#[derive(Debug)]
pub(crate) struct DispatchFailure {
    authority: DispatchFailureAuthority,
    pub(super) bytes: Vec<u8>,
}

impl DispatchFailure {
    pub(super) fn step_number(&self) -> u64 {
        self.authority.step_number
    }

    pub(super) fn key(&self) -> String {
        format!("dispatch-failure-{}", self.authority.reference.as_str())
    }

    pub(crate) fn bind_original(
        &self,
        run_id: &RunId,
        request_key: &RequestKey,
        step: &RunStep,
        original: &Original,
    ) -> Option<WireText> {
        let digest = Sha256Digest::of(&self.bytes);
        if self.authority.run_id != *run_id
            || self.authority.request_key != *request_key
            || self.authority.step_number != step.number
            || self.authority.step != step.step
            || self.authority.request_digest != step.request_digest
            || step.effects != Some(Effect::Unknown)
            || step.instrument_reference.is_some()
            || original.attachment.key != self.key()
            || original.attachment.position == 0
            || original.attachment.size_bytes != self.bytes.len()
            || original.attachment.digest != digest
            || original.artifact.digest != digest
        {
            return None;
        }
        format!("dispatch:{}", digest.as_str()).try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::Run,
        evidence::Attachment,
        rounds::PreDispatchRefusal,
        teapot::{BoundEngine, Environment, ExecutableKind},
        wire::Artifact,
    };
    use serde_json::{Value, json};

    fn fixture() -> (Teapot, Run, RunStep, DispatchFailure) {
        let engine = BoundEngine {
            instance: "engine-fixture".parse().unwrap(),
            project_id: "project-fixture".parse().unwrap(),
            enforced: false,
            policy_locked: true,
        };
        let teapot = Teapot::new(
            "/tmp/qualified-teapot".parse().unwrap(),
            ExecutableKind::Native,
            "/tmp/qualified-project".parse().unwrap(),
            Environment {
                home: "/tmp".parse().unwrap(),
                config_home: None,
                data_home: None,
                state_home: None,
                cache_home: None,
                runtime_dir: None,
            },
            engine.clone(),
        );
        let instrument = Instrument {
            name: "teapot".parse().unwrap(),
            version: "0.1.0".parse().unwrap(),
            commit: Some(crate::teapot::REQUEST_REFERENCE_SOURCE.parse().unwrap()),
            binary_digest: Some(
                crate::teapot::REQUEST_REFERENCE_BINARY_SHA256
                    .parse()
                    .unwrap(),
            ),
            engine_instance: engine.instance,
            project_id: engine.project_id,
            protocol: 1,
        };
        let run = Run::declare(
            "engagement-dispatch".parse().unwrap(),
            Sha256Digest::of(b"experiment"),
        );
        let step = RunStep {
            number: 1,
            step: "round.1.I1".parse().unwrap(),
            request_digest: Sha256Digest::of(b"request"),
            flow_id_floor: None,
            instrument_reference: None,
            effects: Some(Effect::Unknown),
            flows: Vec::new(),
        };
        let refusal = PreDispatchRefusal::authenticated_fixture(
            &run,
            &step,
            &teapot,
            &instrument,
            Sha256Digest::of(b"start observation"),
            Sha256Digest::of(b"end observation"),
        );
        let mut lookup: Value = serde_json::from_slice(&refusal.lookup_original).unwrap();
        lookup["lookup"]["state"] = json!("failed");
        lookup["lookup"]["reason"] = json!("outcome-unknown");
        lookup["lookup"]["evidence"]["last_recorded"] = json!("failed");
        lookup["lookup"]["evidence"]["units_admitted"] = json!(1);
        lookup["lookup"]["evidence"]["units_used"] = json!(1);
        lookup["lookup"]["evidence"]["dial"] = json!("started");
        let lookup = serde_json::to_vec(&lookup).unwrap();
        let dispatch = DispatchFailureAuthority {
            schema: DispatchFailureAuthority::SCHEMA.to_owned(),
            reference: refusal.reference,
            run_id: run.id.clone(),
            request_key: run.request_key.clone(),
            step_number: step.number,
            step: step.step.clone(),
            request_digest: step.request_digest.clone(),
            action_index: 1,
            argv_digest: refusal.argv_digest,
            instrument_digest: refusal.instrument_digest,
            target_digest: refusal.target_digest,
            lookup_digest: Sha256Digest::of(&lookup),
            instrument,
            target: refusal.target,
            native_state: RequestLookupState::Failed,
            native_reason: Some("outcome-unknown".parse().unwrap()),
            lookup_base64: STANDARD.encode(&lookup),
        }
        .encode(&teapot)
        .unwrap();
        (teapot, run, step, dispatch)
    }

    #[test]
    fn dispatch_failure_rejects_authority_and_lookup_drift() {
        let (teapot, _, _, dispatch) = fixture();
        assert!(DispatchFailureAuthority::decode(&dispatch.bytes, &teapot).is_some());
        let uncanonical = [&b" "[..], &dispatch.bytes].concat();
        assert!(DispatchFailureAuthority::decode(&uncanonical, &teapot).is_none());

        let authority: Value = serde_json::from_slice(&dispatch.bytes).unwrap();
        for (pointer, replacement) in [
            ("/action_index", json!(2)),
            ("/argv_digest", json!(Sha256Digest::of(b"other argv"))),
            ("/instrument/engine_instance", json!("other-engine")),
            ("/native_state", json!("completed")),
            ("/native_reason", json!(null)),
            ("/target/url", json!("http://127.0.0.1:9/other")),
        ] {
            let mut altered = authority.clone();
            *altered.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                DispatchFailureAuthority::decode(&canonical::to_vec(&altered).unwrap(), &teapot)
                    .is_none(),
                "accepted alteration at {pointer}",
            );
        }

        let mut altered = authority;
        altered["unexpected"] = json!(true);
        assert!(
            DispatchFailureAuthority::decode(&canonical::to_vec(&altered).unwrap(), &teapot)
                .is_none()
        );
        altered.as_object_mut().unwrap().remove("unexpected");
        let mut lookup: Value = serde_json::from_slice(
            &STANDARD
                .decode(altered["lookup_base64"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        lookup["lookup"]["unexpected"] = json!(true);
        let lookup = serde_json::to_vec(&lookup).unwrap();
        altered["lookup_digest"] = json!(Sha256Digest::of(&lookup));
        altered["lookup_base64"] = json!(STANDARD.encode(lookup));
        assert!(
            DispatchFailureAuthority::decode(&canonical::to_vec(&altered).unwrap(), &teapot)
                .is_none()
        );
    }

    #[test]
    fn dispatch_failure_links_only_exact_run_step_and_finalized_original() {
        let (_, run, step, dispatch) = fixture();
        let digest = Sha256Digest::of(&dispatch.bytes);
        let original = Original {
            attachment: Attachment {
                key: dispatch.key(),
                position: 1,
                digest: digest.clone(),
                size_bytes: dispatch.bytes.len(),
                request_digest: Sha256Digest::of(b"attach request"),
                accepted_at: "2026-11-26T12:00:00Z".to_owned(),
            },
            artifact: Artifact {
                artifact_id: "art_fixture".parse().unwrap(),
                digest: digest.clone(),
            },
        };
        assert_eq!(
            dispatch
                .bind_original(&run.id, &run.request_key, &step, &original)
                .unwrap()
                .as_str(),
            format!("dispatch:{}", digest.as_str()),
        );
        let wrong_key = RequestKey::generate();
        assert!(
            dispatch
                .bind_original(&run.id, &wrong_key, &step, &original)
                .is_none()
        );
        let mut wrong_step = step.clone();
        wrong_step.request_digest = Sha256Digest::of(b"other request");
        assert!(
            dispatch
                .bind_original(&run.id, &run.request_key, &wrong_step, &original)
                .is_none()
        );
        for wrong in [
            Original {
                artifact: Artifact {
                    digest: Sha256Digest::of(b"mismatched original"),
                    ..original.artifact.clone()
                },
                ..original.clone()
            },
            Original {
                attachment: Attachment {
                    key: "other-key".to_owned(),
                    ..original.attachment.clone()
                },
                ..original.clone()
            },
            Original {
                attachment: Attachment {
                    size_bytes: 0,
                    ..original.attachment.clone()
                },
                ..original.clone()
            },
        ] {
            assert!(
                dispatch
                    .bind_original(&run.id, &run.request_key, &step, &wrong)
                    .is_none()
            );
        }
    }
}
