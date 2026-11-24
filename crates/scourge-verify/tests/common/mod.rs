//! Builders shared by the `scourge-verify` tests.
//!
//! Every helper produces typed saved observations only. Nothing here performs
//! I/O or reaches a network.

#![allow(dead_code)]

pub mod property;

use std::io::Write;

use flate2::{Compression, write::DeflateEncoder, write::GzEncoder, write::ZlibEncoder};

use scourge_core::{
    canonical::Sha256Digest,
    ids::{ArtifactId, RunId, WireText},
    wire::{Artifact, Completeness},
};

use scourge_verify::{
    Canary, CleanupDetail, DecodeLimits, Decoding, FieldName, FlowId, OBSERVATION_SCHEMA,
    ORACLE_ID, ORACLE_VERSION, ObjectKey, OracleRef, PlantDetail, PlantedCanary, SavedFlow,
    SavedObservations, Subject,
};

pub const RUN: &str = "R-1";
pub const OWNER: &str = "subject-owner";
pub const OTHER: &str = "subject-other";
pub const PRIMARY_OBJECT: &str = "object-primary";
pub const CONTROL_OBJECT: &str = "object-control";
pub const FIELD: &str = "label";

pub fn text(value: &str) -> WireText {
    WireText::try_from(value.to_owned()).expect("wire text")
}

pub fn run() -> RunId {
    RunId::try_from(RUN.to_owned()).expect("run id")
}

/// A deterministic 32-lowercase-hex canary, distinct per seed.
pub fn canary(seed: u8) -> Canary {
    Canary::parse(&format!("{seed:02x}").repeat(16)).expect("canary form")
}

pub fn artifact(id: &str) -> Artifact {
    Artifact {
        artifact_id: ArtifactId::try_from(format!("artifact-{id}")).expect("artifact id"),
        digest: Sha256Digest::of(id.as_bytes()),
    }
}

pub fn field(name: &str) -> FieldName {
    FieldName::from(text(name))
}

pub fn object(name: &str) -> ObjectKey {
    ObjectKey::from(text(name))
}

pub fn subject(name: &str) -> Subject {
    Subject::from(text(name))
}

/// A decoded body that carries one canary in a JSON field.
pub fn body_with(canary: &Canary) -> Vec<u8> {
    format!("{{\"secret\":\"{}\"}}", canary.as_str()).into_bytes()
}

/// A decoded body that carries one canary in a named JSON field.
pub fn body_with_field(name: &str, canary: &Canary) -> Vec<u8> {
    format!("{{\"{name}\":\"{}\"}}", canary.as_str()).into_bytes()
}

/// A decoded body that carries each canary in its own JSON field.
pub fn body_with_all(canaries: &[&Canary]) -> Vec<u8> {
    let members: Vec<String> = canaries
        .iter()
        .enumerate()
        .map(|(index, canary)| format!("\"f{index}\":\"{}\"", canary.as_str()))
        .collect();
    format!("{{{}}}", members.join(",")).into_bytes()
}

/// Add one more fresh per-field canary to the primary plant (POR-10).
pub fn plant_primary(observations: &mut SavedObservations, name: &str, canary: &Canary) {
    saved_mut(observations, FlowId::P)
        .plant
        .as_mut()
        .expect("plant")
        .canaries
        .push(PlantedCanary {
            field: field(name),
            canary: canary.clone(),
        });
}

pub fn sequence(id: FlowId) -> u64 {
    let position = FlowId::REQUIRED
        .iter()
        .position(|candidate| *candidate == id)
        .expect("required flow");
    u64::try_from(position).expect("small index") + 1
}

pub fn flow(id: FlowId) -> SavedFlow {
    SavedFlow {
        flow: id,
        run: run(),
        sequence: sequence(id),
        completeness: Completeness::Complete,
        decoding: Decoding::default(),
        decoder: None,
        original: Some(artifact(id.as_str())),
        body: b"no canary here".to_vec(),
        subject: None,
        plant: None,
        cleanup: None,
    }
}

/// A round that is valid setup with no exposure: F1 shows the primary canary,
/// F4 shows only the control canary, and no treatment read shows the primary.
pub fn observations() -> SavedObservations {
    let mut flows = Vec::with_capacity(FlowId::REQUIRED.len());
    for id in FlowId::REQUIRED {
        let mut saved = flow(id);
        match id {
            FlowId::I1 | FlowId::I3 => saved.subject = Some(subject(OWNER)),
            FlowId::I2 | FlowId::I4 => saved.subject = Some(subject(OTHER)),
            FlowId::P => {
                saved.plant = Some(PlantDetail {
                    object: Some(object(PRIMARY_OBJECT)),
                    canaries: vec![PlantedCanary {
                        field: field(FIELD),
                        canary: canary(0x11),
                    }],
                });
            }
            FlowId::P2 => {
                saved.plant = Some(PlantDetail {
                    object: Some(object(CONTROL_OBJECT)),
                    canaries: vec![PlantedCanary {
                        field: field(FIELD),
                        canary: canary(0x22),
                    }],
                });
            }
            FlowId::F1 => saved.body = body_with(&canary(0x11)),
            FlowId::F4 => saved.body = body_with(&canary(0x22)),
            FlowId::C => {
                saved.cleanup = Some(CleanupDetail {
                    attempted: true,
                    removed: vec![object(PRIMARY_OBJECT), object(CONTROL_OBJECT)],
                });
            }
            _ => {}
        }
        flows.push(saved);
    }
    SavedObservations {
        schema: text(OBSERVATION_SCHEMA),
        oracle: OracleRef {
            id: text(ORACLE_ID),
            version: text(ORACLE_VERSION),
        },
        run: run(),
        round: 1,
        limits: DecodeLimits::default(),
        flows,
    }
}

pub fn primary() -> Canary {
    canary(0x11)
}

pub fn control() -> Canary {
    canary(0x22)
}

pub fn saved_mut(observations: &mut SavedObservations, id: FlowId) -> &mut SavedFlow {
    observations
        .flows
        .iter_mut()
        .find(|saved| saved.flow == id)
        .expect("flow present")
}

pub fn saved(observations: &SavedObservations, id: FlowId) -> &SavedFlow {
    observations
        .flows
        .iter()
        .find(|saved| saved.flow == id)
        .expect("flow present")
}

/// Put a canary in a read flow's saved body.
pub fn show(observations: &mut SavedObservations, id: FlowId, canary: &Canary) {
    saved_mut(observations, id).body = body_with(canary);
}

pub fn remove_flow(observations: &mut SavedObservations, id: FlowId) {
    observations.flows.retain(|saved| saved.flow != id);
}

pub fn gzip(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

pub fn zlib(body: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).expect("deflate write");
    encoder.finish().expect("deflate finish")
}

pub fn raw_deflate(body: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).expect("raw deflate write");
    encoder.finish().expect("raw deflate finish")
}

/// HTTP/1.1 chunk framing with one chunk per size, then trailers.
pub fn chunked(body: &[u8], chunk_sizes: &[usize]) -> Vec<u8> {
    let mut framed = Vec::new();
    let mut rest = body;
    for size in chunk_sizes {
        if rest.is_empty() {
            break;
        }
        // The header states the size that is actually written: a generated
        // body can be shorter than the requested chunk.
        let written = (*size).min(rest.len());
        let (chunk, tail) = rest.split_at(written);
        framed.extend_from_slice(format!("{written:x};ext=1\r\n").as_bytes());
        framed.extend_from_slice(chunk);
        framed.extend_from_slice(b"\r\n");
        rest = tail;
    }
    if !rest.is_empty() {
        framed.extend_from_slice(format!("{:x}\r\n", rest.len()).as_bytes());
        framed.extend_from_slice(rest);
        framed.extend_from_slice(b"\r\n");
    }
    framed.extend_from_slice(b"0\r\nx-trailer: 1\r\n\r\n");
    framed
}

/// The body as a JSON string literal, with the payload escaped.
pub fn escaped_json(body: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(body).expect("utf-8 body");
    serde_json::to_vec(&serde_json::Value::String(text.to_owned())).expect("json string")
}

/// The referee fixture's `escaped_json` shape: `{"document":"<escaped>"}`.
pub fn escaped_json_document(body: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(body).expect("utf-8 body");
    serde_json::to_vec(&serde_json::json!({ "document": text })).expect("json document wrapper")
}

/// Two concatenated gzip members, as RFC 1952 permits in one body.
pub fn gzip_members(members: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for member in members {
        body.extend_from_slice(&gzip(member));
    }
    body
}
