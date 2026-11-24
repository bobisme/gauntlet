//! The trusted verifier's pure oracle library.
//!
//! This crate holds the frozen `web.private-object-read.v1` oracle: a pure,
//! offline function over the verifier's own typed saved observations
//! ([`oracle::evaluate`]), the bounded decoder that feeds it ([`decode`]), the
//! compiled registration that pins it to
//! [`scourge.oracle-specifications.v1`](../../../docs/contracts/oracle-specifications.v1.json)
//! ([`registry`]) and the read-only out-of-class gate ([`scope`]).
//!
//! Deliberately absent: network access, credentials, target interaction, an
//! instrument adapter, active dispatch and any policy input. The oracle
//! measures exposure; policy decides what the measurement means.

#![forbid(unsafe_code)]

pub mod decode;
pub mod observations;
pub mod oracle;
pub mod registry;
pub mod scope;

pub use decode::{
    ContentCoding, DecodeError, DecodeLimits, DecodedBody, DecoderName, Decoding, TransferCoding,
    decode,
};
pub use observations::{
    Canary, CleanupDetail, FieldName, FlowId, OBSERVATION_SCHEMA, ObjectKey, OracleRef,
    PlantDetail, PlantedCanary, SavedFlow, SavedObservations, Subject,
};
pub use oracle::{
    CleanupRecord, Evaluation, FaultCause, IncompleteCause, Verdict, evaluate, supervise,
};
pub use registry::{InvalidReason, ORACLE_CONTRACT_KEY, ORACLE_ID, ORACLE_VERSION};
pub use scope::{ClaimClass, Dispatch, dispatch};
