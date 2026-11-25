//! Shared, in-memory parser invariants for the replay tests and libFuzzer.
//!
//! Every function here takes bytes the system does not control and asserts the
//! frozen hostile-input invariants over them (INV-22, INV-44, §6.5). Nothing
//! here reads the network, writes to disk, mints evidence or changes a verdict:
//! a malformed input produces a typed error and no effect.
//!
//! Each entry returns an [`Outcome`]: the ordered trace of the production
//! calls it made and the typed decision each one took. The libFuzzer binaries
//! and `fuzz/tests/corpus_replay.rs` call the *same* six functions, so a replay
//! can assert that the entry really drove its parsers. An entry that returns
//! immediately returns an empty trace, which no corpus seed accepts.
#![forbid(unsafe_code)]

use std::fmt;

use scourge_core::{
    canonical::{self, CanonicalJson, JsonError, Sha256Digest},
    engagement::{EngagementDraft, ManifestRevision},
    is_schema_stanza,
    policy::PolicyRule,
    request::NormalizedInput,
    teapot::{
        BodyWindow, BoundEngine, ExecutableKind, InvocationError, NativeOutput,
        hostile::{self, Trusted},
    },
    template::{ClaimTemplate, FrozenExperiment, TemplateError},
    wire::AbsolutePath,
    wire::{
        self, AccountingV1, DiagnosticV1, PublicationIntentV1, RequestInputV1, ResponseV1,
        VerificationV1,
    },
};
use scourge_verify::{
    ContentCoding, DecodeLimits, Decoding, Evaluation, FaultCause, IncompleteCause,
    SavedObservations, TransferCoding, Verdict, evaluate,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Hard input cap in replay and fuzzing, independent of the fuzzer's settings.
pub const MAX_INPUT_BYTES: usize = 16 * 1024;

/// The single stage an entry records for an input it refuses to parse.
pub const INPUT_LIMIT_STAGE: &str = "input-limit";

/// A minimal `scourge.diagnostic.v1` wrapper event.
///
/// `corpus_replay.rs` checks that this parses as [`DiagnosticV1`], so a frozen
/// shape change fails the fast suite instead of silently weakening the
/// wrapper-only check below.
pub const DIAGNOSTIC_EVENT: &[u8] = br#"{"schema":"scourge.diagnostic.v1","workspace":"/w","engagement":"e","request_key":"rk_fixture","run_id":"R-1","diagnostic":{"code":"TOOL_UNAVAILABLE","stage":"describe","message":"The bound executable was unavailable.","native_exit":null,"wrapper_exit":0}}"#;

// -- The entry contract -----------------------------------------------------

/// One schema-owned decision a shared entry took through a production parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The production call accepted the input.
    Accepted,
    /// The production call refused the input with its own typed error.
    Rejected(String),
    /// The production call classified the input instead of accepting it, such
    /// as the oracle's verdict over saved observations.
    Classified(&'static str),
    /// Not reached, because an earlier stage already refused the input.
    Skipped,
}

impl Decision {
    /// The decision a typed production result represents.
    pub fn of<T, E: fmt::Display>(result: Result<T, E>) -> Self {
        match result {
            Ok(_) => Self::Accepted,
            Err(error) => Self::Rejected(error.to_string()),
        }
    }
}

/// The ordered trace of production decisions one shared entry observed.
///
/// The stages are the contract: [`stages`] states which ones each entry must
/// visit for any input inside the cap, regardless of whether that input is
/// accepted or refused.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome(Vec<(&'static str, Decision)>);

impl Outcome {
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// The trace of an entry that refused the input before parsing it.
    #[must_use]
    pub fn over_limit() -> Self {
        Self(vec![(INPUT_LIMIT_STAGE, Decision::Skipped)])
    }

    fn record(&mut self, stage: &'static str, decision: Decision) {
        self.0.push((stage, decision));
    }

    /// Every decision the entry recorded, in call order.
    #[must_use]
    pub fn decisions(&self) -> &[(&'static str, Decision)] {
        &self.0
    }

    /// The stages the entry visited, in call order.
    pub fn stages(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.iter().map(|(stage, _)| *stage)
    }

    /// The decision recorded for one stage.
    #[must_use]
    pub fn get(&self, stage: &str) -> Option<&Decision> {
        self.0
            .iter()
            .find(|(name, _)| *name == stage)
            .map(|(_, decision)| decision)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether one stage accepted a document.
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.0
            .iter()
            .any(|(_, decision)| matches!(decision, Decision::Accepted))
    }

    /// Whether one stage refused the input with a typed error.
    #[must_use]
    pub fn rejected(&self) -> bool {
        self.0
            .iter()
            .any(|(_, decision)| matches!(decision, Decision::Rejected(_)))
    }
}

/// One shared entry: the exact function a libFuzzer target and a replay call.
pub type Entry = fn(&[u8]) -> Outcome;

/// Every shared entry, in corpus order.
///
/// `fuzz/fuzz_targets/<name>.rs` must call the same-named function and nothing
/// else, which `fuzz/tests/targets.rs` checks statically.
pub const ENTRIES: &[(&str, Entry)] = &[
    ("canonical_json", canonical_json),
    ("wire_contracts", wire_contracts),
    ("declarations", declarations),
    ("teapot_output", teapot_output),
    ("oracle_observations", oracle_observations),
    ("body_decoder", body_decoder),
];

const CANONICAL_JSON_STAGES: &[&str] = &[
    "canonical.parse",
    "canonical.store",
    "canonical.digest",
    "wire.shape",
];

const WIRE_CONTRACTS_STAGES: &[&str] = &[
    "wire.value",
    "wire.accounting",
    "wire.diagnostic",
    "wire.publication-intent",
    "wire.response",
    "wire.verification",
    "wire.checkpoint",
    "wire.request-input",
];

const DECLARATIONS_STAGES: &[&str] = &[
    "engagement.json",
    "engagement.toml",
    "policy-rule",
    "claim-template",
    "claim-template.rules",
    "manifest",
    "experiment",
    "experiment.freeze",
];

const ORACLE_OBSERVATIONS_STAGES: &[&str] = &["oracle.record", "oracle.verdict"];

/// The trailing parsers of the three passive replies that carry a typed body
/// beyond the schema: the engine identity, one bounded job page and the pass
/// ceiling.
pub const REPLY_STAGES: &[&str] = &["version.identity", "jobs.page", "pass.ceiling"];

/// The body window the harness asks `flows show` for: the adapter's own default.
pub const FLOW_WINDOW_OFFSET: u64 = 0;
pub const FLOW_WINDOW_BYTES: u64 = 32 * 1024;

/// The bound engine the `describe.json` capture was taken against.
///
/// The identity check compares untrusted reply bytes to this trusted binding, so
/// the harness fixes it at the captured values.
#[must_use]
pub fn fixture_engine() -> (AbsolutePath, BoundEngine) {
    let project: AbsolutePath = "/tmp/scourge-contract-wr1psuja"
        .parse()
        .expect("the captured project path is absolute");
    let engine = BoundEngine {
        instance: "9ad076d69051393fe80e0883e6035061"
            .parse()
            .expect("the captured instance is wire text"),
        project_id: "8a4699e6590e3a5f7cd42f07f0c712f1"
            .parse()
            .expect("the captured project id is wire text"),
        enforced: false,
        policy_locked: false,
    };
    (project, engine)
}

/// Every action reply with its trusted operator parameters.
///
/// The parameters come from bound run state in a live call; here they are the
/// values each captured seed was recorded with, so the harness varies only the
/// bytes Teapot printed.
#[must_use]
pub fn action_cases() -> Vec<(&'static str, NativeOutput, Trusted<'static>)> {
    let window = BodyWindow::new(FLOW_WINDOW_OFFSET, FLOW_WINDOW_BYTES)
        .expect("the adapter default body window is valid");
    vec![
        (
            "shape.send",
            NativeOutput::Send,
            Trusted::Send {
                session: "alice",
                follow: None,
            },
        ),
        (
            "shape.macro_run",
            NativeOutput::MacroRun,
            Trusted::MacroRun {
                name: "plant",
                session: "alice",
                until: None,
            },
        ),
        (
            "shape.macro_replay",
            NativeOutput::MacroReplay,
            Trusted::MacroReplay {
                name: "plant",
                session: "alice",
                step: 2,
            },
        ),
        (
            "shape.read_flow",
            NativeOutput::ReadFlow,
            Trusted::ReadFlow { id: 3, window },
        ),
        (
            "shape.job_stop",
            NativeOutput::JobStop,
            Trusted::JobStop { id: 41 },
        ),
    ]
}

/// Every transfer and content coding the body decoder is exercised with, and
/// the stage name each combination records. A witness asserts this is the full
/// cross product with the JSON-string wrapper.
pub const BODY_MATRIX: &[(&str, TransferCoding, ContentCoding, bool)] = &[
    (
        "body.identity.identity.raw",
        TransferCoding::Identity,
        ContentCoding::Identity,
        false,
    ),
    (
        "body.identity.identity.string",
        TransferCoding::Identity,
        ContentCoding::Identity,
        true,
    ),
    (
        "body.identity.gzip.raw",
        TransferCoding::Identity,
        ContentCoding::Gzip,
        false,
    ),
    (
        "body.identity.gzip.string",
        TransferCoding::Identity,
        ContentCoding::Gzip,
        true,
    ),
    (
        "body.identity.deflate.raw",
        TransferCoding::Identity,
        ContentCoding::Deflate,
        false,
    ),
    (
        "body.identity.deflate.string",
        TransferCoding::Identity,
        ContentCoding::Deflate,
        true,
    ),
    (
        "body.chunked.identity.raw",
        TransferCoding::Chunked,
        ContentCoding::Identity,
        false,
    ),
    (
        "body.chunked.identity.string",
        TransferCoding::Chunked,
        ContentCoding::Identity,
        true,
    ),
    (
        "body.chunked.gzip.raw",
        TransferCoding::Chunked,
        ContentCoding::Gzip,
        false,
    ),
    (
        "body.chunked.gzip.string",
        TransferCoding::Chunked,
        ContentCoding::Gzip,
        true,
    ),
    (
        "body.chunked.deflate.raw",
        TransferCoding::Chunked,
        ContentCoding::Deflate,
        false,
    ),
    (
        "body.chunked.deflate.string",
        TransferCoding::Chunked,
        ContentCoding::Deflate,
        true,
    ),
];

/// The stages an entry must visit for any input inside the size cap.
///
/// A replay compares the entry's trace to this list, so an entry that stops
/// calling a parser (or calls a different one) fails instead of staying green.
#[must_use]
pub fn stages(target: &str) -> Option<Vec<&'static str>> {
    Some(match target {
        "canonical_json" => CANONICAL_JSON_STAGES.to_vec(),
        "wire_contracts" => WIRE_CONTRACTS_STAGES.to_vec(),
        "declarations" => DECLARATIONS_STAGES.to_vec(),
        "teapot_output" => NativeOutput::ALL
            .iter()
            .map(|output| output.name())
            .chain(action_cases().into_iter().map(|(stage, ..)| stage))
            .chain(REPLY_STAGES.iter().copied())
            .collect(),
        "oracle_observations" => ORACLE_OBSERVATIONS_STAGES.to_vec(),
        "body_decoder" => BODY_MATRIX.iter().map(|(stage, ..)| *stage).collect(),
        _ => return None,
    })
}

fn assert_stanza(stanza: &str) {
    assert!(
        is_schema_stanza(stanza),
        "rejection must name a schema-owned stanza, found {stanza:?}"
    );
}

// -- canonical_json ---------------------------------------------------------

pub fn canonical_json(input: &[u8]) -> Outcome {
    if input.len() > MAX_INPUT_BYTES {
        return Outcome::over_limit();
    }
    let mut outcome = Outcome::new();

    // INV-44: a duplicate member name is rejected at every depth, whichever
    // way it is spelled. `serde_json` would otherwise keep the last value.
    let text = String::from_utf8_lossy(&input[..input.len().min(128)]);
    let key = serde_json::to_string(&text).unwrap();
    let prefixed = serde_json::to_string(&format!("x{text}")).unwrap();
    for duplicate in [
        // The same name twice, spelled from arbitrary input bytes.
        format!(r#"{{"outer":[{{{key}:0,{key}:1}}]}}"#),
        // A second name repeated next to it, so the escape path is not the
        // only way a duplicate can be hidden.
        format!(r#"{{"outer":[{{{key}:0,{prefixed}:1,{prefixed}:2}}]}}"#),
        // One name spelled plain and once with a JSON escape.
        r#"{"outer":[{"key":0,"k\u0065y":1}]}"#.to_owned(),
        // A duplicate nested under an array element.
        r#"{"a":[{"b":1,"b":2}],"c":null}"#.to_owned(),
    ] {
        assert_eq!(
            canonical::parse(duplicate.as_bytes()),
            Err(JsonError::DuplicateKey),
            "duplicate member name must always be rejected"
        );
        assert_eq!(
            wire::from_slice::<Value>(duplicate.as_bytes()),
            Err(JsonError::DuplicateKey)
        );
    }

    let parsed = canonical::parse(input);
    outcome.record("canonical.parse", Decision::of(parsed.as_ref().map(|_| ())));
    let digest = Sha256Digest::of(input);
    outcome.record(
        "canonical.store",
        Decision::of(canonical::from_canonical_slice::<Value>(input).map(|_| ())),
    );
    outcome.record(
        "canonical.digest",
        Decision::of(canonical::from_digest::<Value>(input, &digest).map(|_| ())),
    );
    outcome.record(
        "wire.shape",
        Decision::of(wire::from_slice::<Value>(input).map(|_| ())),
    );

    let Ok(value) = parsed else {
        return outcome;
    };

    // An accepted document round-trips through canonical bytes exactly.
    let bytes = canonical::to_vec(&value).unwrap();
    assert_eq!(canonical::parse(&bytes).unwrap(), value);
    assert_eq!(canonical::from_slice::<Value>(&bytes).unwrap(), value);
    assert_eq!(
        canonical::to_vec(&canonical::parse(&bytes).unwrap()).unwrap(),
        bytes
    );
    assert!(canonical::from_canonical_slice::<Value>(&bytes).is_ok());

    // Acceptance is canonical-form detection, not a second syntax: the input
    // bytes are accepted as stored JSON exactly when they are those bytes.
    assert_eq!(
        canonical::from_canonical_slice::<Value>(input).is_ok(),
        input == bytes
    );

    // A digest binds the exact bytes it was taken over and nothing else.
    assert_eq!(
        canonical::from_digest::<Value>(input, &digest).unwrap(),
        value
    );
    if input != bytes {
        assert_eq!(
            canonical::from_digest::<Value>(&bytes, &digest),
            Err(JsonError::DigestMismatch)
        );
    }
    outcome
}

pub fn wire_round_trip<T: CanonicalJson + DeserializeOwned>(input: &[u8]) -> Result<(), JsonError> {
    let value = wire::from_slice::<T>(input)?;
    let bytes = wire::to_vec(&value).unwrap();
    assert_eq!(
        wire::to_vec(&wire::from_slice::<T>(&bytes).unwrap()).unwrap(),
        bytes
    );
    Ok(())
}

// -- wire_contracts ---------------------------------------------------------

pub fn wire_contracts(input: &[u8]) -> Outcome {
    if input.len() > MAX_INPUT_BYTES {
        return Outcome::over_limit();
    }
    let mut outcome = Outcome::new();
    for (stage, result) in [
        ("wire.value", wire_round_trip::<Value>(input)),
        ("wire.accounting", wire_round_trip::<AccountingV1>(input)),
        ("wire.diagnostic", wire_round_trip::<DiagnosticV1>(input)),
        (
            "wire.publication-intent",
            wire_round_trip::<PublicationIntentV1>(input),
        ),
        ("wire.response", wire_round_trip::<ResponseV1>(input)),
        (
            "wire.verification",
            wire_round_trip::<VerificationV1>(input),
        ),
        (
            "wire.checkpoint",
            wire_round_trip::<wire::Checkpoint>(input),
        ),
    ] {
        outcome.record(stage, Decision::of(result));
    }

    // The persisted request and the wire envelope are one document: the same
    // bytes are accepted or rejected with the same typed error, and an accepted
    // request normalizes to the same bytes it came from.
    let request = RequestInputV1::read(input);
    let normalized = NormalizedInput::read(input);
    assert_eq!(request.as_ref().err(), normalized.as_ref().err());
    outcome.record(
        "wire.request-input",
        Decision::of(normalized.as_ref().map(|_| ())),
    );
    if let (Ok(request), Ok(normalized)) = (request, normalized) {
        let bytes = normalized.to_bytes().unwrap();
        assert_eq!(wire::to_vec(&request).unwrap(), bytes);
        let stored = NormalizedInput::read_canonical(&bytes).unwrap();
        assert_eq!(stored.to_bytes().unwrap(), bytes);
        assert_eq!(stored.digest().unwrap(), Sha256Digest::of(&bytes));
        assert_eq!(
            NormalizedInput::read_canonical(input).is_ok(),
            input == bytes
        );
    }
    outcome
}

// -- declarations -----------------------------------------------------------

pub fn declarations(input: &[u8]) -> Outcome {
    if input.len() > MAX_INPUT_BYTES {
        return Outcome::over_limit();
    }
    let mut outcome = Outcome::new();

    // `scourge.engagement.v1`, in both accepted serializations. Every rejection
    // names a schema-owned stanza (never a supplied key or value).
    for (stage, draft) in [
        ("engagement.json", EngagementDraft::parse_json(input)),
        ("engagement.toml", EngagementDraft::parse_toml(input)),
    ] {
        let validated = draft.and_then(|draft| draft.validate());
        if let Err(error) = &validated {
            assert_stanza(error.stanza());
        }
        outcome.record(stage, Decision::of(validated));
    }

    // `scourge.policy-rule.v1`.
    let rule = PolicyRule::parse_json(input);
    if let Err(error) = &rule {
        assert_stanza(error.stanza());
    }
    outcome.record("policy-rule", Decision::of(rule));

    // `scourge.claim-template.v1`: an accepted template re-reads to the same
    // value and keeps the same validity, and a rejection names a schema-owned
    // stanza or rule. The schema owns the extension rules: an unlisted member,
    // including an identifier-shaped one, is reported as `*`, never by name.
    match ClaimTemplate::parse_json(input) {
        Ok(template) => {
            outcome.record("claim-template", Decision::Accepted);
            let bytes = serde_json::to_vec(&template).unwrap();
            let reread = ClaimTemplate::parse_json(&bytes).unwrap();
            assert_eq!(reread, template);
            let rules = template.validate();
            if let Err(error) = &rules {
                let stanza = match error {
                    TemplateError::Declaration(error) => error.stanza(),
                    TemplateError::Template { stanza, .. } => stanza,
                };
                assert_stanza(stanza);
            }
            assert_eq!(reread.validate().is_ok(), rules.is_ok());
            outcome.record("claim-template.rules", Decision::of(rules));
        }
        Err(error) => {
            let stanza = match &error {
                TemplateError::Declaration(error) => error.stanza(),
                // A rule the schema cannot state still names its stanza.
                TemplateError::Template { stanza, .. } => stanza,
            };
            assert_stanza(stanza);
            outcome.record("claim-template", Decision::Rejected(error.to_string()));
            outcome.record("claim-template.rules", Decision::Skipped);
        }
    }

    // Canonical evidence documents: accepted bytes are returned unchanged, so a
    // stored artifact can never be re-encoded into different bytes.
    let digest = Sha256Digest::of(input);
    let manifest = ManifestRevision::from_canonical_bytes(input, &digest);
    match &manifest {
        Ok(manifest) => {
            assert_eq!(manifest.canonical_bytes(), input);
            assert_eq!(manifest.digest(), &digest);
        }
        Err(error) => assert_stanza(error.stanza()),
    }
    outcome.record("manifest", Decision::of(manifest.map(|_| ())));

    let experiment = FrozenExperiment::from_canonical_bytes(input, &digest);
    let frozen = match &experiment {
        Ok(experiment) => {
            let frozen = experiment.freeze();
            if let Ok((bytes, digest)) = &frozen {
                assert_eq!(
                    FrozenExperiment::from_canonical_bytes(bytes, digest).unwrap(),
                    *experiment
                );
            }
            Some(Decision::of(frozen.map(|_| ())))
        }
        Err(_) => None,
    };
    outcome.record("experiment", Decision::of(experiment.map(|_| ())));
    outcome.record("experiment.freeze", frozen.unwrap_or(Decision::Skipped));
    outcome
}

// -- teapot_output ----------------------------------------------------------

fn invocation_decision(error: &InvocationError) -> Decision {
    // Only the wire codes are schema-owned text; the native error body is
    // untrusted. Both are rendered by their own vocabulary, never by input.
    match error.diagnostic() {
        Some(diagnostic) => Decision::Rejected(format!("{:?}/{:?}", error.code(), diagnostic.code)),
        None => Decision::Rejected(format!("{:?}", error.code())),
    }
}

pub fn teapot_output(input: &[u8]) -> Outcome {
    if input.len() > MAX_INPUT_BYTES {
        return Outcome::over_limit();
    }
    let parsed = wire::from_slice::<Value>(input).ok();
    let mut outcome = Outcome::new();

    for output in NativeOutput::ALL {
        // A captured output is parsed by the one shape its command produces.
        // Malformed bytes are a typed contract error, never a pass; a missing
        // exit code (a signal) and any non-zero exit are failures too.
        let decision = match output.decode(ExecutableKind::Native, Some(0), input, b"") {
            Ok(reply) => {
                assert!(
                    output.accepts(reply.envelope()),
                    "{} accepted an envelope outside its contract",
                    output.name()
                );
                // A forwarded envelope decodes identically through a wrapper.
                let bytes = wire::to_vec(reply.envelope()).unwrap();
                let wrapper = output
                    .decode(ExecutableKind::Wrapper, Some(0), &bytes, b"")
                    .unwrap();
                assert_eq!(wrapper.envelope(), reply.envelope());
                // A non-zero or signal exit can never yield a pass.
                assert!(
                    output
                        .decode(ExecutableKind::Native, Some(1), input, b"")
                        .is_err()
                );
                assert!(
                    output
                        .decode(ExecutableKind::Native, None, input, b"")
                        .is_err()
                );
                // A wrapper-only diagnostic on stderr always masks the result.
                assert!(
                    output
                        .decode(ExecutableKind::Wrapper, Some(0), &bytes, DIAGNOSTIC_EVENT)
                        .is_err()
                );
                Decision::Accepted
            }
            Err(error) => {
                assert!(matches!(
                    &error,
                    InvocationError::DependencyUnavailable { .. }
                ));
                invocation_decision(&error)
            }
        };
        outcome.record(output.name(), decision);

        // Output on stderr alone is never a pass.
        assert!(matches!(
            output
                .decode(ExecutableKind::Wrapper, Some(0), b"", input)
                .unwrap_err(),
            InvocationError::DependencyUnavailable { .. }
        ));

        // The strict verifier preflight accepts a subset of what the adapter
        // accepts, and strict acceptance always decodes. A strict-only
        // envelope that failed to decode would be a masked parse failure.
        if let Some(value) = &parsed
            && output.accepts_strict(value)
        {
            assert!(output.accepts(value));
            let bytes = wire::to_vec(value).unwrap();
            assert!(
                output
                    .decode(ExecutableKind::Native, Some(0), &bytes, b"")
                    .is_ok(),
                "{} rejected an envelope its frozen contract accepts",
                output.name()
            );
        }
    }

    // The five live actions parse one more step: the schema-valid result object
    // is turned into the typed reply the adapter returns. A reply that is
    // schema-valid but contradictory, dry-run or for another job or step is a
    // typed contract error, never a pass.
    for (stage, shape, trusted) in action_cases() {
        let decision = match hostile::action_reply(shape, Some(0), input, b"", trusted) {
            Ok(_) => Decision::Accepted,
            Err(error) => {
                assert!(matches!(
                    &error,
                    InvocationError::DependencyUnavailable { .. }
                ));
                invocation_decision(&error)
            }
        };
        outcome.record(stage, decision);

        // A signal or a non-zero exit never yields a typed action reply.
        assert!(
            hostile::action_reply(shape, Some(1), input, b"", trusted).is_err(),
            "{stage} passed a non-zero exit"
        );
        assert!(
            hostile::action_reply(shape, None, input, b"", trusted).is_err(),
            "{stage} passed a signal exit"
        );
        // A reply from another action call is never this action's reply.
        let other = action_cases()
            .into_iter()
            .find(|(_, candidate, _)| *candidate != shape)
            .map(|(_, _, trusted)| trusted)
            .unwrap();
        assert!(
            hostile::action_reply(shape, Some(0), input, b"", other).is_err(),
            "{stage} accepted another action's trusted parameters"
        );
    }

    // Three passive replies also parse a typed body beyond the schema. A reply
    // that names another engine, an oversized page or an ambiguous ceiling is a
    // typed contract error, never a pass.
    let (project, engine) = fixture_engine();
    let decision = match hostile::version_contract(&project, &engine, Some(0), input, b"") {
        Ok(()) => Decision::Accepted,
        Err(error) => invocation_decision(&error),
    };
    outcome.record("version.identity", decision);
    for (stage, result) in [
        (
            "jobs.page",
            hostile::jobs_page(1, None, Some(0), input, b"").map(|_| ()),
        ),
        (
            "pass.ceiling",
            hostile::request_units_left(Some(0), input, b"").map(|_| ()),
        ),
    ] {
        let decision = match result {
            Ok(()) => Decision::Accepted,
            Err(error) => invocation_decision(&error),
        };
        outcome.record(stage, decision);
    }
    // A non-zero exit never yields a typed reply here either.
    assert!(
        hostile::version_contract(&project, &engine, Some(1), input, b"").is_err()
            && hostile::jobs_page(1, None, Some(1), input, b"").is_err()
            && hostile::request_units_left(Some(1), input, b"").is_err()
    );
    outcome
}

// -- oracle_observations ----------------------------------------------------

pub fn oracle_observations(input: &[u8]) -> Outcome {
    if input.len() > MAX_INPUT_BYTES {
        return Outcome::over_limit();
    }
    let mut outcome = Outcome::new();
    let record = canonical::from_slice::<SavedObservations>(input);
    outcome.record("oracle.record", Decision::of(record.as_ref().map(|_| ())));
    let Ok(observations) = record else {
        outcome.record("oracle.verdict", Decision::Skipped);
        return outcome;
    };

    // An accepted record round-trips, so the verifier can retain what it read.
    let bytes = serde_json::to_vec(&observations).unwrap();
    assert_eq!(
        canonical::from_slice::<SavedObservations>(&bytes).unwrap(),
        observations
    );

    let evaluation = evaluate(&observations);
    assert_evaluation(&evaluation);
    outcome.record(
        "oracle.verdict",
        Decision::Classified(evaluation.result.as_str()),
    );
    outcome
}

/// The frozen result rules of `web.private-object-read.v1`.
///
/// `evaluate` is the pure predicate over saved observations, so these hold for
/// arbitrary records: a verdict is never derived from incomplete evidence, and
/// any undecodable body is a typed `EVIDENCE_INCOMPLETE`, never `false`.
pub fn assert_evaluation_invariants(observations: &SavedObservations) {
    assert_evaluation(&evaluate(observations));
}

fn assert_evaluation(evaluation: &Evaluation) {
    // `evaluate` converts a panic into `error`; on untrusted input that is a
    // defect, so the harness treats it as a failure rather than a verdict.
    assert!(
        !matches!(evaluation.fault, Some(FaultCause::OraclePanic)),
        "oracle panicked on saved observations"
    );

    match evaluation.result {
        Verdict::Error => assert!(
            evaluation.fault.is_some(),
            "error result must carry a fault cause"
        ),
        Verdict::True => {
            assert!(evaluation.fault.is_none());
            assert!(evaluation.exposure.is_some());
            assert!(!evaluation.fields_crossed.is_empty());
            assert!(evaluation.reason_codes.is_empty());
            assert!(evaluation.evidence.is_empty());
            assert!(evaluation.after_owner_read.is_some());
        }
        Verdict::False => {
            assert!(evaluation.fault.is_none());
            assert!(evaluation.exposure.is_none());
            assert!(evaluation.fields_crossed.is_empty());
            assert!(evaluation.reason_codes.is_empty());
            assert!(evaluation.evidence.is_empty());
        }
        Verdict::Invalid => {
            assert!(evaluation.fault.is_none());
            assert!(evaluation.exposure.is_none());
            assert!(evaluation.after_owner_read.is_none());
            assert!(evaluation.fields_crossed.is_empty());
            assert!(!evaluation.reason_codes.is_empty());
            // §6.5: an undecodable, truncated or over-limit body is
            // `EVIDENCE_INCOMPLETE`, whatever else the record says.
            let undecodable = evaluation
                .evidence
                .iter()
                .any(|cause| matches!(cause, IncompleteCause::Decode { .. }));
            if undecodable {
                assert!(
                    evaluation
                        .reason_codes
                        .iter()
                        .any(|code| code.as_str() == "EVIDENCE_INCOMPLETE"),
                    "a failed body decode must be EVIDENCE_INCOMPLETE"
                );
            }
        }
    }
}

// -- body_decoder -----------------------------------------------------------

/// A modest bound exercises size and expansion errors without allocating
/// close to the production ceiling on each fuzz iteration.
pub const BODY_LIMITS: DecodeLimits = DecodeLimits::new(4096, 16);

pub fn body_decoder(input: &[u8]) -> Outcome {
    if input.len() > MAX_INPUT_BYTES {
        return Outcome::over_limit();
    }
    let mut outcome = Outcome::new();
    for &(stage, transfer, content, json_string_body) in BODY_MATRIX {
        let decoding = Decoding {
            transfer,
            content,
            json_string_body,
        };
        let decoded = scourge_verify::decode(input, decoding, BODY_LIMITS);
        if let Ok(body) = &decoded {
            // Bounded: the accepted bytes obey the clamped limits.
            assert_eq!(body.coded_bytes, input.len() as u64);
            assert_eq!(body.decoded_bytes, body.bytes.len() as u64);
            assert!(body.decoded_bytes <= BODY_LIMITS.max_decoded_bytes);
            assert!(body.decoded_bytes <= body.coded_bytes * BODY_LIMITS.max_expansion_ratio);
            assert_eq!(body.decoder, decoding.decoder_name());
            if decoding == Decoding::default() {
                assert_eq!(body.bytes, input);
            }
        }
        outcome.record(stage, Decision::of(decoded.map(|_| ())));
    }
    outcome
}
