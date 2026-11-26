//! Deterministic replay of every checked-in corpus entry.
//!
//! The first half replays each corpus through the same six shared entries the
//! libFuzzer binaries call, and pins the typed decision each production parser
//! took. A replay that observed nothing, visited the wrong stages or called
//! another target's parsers fails here, so an entry cannot become a no-op while
//! the suite stays green.
//!
//! The second half keeps the direct production checks the trace does not
//! express (a wrong digest, a stored-form reread, oracle evidence causes and
//! decoded payloads), as a separate layer over the same parsers.

use scourge_core::{
    DeclarationIssue,
    canonical::{self, JsonError, Sha256Digest},
    request::NormalizedInput,
    teapot::{ExecutableKind, NativeOutput},
    wire::{self, DiagnosticCode},
};
use scourge_parser_fuzz::{BODY_LIMITS, Decision, Outcome};
use scourge_verify::{
    ContentCoding, DecodeError, Decoding, IncompleteCause, SavedObservations, TransferCoding,
    Verdict, evaluate,
};
use serde_json::Value;

// One shared replay module, compiled into both test binaries; each binary
// uses a different part of it.
#[allow(dead_code)]
mod support;

fn replay(target: &str) {
    let entry = support::entry(target).expect("every target has a shared entry");
    let observed = support::replay(target, entry).unwrap_or_else(|error| panic!("{error}"));
    let accepted = observed
        .iter()
        .filter(|(_, outcome)| outcome.accepted())
        .count();
    let rejected = observed
        .iter()
        .filter(|(_, outcome)| outcome.rejected())
        .count();
    // Judged by the entry's own trace, so a silently no-op entry shows up as an
    // empty side instead of a vacuous pass.
    assert!(accepted > 0, "{target} has no accepted seed");
    assert!(rejected > 0, "{target} has no rejected seed");
}

macro_rules! replay_targets {
    ($($target:ident),+ $(,)?) => {
        $(
            #[test]
            fn $target() {
                replay(stringify!($target));
            }
        )+
    };
}

replay_targets!(
    canonical_json,
    wire_contracts,
    declarations,
    teapot_output,
    oracle_observations,
    body_decoder,
);

#[test]
fn the_entry_table_matches_the_replayed_targets() {
    let mut targets = scourge_parser_fuzz::ENTRIES
        .iter()
        .map(|(target, _)| *target)
        .collect::<Vec<_>>();
    targets.sort_unstable();
    assert_eq!(
        targets,
        [
            "body_decoder",
            "canonical_json",
            "declarations",
            "oracle_observations",
            "teapot_output",
            "wire_contracts",
        ]
    );
    for target in targets {
        assert!(
            scourge_parser_fuzz::stages(target).is_some(),
            "{target} has no entry contract"
        );
        assert!(!support::seeds(target).is_empty(), "{target} has no corpus");
    }
}

/// Assert one recorded decision per (seed, stage).
fn assert_decisions(target: &str, cases: &[(&str, &str, Decision)]) {
    for (name, stage, expected) in cases {
        let outcome = support::outcome(target, name);
        assert_eq!(
            support::decision(&outcome, stage),
            expected,
            "{target}/{name} at {stage}"
        );
    }
}

/// A declaration rejection, as its stanza and schema-owned issue render it.
fn declaration(stanza: &str, issue: DeclarationIssue) -> Decision {
    Decision::Rejected(format!("{stanza}: {issue}"))
}

// -- Entry-layer outcomes ---------------------------------------------------

#[test]
fn canonical_seed_outcomes() {
    let accepted = |outcome: &Outcome| {
        ["canonical.parse", "canonical.store", "wire.shape"]
            .iter()
            .all(|stage| support::decision(outcome, stage) == &Decision::Accepted)
    };
    for name in [
        "canonical.json",
        "safe-max.json",
        "byte-limit.json",
        "float-roundtrip.json",
    ] {
        let outcome = support::outcome("canonical_json", name);
        assert!(accepted(&outcome), "{name}");
        assert_eq!(
            support::decision(&outcome, "canonical.digest"),
            &Decision::Accepted,
            "{name}"
        );
    }
    assert_decisions(
        "canonical_json",
        &[
            ("unordered.json", "canonical.parse", Decision::Accepted),
            (
                "unordered.json",
                "canonical.store",
                support::rejected(JsonError::NonCanonical),
            ),
            (
                "duplicate-escaped.json",
                "canonical.parse",
                support::rejected(JsonError::DuplicateKey),
            ),
            (
                "duplicate-escaped.json",
                "wire.shape",
                support::rejected(JsonError::DuplicateKey),
            ),
            (
                "unsafe-plus-one.json",
                "canonical.parse",
                support::rejected(JsonError::UnsafeNumber),
            ),
            (
                "unsafe-minus-one.json",
                "canonical.parse",
                support::rejected(JsonError::UnsafeNumber),
            ),
            (
                "unsafe-exponent.json",
                "canonical.parse",
                support::rejected(JsonError::UnsafeNumber),
            ),
            (
                "depth-limit.json",
                "canonical.parse",
                support::rejected(JsonError::Malformed),
            ),
            (
                "bad-utf8.json",
                "canonical.parse",
                support::rejected(JsonError::Malformed),
            ),
            (
                "truncated.json",
                "canonical.parse",
                support::rejected(JsonError::Malformed),
            ),
            (
                "trailing.json",
                "canonical.parse",
                support::rejected(JsonError::Malformed),
            ),
            (
                "unpaired-surrogate.json",
                "canonical.parse",
                support::rejected(JsonError::Malformed),
            ),
            // A machine envelope keeps full-width integers, while stored
            // evidence bounds them: the two readers differ on purpose.
            ("unsafe-minus-one.json", "wire.shape", Decision::Accepted),
        ],
    );
}

#[test]
fn wire_seed_outcomes() {
    assert_decisions(
        "wire_contracts",
        &[
            ("accounting.json", "wire.accounting", Decision::Accepted),
            ("checkpoint.json", "wire.checkpoint", Decision::Accepted),
            (
                "publication-intent.json",
                "wire.publication-intent",
                Decision::Accepted,
            ),
            ("stderr-event.json", "wire.diagnostic", Decision::Accepted),
            (
                "verification-record.json",
                "wire.verification",
                Decision::Accepted,
            ),
            ("response-0.json", "wire.response", Decision::Accepted),
            ("response-1.json", "wire.response", Decision::Accepted),
            ("response-2.json", "wire.response", Decision::Accepted),
            ("response-3.json", "wire.response", Decision::Accepted),
            ("response-4.json", "wire.response", Decision::Accepted),
            ("response-5.json", "wire.response", Decision::Accepted),
            ("response-6.json", "wire.response", Decision::Accepted),
            // A wide counter stays exact; a stored request is still a request.
            ("wide-counter.json", "wire.verification", Decision::Accepted),
            (
                "request-input.json",
                "wire.request-input",
                Decision::Accepted,
            ),
            (
                "request-retest.json",
                "wire.request-input",
                Decision::Accepted,
            ),
            (
                "request-zero-rounds.json",
                "wire.request-input",
                support::rejected(JsonError::InvalidShape),
            ),
            (
                "request-overflow.json",
                "wire.request-input",
                support::rejected(JsonError::UnsafeNumber),
            ),
            (
                "duplicate-escaped.json",
                "wire.value",
                support::rejected(JsonError::DuplicateKey),
            ),
            (
                "bad-utf8.json",
                "wire.value",
                support::rejected(JsonError::Malformed),
            ),
            (
                "depth-limit.json",
                "wire.value",
                support::rejected(JsonError::Malformed),
            ),
            (
                "truncated.json",
                "wire.response",
                support::rejected(JsonError::Malformed),
            ),
        ],
    );
}

#[test]
fn declaration_seed_outcomes() {
    assert_decisions(
        "declarations",
        &[
            ("engagement.json", "engagement.json", Decision::Accepted),
            ("engagement.toml", "engagement.toml", Decision::Accepted),
            ("policy-rule-orders.json", "policy-rule", Decision::Accepted),
            (
                "claim-template-private-object-read.json",
                "claim-template",
                Decision::Accepted,
            ),
            (
                "claim-template-private-object-read.json",
                "claim-template.rules",
                Decision::Accepted,
            ),
            ("manifest.json", "manifest", Decision::Accepted),
            ("experiment.json", "experiment", Decision::Accepted),
            ("experiment.json", "experiment.freeze", Decision::Accepted),
            (
                "engagement-duplicate.json",
                "engagement.json",
                declaration("engagement.pass", DeclarationIssue::DuplicateKey),
            ),
            (
                "engagement-duplicate.toml",
                "engagement.toml",
                declaration("engagement.objective", DeclarationIssue::DuplicateKey),
            ),
            (
                "engagement-unknown-field.json",
                "engagement.json",
                declaration("engagement.*", DeclarationIssue::InvalidShape),
            ),
            (
                "policy-rule-unknown-field.json",
                "policy-rule",
                declaration("*", DeclarationIssue::InvalidShape),
            ),
            (
                "policy-rule-missing-audience.json",
                "policy-rule",
                declaration("readers/writers", DeclarationIssue::MissingAudience),
            ),
            (
                "manifest-missing-parent.json",
                "manifest",
                declaration("manifest.revision", DeclarationIssue::RevisionLineage),
            ),
            (
                "duplicate-escaped.json",
                "claim-template",
                declaration("*[0].*", DeclarationIssue::DuplicateKey),
            ),
            (
                "bad-utf8.json",
                "engagement.toml",
                declaration("engagement", DeclarationIssue::Malformed),
            ),
            (
                "toml-depth-limit.toml",
                "engagement.toml",
                declaration("engagement", DeclarationIssue::Malformed),
            ),
            (
                "truncated.json",
                "experiment",
                support::rejected(JsonError::Malformed),
            ),
            // A path that starts inside an array has no field name, only a
            // position: `[0]` is schema-owned and the rejection still names it.
            (
                "array-root-unsafe-number.json",
                "engagement.json",
                declaration("[0]", DeclarationIssue::UnsafeNumber),
            ),
            (
                "array-root-unsafe-number.json",
                "claim-template",
                declaration("[0]", DeclarationIssue::UnsafeNumber),
            ),
            (
                "array-root-unsafe-number.json",
                "engagement.toml",
                declaration("*", DeclarationIssue::InvalidShape),
            ),
        ],
    );
}

/// The distinct rejection text every stage of a trace recorded.
fn sole_rejection(outcome: &Outcome) -> Option<&str> {
    assert!(!outcome.accepted(), "a malformed capture must not pass");
    let mut errors = outcome.decisions().iter().filter_map(|(_, decision)| {
        if let Decision::Rejected(error) = decision {
            Some(error.as_str())
        } else {
            None
        }
    });
    let first = errors.next()?;
    errors.all(|error| error == first).then_some(first)
}

#[test]
fn teapot_seed_outcomes() {
    const INVALID: &str = "DependencyUnavailable/InvalidNativeOutput";
    let cases = [
        ("describe.json", NativeOutput::Version),
        ("describe-status.json", NativeOutput::ProxyStatus),
        ("check-session.json", NativeOutput::SessionCheck),
        ("dry-run.json", NativeOutput::MacroDryRun),
        ("send.json", NativeOutput::SendDryRun),
        ("units-left.json", NativeOutput::PassShow),
        ("list-jobs.json", NativeOutput::JobsList),
        ("rules-list.json", NativeOutput::RulesList),
        ("intercept-rules.json", NativeOutput::InterceptRules),
        ("intercept-status.json", NativeOutput::InterceptStatus),
        ("scripts-list.json", NativeOutput::ScriptsList),
        ("session-show.json", NativeOutput::SessionShow),
        ("config-list.json", NativeOutput::ConfigList),
        ("requests-lookup.json", NativeOutput::RequestsLookup),
        ("send.json", NativeOutput::Send),
        ("macro-run.json", NativeOutput::MacroRun),
        ("macro-replay.json", NativeOutput::MacroReplay),
        ("flows-show.json", NativeOutput::ReadFlow),
        ("jobs-stop.json", NativeOutput::JobStop),
    ];
    // Every argv output this build parses has a captured seed, so a live action
    // reply surface cannot be silently left out of the corpus.
    for shape in NativeOutput::ALL {
        assert!(
            cases.iter().any(|(_, candidate)| *candidate == shape),
            "{} has no captured reply in the corpus",
            shape.name()
        );
    }
    for (name, output) in cases {
        let outcome = support::outcome("teapot_output", name);
        assert_eq!(
            support::decision(&outcome, output.name()),
            &Decision::Accepted,
            "{name} is {}",
            output.name()
        );
    }
    for name in [
        "bad-utf8.json",
        "depth-limit.json",
        "duplicate-escaped.json",
        "invalid-schema.json",
        "truncated.json",
        "wrapper-diagnostic.json",
    ] {
        let outcome = support::outcome("teapot_output", name);
        assert_eq!(sole_rejection(&outcome), Some(INVALID), "{name}");
    }
    let native_error = support::outcome("teapot_output", "native-error.json");
    assert_eq!(
        sole_rejection(&native_error),
        Some("DependencyUnavailable/WrongListener")
    );
}

#[test]
fn teapot_action_seed_outcomes() {
    const INVALID: &str = "DependencyUnavailable/InvalidNativeOutput";
    // The five live actions take one more step than a schema check: the typed
    // reply the adapter returns. Each captured reply parses through its own
    // trusted parameters and refuses every other action's.
    for (stage, seed) in [
        ("shape.send", "send.json"),
        ("shape.macro_run", "macro-run.json"),
        ("shape.macro_replay", "macro-replay.json"),
        ("shape.read_flow", "flows-show.json"),
        ("shape.job_stop", "jobs-stop.json"),
    ] {
        let outcome = support::outcome("teapot_output", seed);
        assert_eq!(
            support::decision(&outcome, stage),
            &Decision::Accepted,
            "{seed} at {stage}"
        );
        for (other, other_seed) in [
            ("shape.send", "send.json"),
            ("shape.macro_run", "macro-run.json"),
            ("shape.macro_replay", "macro-replay.json"),
            ("shape.read_flow", "flows-show.json"),
            ("shape.job_stop", "jobs-stop.json"),
        ] {
            if other == stage || other_seed == seed {
                continue;
            }
            let outcome = support::outcome("teapot_output", other_seed);
            assert_eq!(
                support::decision(&outcome, stage),
                &Decision::Rejected(INVALID.to_owned()),
                "{other_seed} must not satisfy {stage}"
            );
        }
    }
    // A schema-valid reply for the same command is still refused when the
    // typed reply is not a live action's: a macro dry run, and a stop that
    // acknowledged no job at all.
    for (stage, seed) in [
        ("shape.macro_run", "dry-run.json"),
        ("shape.job_stop", "jobs-stop-empty.json"),
    ] {
        let outcome = support::outcome("teapot_output", seed);
        assert_eq!(
            support::decision(&outcome, stage),
            &Decision::Rejected(INVALID.to_owned()),
            "{seed} at {stage}"
        );
    }
}

#[test]
fn observation_seed_outcomes() {
    assert_decisions(
        "oracle_observations",
        &[
            (
                "false-no-exposure.json",
                "oracle.record",
                Decision::Accepted,
            ),
            (
                "false-no-exposure.json",
                "oracle.verdict",
                Decision::Classified(Verdict::False.as_str()),
            ),
            (
                "invalid-missing-flow.json",
                "oracle.verdict",
                Decision::Classified(Verdict::Invalid.as_str()),
            ),
            (
                "invalid-same-subject.json",
                "oracle.verdict",
                Decision::Classified(Verdict::Invalid.as_str()),
            ),
            (
                "over-size-limit.json",
                "oracle.verdict",
                Decision::Classified(Verdict::Invalid.as_str()),
            ),
            (
                "over-expansion-ratio.json",
                "oracle.verdict",
                Decision::Classified(Verdict::Invalid.as_str()),
            ),
            (
                "partial-f1-f0-field-exposure.json",
                "oracle.verdict",
                Decision::Classified(Verdict::True.as_str()),
            ),
            (
                "true-unauthenticated-after-owner-read.json",
                "oracle.verdict",
                Decision::Classified(Verdict::True.as_str()),
            ),
            (
                "duplicate-escaped.json",
                "oracle.record",
                support::rejected(JsonError::DuplicateKey),
            ),
            (
                "non-hex-body.json",
                "oracle.record",
                support::rejected(JsonError::InvalidShape),
            ),
            (
                "bad-utf8.json",
                "oracle.record",
                support::rejected(JsonError::Malformed),
            ),
            (
                "depth-limit.json",
                "oracle.record",
                support::rejected(JsonError::Malformed),
            ),
            (
                "truncated.json",
                "oracle.record",
                support::rejected(JsonError::Malformed),
            ),
        ],
    );
}

#[test]
fn body_seed_outcomes() {
    assert_decisions(
        "body_decoder",
        &[
            (
                "identity.bin",
                "body.identity.identity.raw",
                Decision::Accepted,
            ),
            (
                "chunked.bin",
                "body.chunked.identity.raw",
                Decision::Accepted,
            ),
            ("gzip.bin", "body.identity.gzip.raw", Decision::Accepted),
            (
                "gzip-chunked.bin",
                "body.chunked.gzip.raw",
                Decision::Accepted,
            ),
            (
                "deflate-zlib.bin",
                "body.identity.deflate.raw",
                Decision::Accepted,
            ),
            (
                "deflate-raw.bin",
                "body.identity.deflate.raw",
                Decision::Accepted,
            ),
            (
                "size-limit.bin",
                "body.identity.identity.raw",
                Decision::Accepted,
            ),
            (
                "string.bin",
                "body.identity.identity.string",
                Decision::Accepted,
            ),
            (
                "size-plus-one.bin",
                "body.identity.identity.raw",
                support::rejected(DecodeError::OverLimit),
            ),
            (
                "gzip-ratio.bin",
                "body.identity.gzip.raw",
                support::rejected(DecodeError::ExpansionRatio),
            ),
            (
                "gzip-truncated.bin",
                "body.identity.gzip.raw",
                support::rejected(DecodeError::Truncated),
            ),
            (
                "chunked-truncated.bin",
                "body.chunked.identity.raw",
                support::rejected(DecodeError::Truncated),
            ),
            (
                "chunked-overflow.bin",
                "body.chunked.identity.raw",
                support::rejected(DecodeError::Corrupt),
            ),
            (
                "invalid-surrogate.bin",
                "body.identity.identity.string",
                support::rejected(DecodeError::Corrupt),
            ),
            (
                "invalid-utf8.bin",
                "body.identity.identity.string",
                support::rejected(DecodeError::Corrupt),
            ),
        ],
    );
}

// -- Direct production layer ------------------------------------------------

#[test]
fn wrapper_diagnostic_event_is_a_registered_shape() {
    let event: wire::DiagnosticV1 =
        wire::from_slice(scourge_parser_fuzz::DIAGNOSTIC_EVENT).unwrap();
    assert_eq!(event.diagnostic.code, DiagnosticCode::ToolUnavailable);
    let error = NativeOutput::Version
        .decode(
            ExecutableKind::Wrapper,
            Some(0),
            &support::seed("teapot_output", "describe.json"),
            scourge_parser_fuzz::DIAGNOSTIC_EVENT,
        )
        .unwrap_err();
    assert_eq!(
        error.diagnostic().unwrap().code,
        DiagnosticCode::ToolUnavailable
    );
}

#[test]
fn a_digest_binds_only_the_bytes_it_covers() {
    // Not expressed by the entry trace, which always digests the input it read.
    assert_eq!(
        canonical::from_digest::<Value>(
            &support::seed("canonical_json", "canonical.json"),
            &Sha256Digest::of(b"unrelated"),
        ),
        Err(JsonError::DigestMismatch)
    );
}

#[test]
fn a_stored_request_must_already_be_canonical() {
    // The entry reads a request as machine input; the stored-form reader is
    // stricter, and this is the only place the difference is pinned.
    let request =
        NormalizedInput::read(&support::seed("wire_contracts", "request-input.json")).unwrap();
    assert!(NormalizedInput::read_canonical(&request.to_bytes().unwrap()).is_ok());
    assert_eq!(
        NormalizedInput::read_canonical(&support::seed("wire_contracts", "request-input.json"))
            .unwrap_err(),
        JsonError::NonCanonical
    );
}

#[test]
fn oracle_body_bound_seed_outcomes() {
    for (name, expected) in [
        ("over-size-limit.json", DecodeError::OverLimit),
        ("over-expansion-ratio.json", DecodeError::ExpansionRatio),
    ] {
        let observations: SavedObservations =
            canonical::from_slice(&support::seed("oracle_observations", name)).unwrap();
        let evaluation = evaluate(&observations);
        assert_eq!(evaluation.result, Verdict::Invalid, "{name}");
        assert_eq!(evaluation.reason_codes.len(), 1, "{name}");
        assert_eq!(
            evaluation.reason_codes[0].as_str(),
            "EVIDENCE_INCOMPLETE",
            "{name}"
        );
        assert_eq!(evaluation.evidence.len(), 1, "{name}");
        assert!(
            matches!(
                evaluation.evidence[0],
                IncompleteCause::Decode {
                    flow: scourge_verify::FlowId::F2,
                    error,
                } if error == expected
            ),
            "{name}: {:?}",
            evaluation.evidence
        );
    }
}

#[test]
fn decoded_body_payloads_are_equal_across_codings() {
    // The entry trace records whether a coding was accepted; this pins what the
    // accepted bytes actually are.
    let decode = |name: &str, transfer, content, json_string_body| {
        scourge_verify::decode(
            &support::seed("body_decoder", name),
            Decoding {
                transfer,
                content,
                json_string_body,
            },
            BODY_LIMITS,
        )
        .map(|decoded| decoded.bytes)
    };
    use ContentCoding::{Deflate, Gzip, Identity as Raw};
    use TransferCoding::{Chunked, Identity};
    let plain = support::seed("body_decoder", "identity.bin");
    for (name, transfer, content) in [
        ("identity.bin", Identity, Raw),
        ("gzip.bin", Identity, Gzip),
        ("gzip-chunked.bin", Chunked, Gzip),
        ("deflate-zlib.bin", Identity, Deflate),
        ("deflate-raw.bin", Identity, Deflate),
    ] {
        assert_eq!(
            decode(name, transfer, content, false).unwrap(),
            plain,
            "{name}"
        );
    }
    assert_eq!(decode("chunked.bin", Chunked, Raw, false).unwrap(), b"test");
    assert_eq!(
        decode("size-limit.bin", Identity, Raw, false)
            .unwrap()
            .len(),
        4096
    );
    assert_eq!(
        decode("string.bin", Identity, Raw, true).unwrap(),
        b"fixture string\n"
    );
    // A JSON-string wrapper accepts exactly one string and rejects trailing
    // bytes, so a wrapper cannot smuggle an undecoded canary past the match.
    let wrapper = Decoding {
        transfer: Identity,
        content: Raw,
        json_string_body: true,
    };
    assert_eq!(
        decode("invalid-surrogate.bin", Identity, Raw, true),
        Err(DecodeError::Corrupt)
    );
    assert_eq!(
        scourge_verify::decode(br#""ok" trailing"#, wrapper, BODY_LIMITS),
        Err(DecodeError::Corrupt)
    );
    assert_eq!(
        scourge_verify::decode(br#""ok""#, wrapper, BODY_LIMITS)
            .unwrap()
            .bytes,
        b"ok"
    );
}

// -- Reply-stage decisions (version.identity, jobs.page, pass.ceiling) -----

/// The three passive-reply stages of the 26-stage `teapot_output` trace, pinned
/// per seed: the captured describe reply passes the engine-identity check, the
/// captured jobs-list passes the bounded page read, and the captured pass show
/// passes the ceiling read; every other seed records a typed rejection at
/// every one of the three.
#[test]
fn teapot_reply_seed_outcomes() {
    let cases = [
        ("describe.json", true),
        ("list-jobs.json", true),
        ("units-left.json", true),
    ];
    let other_seeds = [
        "bad-utf8.json",
        "check-session.json",
        "config-list.json",
        "depth-limit.json",
        "describe-status.json",
        "dry-run.json",
        "duplicate-escaped.json",
        "flows-show.json",
        "intercept-rules.json",
        "intercept-status.json",
        "invalid-schema.json",
        "jobs-stop-empty.json",
        "jobs-stop.json",
        "macro-replay.json",
        "macro-run.json",
        "native-error.json",
        "rules-list.json",
        "scripts-list.json",
        "send.json",
        "session-show.json",
        "truncated.json",
        "wrapper-diagnostic.json",
    ];
    assert_eq!(cases.len() + other_seeds.len(), 25);
    for (name, _) in cases {
        let outcome = support::outcome("teapot_output", name);
        for (stage, accepted) in [
            ("version.identity", name == "describe.json"),
            ("jobs.page", name == "list-jobs.json"),
            ("pass.ceiling", name == "units-left.json"),
        ] {
            let decision = support::decision(&outcome, stage);
            if accepted {
                assert_eq!(decision, &Decision::Accepted, "{name} {stage}");
            } else {
                assert!(
                    matches!(decision, Decision::Rejected(_)),
                    "{name} {stage}: expected a typed rejection, got {decision:?}"
                );
            }
        }
    }
    for stage in ["version.identity", "jobs.page", "pass.ceiling"] {
        for name in other_seeds {
            let outcome = support::outcome("teapot_output", name);
            assert!(
                matches!(support::decision(&outcome, stage), Decision::Rejected(_)),
                "{name} {stage} must be a typed rejection"
            );
        }
    }
}
