# Parser fuzzing

Coverage-guided fuzzing for every Scourge parser that reads bytes the system
does not control. This is an offline, in-memory harness: no target traffic, no
evidence store, no credentials, no network, no file writes.

```sh
just parser-corpus-check            # fast, deterministic: replay + witnesses
just fuzz-parsers <target> [secs]   # optional coverage-guided run
```

## Targets

| Target | Parses | Invariants asserted |
| --- | --- | --- |
| `canonical_json` | canonical JSON evidence (`canonical::parse`, `from_digest`) | never panics; a duplicate member name is always rejected, including a `\uXXXX` spelling (INV-44); an accepted value re-serializes to the same canonical bytes, and stored bytes are accepted only when they are already canonical |
| `wire_contracts` | machine envelopes: request input, verification record, publication intent, accounting, diagnostic, checkpoint, response | never panics; every accepted envelope re-reads to identical bytes; the stored request and the wire request are one document and fail with the same typed error |
| `declarations` | `scourge.engagement.v1` (JSON and TOML), `scourge.policy-rule.v1`, `scourge.claim-template.v1`, manifest revisions, frozen experiments | never panics; every rejection names a schema-owned stanza and never echoes supplied text; a stored manifest or experiment is returned byte-identical |
| `teapot_output` | the 18 frozen `scourge.teapot-argv.v1` output shapes, including the five live actions (`requests send`, `macros run`, `flows replay`, `flows show`, `jobs stop`), their trailing typed-reply parsers and the three passive replies (`version.identity`, `jobs.page`, `pass.ceiling`) | never panics; malformed bytes are a typed contract error and never a pass; a non-zero or signal exit never passes; a wrapper-only diagnostic on stderr always masks the result; a forwarded envelope decodes identically; strict acceptance is a subset of adapter acceptance and always decodes; a schema-valid but contradictory action reply (a dry run, another job's stop, a hop list past the follow bound, a body window that disagrees with its bytes) never becomes a typed reply |
| `oracle_observations` | `scourge.oracle-observations.v1` records | never panics; a verdict is never derived from incomplete evidence; an undecodable, truncated or over-limit body is a typed `EvidenceIncomplete` cause and `EVIDENCE_INCOMPLETE`, never `false`; a panic inside the oracle is a harness failure, not an `error` verdict |
| `body_decoder` | transfer, content and JSON-string codings under `DecodeLimits` | never panics; accepted bytes are within the size and expansion-ratio bounds; chunk framing, gzip members and deflate streams must end exactly at the end of the body; every refusal is a typed `DecodeError` |

`fuzz/src/lib.rs` holds the shared entries. Each entry returns an `Outcome`: the
ordered trace of the production calls it made and the typed decision each one
took (`Accepted`, `Rejected(error)`, `Classified(verdict)` or `Skipped`).

## Entry contract

`fuzz/src/lib.rs` registers every entry in `ENTRIES`, and `stages(target)`
states the stages each entry must visit for any input inside the cap
(26 stages for `teapot_output`: 18 output shapes, five typed action replies
and three passive reply checks). The three layers that keep an entry honest are:

- `fuzz/fuzz_targets/<target>.rs` calls `scourge_parser_fuzz::<target>(input)`;
  `fuzz/tests/targets.rs` reads those files, so an empty `fuzz_target!` or one
  wired to another target fails the fast suite;
- `fuzz/tests/corpus_replay.rs` replays every seed through the *same* function
  and asserts the exact stage trace and the typed decision per parser, so an
  entry that returns before touching a parser cannot pass;
- `fuzz/tests/witnesses.rs` runs that replay with a stand-in that returns
  immediately, and with another target's entry, and requires both to fail.

The stanza predicate is likewise not a second copy: `scourge_core::
is_schema_stanza` validates the frozen field grammar and roots the producer in
`crates/scourge-core/src/declaration.rs` uses, so an identifier-shaped leak such
as a supplied `template_extension` key is rejected as non-schema text rather
than accepted by its shape.

The five live Teapot actions parse one step beyond the schema: `requests send`,
`macros run`, `flows replay`, `flows show` and `jobs stop` turn the validated
result object into a typed reply. That step is fuzzed through
`scourge_core::teapot::hostile`, the crate's own decoders compiled only for the
`hostile-input` feature the fuzz crate enables. The operator parameters a live
call takes from run state (session name, follow bound, macro name and step, job
ID, body window) are supplied by `fuzz/src/lib.rs::action_cases` from the values
each captured seed was recorded with, so only the bytes Teapot printed vary.
Nothing in that module spawns a process, touches the network or changes state.

`fuzz/tests/witnesses.rs` also holds the non-vacuity witnesses: cases that would
fail if a target silently accepted everything or ran the wrong parser (for
example, one Teapot shape parsing another shape's capture).

## Corpus

`fuzz/corpus/<target>/` holds frozen seeds. They come from
`fixtures/contracts/` (captured Teapot output and wire fixtures) and the
development fixture engagement, plus one deliberate boundary or negative case
per parser: truncated, bad UTF-8, duplicate member, depth limit, oversized body,
expansion ratio, missing stanza, wrong-lane document.

The action-reply seeds are derived from the checked-in captures and record their
provenance:

| Seed | Derived from |
| --- | --- |
| `teapot_output/send.json` | `fixtures/contracts/send.json` (a live `requests send`, session `alice`, flow 3) |
| `teapot_output/macro-run.json` | `fixtures/contracts/macro-send.json` (a live `macros run plant`, session `alice`) |
| `teapot_output/macro-replay.json` | the two captured `macro-run` steps, arranged as the checked-in `replay_output` test arranges them: flow 5, step 2 of 2, `parent` 0 |
| `teapot_output/flows-show.json` | `fixtures/contracts/read-flow.json` (flow 3, body window 0..32 KiB) |
| `teapot_output/jobs-stop.json` | the checked-in stop-reply fixture in `crates/scourge-core/tests/teapot_invocation.rs` (`jobs stop 41`, job `ending` with `stopped_now`) |
| `teapot_output/jobs-stop-empty.json` | `fixtures/contracts/cancel.json` (`--all` with no running job: schema-valid, but no acknowledgment) |

Those bytes are the point, so `.gitattributes` marks the deliberately invalid
UTF-8 seeds and the raw coded bodies as binary and keeps every corpus entry out
of line-ending normalization. Without it, `git diff` prints invalid UTF-8 into a
review diff and `seal diff` refuses the range.

Rules for adding seeds:

- every seed is at most 16 KiB (`MAX_INPUT_BYTES`), checked by the replay test;
- a crash artifact is minimized (`cargo +nightly-2026-08-21 fuzz tmin …`) and
  added here before the run is recorded as clean;
- an accepted seed and a rejected seed per target stay in the corpus, so a
  regression that stops accepting (or stops rejecting) is visible.

## Running libFuzzer

The harness needs a nightly toolchain; this repository pins
`nightly-2026-08-21` for fuzzing and `cargo-fuzz 0.13.1` for the driver, and
keeps the stable toolchain for build and test. The driver builds the instrument
and owns the libFuzzer flags, so `just fuzz-parsers` runs
`scripts/check-fuzz-toolchain.py` first and refuses any other `cargo-fuzz`
before it compiles or launches a target. Dependencies come from the workspace
lockfile, so a run needs no network:

```sh
just fuzz-parsers teapot_output 60
```

The recipe copies the checked-in corpus into a scratch directory, prints the
target, revision, seed count and toolchain, and passes
`-max_len=16384 -timeout=5 -rss_limit_mb=1024`. New units and crash artifacts
stay in the scratch directory; the checked-in corpus is never modified. Add a
crash artifact to `fuzz/corpus/<target>/` by hand, with a name that says what it
is.

## Recorded runs

A run is a bounded sample, not a proof. It cannot show that a parser is free of
panics or that a check holds for every input; it only shows that no counterexample
was found in that time, with that corpus, at that revision.

The record of each bounded session — date, exact revision, toolchain, duration,
corpus size, crash count and scope limits — lives in
[`docs/fuzzing.md`](../docs/fuzzing.md).
