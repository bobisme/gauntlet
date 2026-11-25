# Parser fuzzing record

Coverage-guided fuzzing of the parsers that read bytes Scourge does not control
(bone `bn-2ai`, M1.13). The harness, its invariants and its corpus conventions
are documented in [`fuzz/README.md`](../fuzz/README.md); this page records what
was actually run.

## What the fast suite proves

`just parser-corpus-check` (also part of `just test`) runs three deterministic
test binaries on the stable toolchain, with no libFuzzer and no network:

- `fuzz/tests/corpus_replay.rs` replays every checked-in corpus entry through
  the *same* shared entry the libFuzzer binaries call — `fuzz/src/lib.rs`
  registers them in `ENTRIES`, and `stages(target)` is the stage trace each one
  must visit (26 stages for `teapot_output`: 18 output shapes plus the five
  typed action replies and the three passive replies — `version.identity`,
  `jobs.page` and `pass.ceiling`). The replay asserts the exact stage trace and the typed decision
  per parser: accepted documents, each rejection class (`Malformed`,
  `DuplicateKey`, `UnsafeNumber`, `InvalidShape`, `NonCanonical`), each stanza
  name, each Teapot diagnostic code, each oracle verdict, and each
  `DecodeError`. It also asserts that every target's corpus holds both an
  accepted and a rejected entry, judged by the entry's own trace. A separate
  layer keeps the direct production checks the trace does not express (a wrong
  digest, a stored-form reread, oracle evidence causes, decoded payloads).
- `fuzz/tests/targets.rs` reads `fuzz/fuzz_targets/*.rs` and requires each
  libFuzzer binary to call its own shared entry with the fuzzer input, exactly
  once. An empty `fuzz_target!` or one wired to another target fails here.
- `fuzz/tests/witnesses.rs` holds the non-vacuity and mutation witnesses: cases
  that would fail if a target silently accepted everything or exercised the
  wrong parser. It runs the replay with a stand-in entry that returns
  immediately and with another target's entry, and requires both to fail, so
  the "does the entry reach its parser" claim is tested rather than asserted.
  The Teapot matrix asserts that each of the 13 frozen output shapes parses its
  own capture and rejects every other shape's capture, with the one documented
  overlap (`rules list` and `intercept rules list` share the frozen `rules`
  contract), and that each live action shares its schema with the matching dry
  run while the trailing shape parser separates them.
- `teapot_output` covers all 18 `scourge.teapot-argv.v1` outputs, including the
  five live actions merged after the first session (`requests send`,
  `macros run`, `flows replay`, `flows show`, `jobs stop`) plus the three
  passive reply parsers (`version.identity`, `jobs.page`, `pass.ceiling`) that
  read a typed body beyond the frozen schema. Their typed-reply
  parsers are the adapter's own decoders, reached through
  `scourge_core::teapot::hostile` (the `hostile-input` feature, enabled only by
  this crate) with the operator parameters each captured seed was recorded with.
  The witnesses require a schema-valid but contradictory reply — a dry run,
  another job's stop, a hop list past the follow bound, a body window that
  disagrees with its bytes, a replay whose parent is not zero — to be refused.
  The declaration witnesses assert that `scourge.engagement.v1`,
  `scourge.policy-rule.v1` and `scourge.claim-template.v1` documents are not
  interchangeable, and that no rejection diagnostic echoes supplied text: the
  stanza predicate is `scourge_core::is_schema_stanza`, the same frozen field
  grammar and roots the producer uses, so an identifier-shaped leak such as a
  supplied `template_extension` key is rejected as non-schema text instead of
  passing a shape-only check.

The fast suite is a regression net over a finite set. It says nothing about
inputs nobody wrote down, which is what a bounded session adds — and even that
remains a sample, not a proof.

## What a bounded session proves, and what it does not

A recorded run shows that no counterexample was found in a stated time, at a
stated revision, with a stated toolchain and corpus, for the stated targets. It
does not establish that a parser is panic-free for all inputs, that a check holds
universally, or that the corpus is exhaustive. libFuzzer's counters are over all
instrumented code, including dependencies, so they are a trend line, not a
coverage claim about `fuzz/src/lib.rs`.

A further limit: coverage feedback rewards reaching new code, not reaching an
assertion. The entry contract above makes an entry that stops entering a parser
visible as a failed replay instead of a plateau, but an invariant whose
assertion stopped firing because its *condition* stopped occurring is still
invisible to coverage. The witnesses above are what make such an assertion
visible; the sessions below are what make an input nobody wrote down visible.

## Session 2026-11-24 — bounded coverage-guided run, all six targets

| Field | Value |
| --- | --- |
| Revision under test | `1ef9575cff696fa56b1869d4c932f332e2ce2e2a`, working tree clean |
| Follow-up commit | `84b5e86d679d` removes five `maw` conflict-bookkeeping comment lines at the top of `crates/scourge-core/src/teapot/mod.rs`; `git diff 1ef9575 84b5e86` changes no code |
| Toolchain | `nightly-2026-08-21`: `cargo 1.100.0-nightly (514c56dd7 2026-08-19)`, `cargo-fuzz 0.13.1` |
| Offline | `CARGO_NET_OFFLINE=true`; dependencies from the workspace lockfile, no network |
| Sanitizer and limits | cargo-fuzz defaults (AddressSanitizer), `-max_len=16384 -timeout=5 -rss_limit_mb=1024 -max_total_time=90` |
| Invocation | `just fuzz-parsers <target> 90`; seeds copied to a scratch corpus, artifacts kept in the same scratch directory |
| Result | no crash, no timeout, no OOM in any target; nothing to minimize and nothing added to the checked-in corpus |

| Target | Seeds | Seconds | Runs | Corpus after | Crashes | Final libFuzzer counters |
| --- | --- | --- | --- | --- | --- | --- |
| `canonical_json` | 14 | 91 | 509 926 | 1347 | 0 | `cov: 1818 ft: 5938` |
| `wire_contracts` | 21 | 91 | 255 368 | 1175 | 0 | `cov: 6902 ft: 15286` |
| `declarations` | 17 | 91 | 347 405 | 2891 | 0 | `cov: 13754 ft: 34317` |
| `teapot_output` | 20 | 91 | 43 115 | 527 | 0 | `cov: 1986 ft: 6393` |
| `oracle_observations` | 12 | 91 | 2 077 193 | 1567 | 0 | `cov: 4191 ft: 12615` |
| `body_decoder` | 15 | 91 | 837 098 | 846 | 0 | `cov: 1412 ft: 3797` |

The invalid-UTF-8 seeds and the raw coded bodies are marked binary in
`.gitattributes` so a review diff stays valid UTF-8; read them with `xxd` or the
corpus replay test.

Each target ran for one 90-second bound (91 reported seconds include libFuzzer's
own startup and shutdown). The corpus sizes are scratch-only: they count the
fuzzer's own generated units, which are not checked in because the run found no
crash and unminimized noise is not a regression net.

`teapot_output` explores the least, which is expected: its acceptance region is
the union of thirteen closed, schema-checked shapes, and a random mutation
almost always leaves it. Its rejection path is still the one that matters, and
the matrix witness in `fuzz/tests/witnesses.rs` pins it per shape.

This session predates the Teapot action adapter merge (`requests send`,
`macros run`, `flows replay`, `flows show`, `jobs stop`). It is still the record
for the parsers it ran at `1ef9575`, but it does not cover those five live action
reply parsers; the smoke below is the recorded sample for the current revision,
and a full six-target campaign over the current parsers has not been run.

## Session 2026-11-24 — final-revision smoke, all six targets

| Field | Value |
| --- | --- |
| Revision under test | `c8c93e2744a16834b2be14f2cbc106459937435f`, working tree clean |
| Toolchain | `nightly-2026-08-21`: `cargo 1.100.0-nightly (514c56dd7 2026-08-19)`, `cargo-fuzz 0.13.1` (enforced by `scripts/check-fuzz-toolchain.py` before the build) |
| Offline | `CARGO_NET_OFFLINE=true`; dependencies from the workspace lockfile, no network |
| Sanitizer and limits | cargo-fuzz defaults (AddressSanitizer), `-max_len=16384 -timeout=5 -rss_limit_mb=1024 -max_total_time=15` |
| Invocation | `just fuzz-parsers <target> 15`; seeds copied to a scratch corpus, artifacts kept in the same scratch directory |
| Result | no crash, no timeout, no OOM in any target; nothing to minimize and nothing added to the checked-in corpus |

| Target | Seeds | Seconds | Runs | Corpus after | Crashes |
| --- | --- | --- | --- | --- | --- |
| `canonical_json` | 14 | 16 | 99 746 | 791 | 0 |
| `wire_contracts` | 21 | 16 | 40 679 | 635 | 0 |
| `declarations` | 18 | 16 | 53 966 | 1 555 | 0 |
| `teapot_output` | 25 | 16 | 4 481 | 290 | 0 |
| `oracle_observations` | 12 | 16 | 222 454 | 1 043 | 0 |
| `body_decoder` | 15 | 16 | 84 352 | 543 | 0 |

`teapot_output` now covers all 18 argv outputs, including the five live actions
and their typed-reply parsers, which is why its corpus and its run count differ
from the 90-second session. A 15-second bound is a smoke: it shows the driver,
the corpus and every entry launch cleanly at this revision, not that the parsers
are correct.

An intermediate smoke of `declarations` at the first fix revision found a
harness defect rather than a parser defect: the strict stanza grammar rejected
the index-only stanza `[0]` that the producer emits for a path inside an array
(`[9007199254740992]`, an array-rooted document with an unsafe number). The
grammar was corrected, the minimized input is the checked-in seed
`fuzz/corpus/declarations/array-root-unsafe-number.json`, and the replay now
pins its exact decisions.

Adding a crash: minimize it
(`cargo +nightly-2026-08-21 fuzz tmin --features fuzzing <target> <artifact>`),
add the minimized file to `fuzz/corpus/<target>/` with a descriptive name, make
`just parser-corpus-check` pass, and record the new session above rather than
editing the numbers of an earlier one.

## Session 2026-11-25 — 26-stage teapot_output smoke, all six targets

| Field | Value |
| --- | --- |
| Revision under test | `e77f5c3c51f6c260e9eb99cba102f0fa7683ad5e`, tracked tree clean (`.tmp/` and `fuzz/tests/dump.rs` intentionally left untracked and untouched) |
| Toolchain | `nightly-2026-08-21`: `cargo 1.100.0-nightly (514c56dd7 2026-08-19)`, `cargo-fuzz 0.13.1` (enforced by `scripts/check-fuzz-toolchain.py`) |
| Sanitizer and limits | cargo-fuzz defaults (AddressSanitizer), `-max_len=16384 -timeout=5 -rss_limit_mb=1024 -max_total_time=15` |
| Invocation | `just fuzz-parsers <target> 15`; seeds copied to a scratch corpus under the workspace TMPDIR |
| Result | no crash, no timeout, no OOM in any target; nothing added to the checked-in corpus |

| Target | Seeds | Seconds | Runs | Corpus after | Crashes |
| --- | --- | --- | --- | --- | --- |
| `canonical_json` | 14 | 16 | 103 688 | 757 | 0 |
| `wire_contracts` | 21 | 16 | 44 759 | 655 | 0 |
| `declarations` | 18 | 16 | 55 222 | 1 579 | 0 |
| `teapot_output` | 25 | 16 | 4 407 | 291 | 0 |
| `oracle_observations` | 12 | 16 | 158 555 | 938 | 0 |
| `body_decoder` | 15 | 16 | 118 311 | 571 | 0 |

Each target ran a 15-second bound at the exact committed revision — a clean smoke over the 26-stage trace (18 argv shapes, five typed action replies, three passive reply checks), not a proof of panic-freedom.
