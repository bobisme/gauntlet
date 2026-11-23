# Two Teapot projects on one Hallpass pass

**Result: works with accounting and containment caveats.** Two distinct engines
were running simultaneously, each bound to the exact same pass path and digest;
each sent one GET to the loopback target and received 200. Sends were sequential,
so this does not test simultaneous draws or race safety. Both engines used
`--no-enforce`: Teapot reports a loopback destination cannot be enforced by
Playpen. This experiment establishes neither OS containment nor credential
isolation. The policy lock is not containment.

The pass had a 100-request ceiling. The verified Hallpass ledger and Teapot
`pass show` (spent / left / unused) showed:

| Snapshot | Ledger spent / remaining | Project 1 | Project 2 |
| --- | --- | --- | --- |
| Both started | 0 / 100 | 0 / 100 / 0 | 0 / 100 / 0 |
| After project 1 sends | 10 / 90 | 1 / 99 / 0 | 0 / 100 / 0 |
| After project 2 sends | 20 / 80 | 1 / 99 / 0 | 11 / 89 / 0 |
| Both stopped cleanly | 20 / 80 | 11 / 89 / 9 | 11 / 89 / 9 |

Each engine reported one block drawn, ten units drawn, one handed and nine
in hand after its send. Its live view did not necessarily refresh after the
other engine drew. Project 2's `spent=11` includes project 1's entire block,
although the target saw just two requests total. After clean stops each project
reported nine unused, local to that project; the ledger still held both ten-unit
charges. These are reservations, not evidence of 20 target requests. Teapot
source at the pinned `crates/teapot-engine/src/allocator/mod.rs` explains that
unused in-hand units are noted per project on clean shutdown and may be carried
by a later engine of the **same project and pass path/id**; crashes can lose
units. This experiment did not restart an engine or exercise a crash, a ceiling
exhaustion, or concurrent draws. Do not add the two projects' displayed
`left` or treat either project's `spent` as aggregate actual requests.

For custody spike **bn-34o**: a separate verifier project can use the same
pass in this narrowly tested configuration, but its own block and stale/local
views make pass-wide budget attribution unsuitable for per-run proof. Preserve
the same physical pass and ledger, independently account for both projects'
in-hand units and lifecycle, and test containment and concurrent spending before
relying on this architecture. This is an inference from the observations and
source, not a demonstrated custody or safety guarantee.

## Reproduction and provenance

`fixtures/contracts/two-projects-observed.jsonl` is the full captured command
output (temporary root redacted to `$TMP`); timestamps, ports and IDs are
run-specific. It records the generated pass contents and SHA-256
`c7bcecb2d3b2d4f522df7ccb50c7306b1ba41a611266b3eebd2d9187b42856e1`.
Both `pass show` outputs and every ledger entry carry that same digest. Hallpass
`init` made the file, the harness filled it, and `check` validated it; this is a
local test approval, not an external authorization.

Teapot was the existing clean offline locked build of source commit
`6238d5a78a6514466d54ad16dd5737f43c1d4961`, binary SHA-256
`6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458`
(see `fixtures/contracts/manifest.json`). Hallpass was exported with `git archive`
from `44f749ac158e8378705bab80d855ed0a1f634a54`, then built using
`cargo build --offline --locked --bin hallpass` in a separate target; binary
SHA-256 `be289583707b9a6810d148dbddf4e3c0c09fddd74b78d4e00cab47f8c30e993d`.
Both used rustc 1.100.0 (0ef1bc386 2026-11-09). Build digests can depend on
source path and toolchain; the harness enforces the existing Teapot digest and
prints the Hallpass digest, so compare it with this observation.

Run `python3 scripts/two-projects-pass.py --teapot /absolute/path/to/teapot
--hallpass /absolute/path/to/hallpass`. It creates its own temporary HOME,
projects, pass, ledger and loopback HTTP listener, asserts the key observations,
and stops both engines in a finally block. It requires local sockets; no external
network is used. Preserve stdout for the run's exact pass and accounting evidence.
