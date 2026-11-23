# Evidence contract and Investigation slice

**Status** · Qualified. M0.6.2 passes all 12 public-interface cases.

Scourge needs immutable capture, read and record through one evidence store.
Investigation owns the original bytes, Artifact IDs, lineage and recording
recovery. Scourge's evidence fixtures exercise the public Investigation
0.1.0 JSON CLI at source commit `6a0c5ed843d0f4870910d3a926298890290c916e`.
The fixture adapter targets `inv.capture.v1`, `inv.ingest.v1` and
`inv.selector.v1`. Configuration is limited to a fresh workspace, a single
record case per fixture workspace and a private import root.

The minimum supported slice is W01's versioned request and receipt rules,
W02's hashed content and idempotent commits, W03's Run and Artifact identity,
W06's derivative ingest and digest-bound selectors, and W07's incremental
recording. A staging receipt identifies a durable item by handle, key,
position and request digest. The sealed Run binds that item to its published
Artifact ID and content digest. Presence in an accepted staging prefix
establishes persistence of the recording so far.

## Conformance record

On 2026-11-23, the pinned binary passed all 12 cases. The run used
`capture begin`, `attach`, `finalize` and `recover`; `show --depth full`
for committed Run, Artifact and lineage; `ingest` for derivatives; and
`evidence read` for whole, byte-range and strict root JSON selectors.
Complete finalization opted into strict artifact inventory, binary reads used
the public base64 byte field, and structured derivative writes opted into the
strict JSON validator before commit.

| Exercised behavior | Result |
| --- | --- |
| Positions, stale cursors, complete sealing and refusal of late attachments | Pass |
| Whole UTF-8 reads, selected text bytes and invalid byte ranges | Pass |
| Immutable originals, separate redaction, ordered multi-input lineage and bad input rejection | Pass |
| Same-key retry across producer restarts, original receipts and Artifact IDs, changed-request conflicts | Pass |
| SIGKILL of the producer after acknowledged attachments, read-first recovery and partial sealing with a missing position | Pass |
| Whole and selected binary reads, including raw invalid UTF-8 | Pass through `excerpt.bytes_base64`; exact bytes and digest are checked. |
| Strict complete inventory | Pass with `strict_artifact_inventory: true`; a mismatch refuses atomically, leaves the handle open and permits corrected same-key finalization. |
| Strict JSON and byte preservation | Pass with `validate_as: strict_json`; all 18 malformed document/kind writes refuse before publication and key consumption, while distinct valid spellings retain exact bytes. |

Recovery is exercised at the producer boundary between acknowledged CLI calls.
This run establishes the accepted prefix that a fresh session sees. Internal
recorder failures during a write, system power loss, retention, export and
retraction handling are outside this qualification.

## Reproduction

Build from the pinned Investigation source using a clean snapshot, especially
when its active checkout has advanced. The accepted run used Rust and Cargo
1.100.0, release mode and offline locked resolution. Its executable SHA-256 was
`c368ab4d8e0511524674692b039c4f248cee2b5676d143a23f5ab9025a31d4fc`.
The clean `git archive` tar of the named source commit had SHA-256
`12efb99c978e10f634f43b039ddc5391de5dbfeb44bcd4703952fb1aae0415df`.
The machine-readable conformance record binds the run, driver and adapter bytes
that produced the result as well as the exact build and execution arguments.

~~~sh
cargo build --release --locked --offline -p investigation-cli --bin investigation
sha256sum target/release/investigation
./target/release/investigation --version
~~~

From Scourge, point the fixture at that binary. Its version string identifies
0.1.0, so the exact source commit must also be verified when building it.

~~~sh
SCOURGE_INVESTIGATION_BIN=/absolute/path/to/investigation \
  python3 -B fixtures/contracts/evidence/run.py \
  --adapter fixtures/contracts/evidence/investigation.py
~~~

## Requalification

Re-run the suite after any source pin, wire protocol, strict validator,
selector, capture lifecycle, retention or lineage behavior change. Before M1.4
uses this slice in production, verify the operative limits and the retraction
capability against the selected binary and the plan's retraction gate. The
qualification covers public CLI behavior on a local filesystem; it does not
qualify power loss, retention, export, retraction or concurrent writers.
