# Evidence contract and Investigation slice

**Status** · API selected. M0.6.2 conformance is blocked by three upstream packages.

Scourge needs immutable capture, read and record through one evidence store.
Investigation owns the original bytes, Artifact IDs, lineage and recording
recovery. Scourge's evidence fixtures exercise the public Investigation
0.1.0 JSON CLI at source commit `612eadb706eb14f349bad3b5625e0e8577180fc2`.
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

On 2026-11-23, the pinned binary passed 8 of 12 cases. The passing cases used
`capture begin`, `attach`, `finalize` and `recover`; `show --depth full`
for committed Run, Artifact and lineage; `ingest` for derivatives; and
`evidence read` for whole, byte-range and strict root JSON selectors.
`schema capture` advertised all five recording operations. A separate CLI
probe called `capture append` and recovered its accepted item at position 1.

| Exercised behavior | Result |
| --- | --- |
| Positions, stale cursors, complete sealing and refusal of late attachments | Pass |
| Whole UTF-8 reads, selected text bytes and invalid byte ranges | Pass |
| Immutable originals, separate redaction, ordered multi-input lineage and bad input rejection | Pass |
| Same-key retry across producer restarts, original receipts and Artifact IDs, changed-request conflicts | Pass |
| SIGKILL of the producer after acknowledged attachments, read-first recovery and partial sealing with a missing position | Pass |
| Whole and selected binary reads, including raw invalid UTF-8 | Blocked by Investigation `bn-q7sy`. The CLI reports the binary selection's offsets without its bytes. |
| Strict complete inventory | Blocked by Investigation `bn-29y4`. The CLI commits the seal and records partial evidence when a declared key is absent and an attachment is undeclared. |
| Strict JSON and byte preservation | Exact valid JSON bytes pass, and root selectors reject every malformed document. Investigation `bn-u6ja` tracks the write gap: derivative ingest commits malformed output across all 18 document and kind combinations. |

Recovery is exercised at the producer boundary between acknowledged CLI calls.
This run establishes the accepted prefix that a fresh session sees. Internal
recorder failures during a write, system power loss, retention, export and
retraction handling are outside this qualification.

## Reproduction

Build from the pinned Investigation source using a clean snapshot, especially
when its active checkout has advanced. The run used Rust and Cargo 1.100.0.

~~~sh
cargo build --locked --offline -p investigation-cli --bin investigation
./target/debug/investigation --version
~~~

From Scourge, point the fixture at that binary. Its version string identifies
0.1.0, so the exact source commit must also be verified when building it.

~~~sh
SCOURGE_INVESTIGATION_BIN=/absolute/path/to/investigation \
  python3 -B fixtures/contracts/evidence/run.py \
  --adapter fixtures/contracts/evidence/investigation.py
~~~

## Requalification

M0.6.2 stays open until every case passes against one named Investigation
version. Run the suite again after any pin, wire protocol, selector, or
retention behavior change. Before M1.4 uses this slice in production, verify
the operative limits and the retraction capability against the selected
binary and the plan's retraction gate.
