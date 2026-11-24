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
selector, capture lifecycle, retention or lineage behavior change. The M0.6
qualification covers the operations listed above on a local filesystem.

## M1.4 Evidence bridge

`scourge_core::evidence::Evidence` uses one private Investigation workspace
and one record case per Scourge workspace. Initialize with the qualified
executable, evidence directory and a separate private import directory in the
same custody boundary. Reopening resolves the case from Investigation's
original receipt. Keep the private import path fixed. Scourge records the
Investigation version, source commit and executable digest with each capture.
Attach requests preserve the input bytes and use a stable item key and position.
Finalization reconciles its receipt with recovery and the committed Run
inventory before returning original Artifact references.

Reads use full Artifact IDs. Byte ranges are half-open. The bridge checks
the revision, snapshot, digest and returned offsets across each range, and
hashes the assembled bytes for whole reads. The pinned API returns at most
32 KiB per excerpt and reads artifacts up to 64 MiB. A large artifact takes
multiple CLI calls, each of which verifies the retained artifact. Structured
reads use Investigation's strict root JSON selector. Structured derivative
writes opt into its strict JSON validator and preserve valid input bytes
exactly. Derivatives record ordered, digest-bound input references.

The exact pin exposes `artifact.withdraw` and `source.withdraw`.
`show` and `evidence read` report `evidentiary_use.state` for the artifact
and its current lineage. A partial or entire withdrawal denies a read or use
as a derivative input. The bridge refuses missing or unknown use states and
unqualified builds. M1.6 consumes the typed withdrawal result for finding
status. Investigation still retains the original bytes.

That reported state is **bounded**: the pinned lineage walk visits at most 64
current Artifacts and Sources (`source_ops.rs`, `MAX_LINEAGE`) and carries no
completeness flag, so a withdrawal further back leaves `state: in_use` with an
empty `withdrawals` list. The bridge therefore never treats the reported state
as complete on its own. Before a read, a describe or a derivative input is
accepted, it walks the whole current lineage itself: it follows every
`transforms[].input` and `source` of each reachable Artifact, requires one
unchanged snapshot head across the walk, and re-verifies each record's revision
and input digest. Every visited record is asked for its own reported state,
which always covers that record, so a withdrawal cannot fall outside the scan.
The walk refuses with `LineageUnverified` when a record cannot be fetched or
verified, or when it exceeds its bounds (256 current records); a changed
snapshot head refuses with `ChangedSnapshot`; an exhausted deadline refuses
with `BackendTimeout`. Bounds limit work; they never stand in for completeness,
and an incomplete lineage is never accepted or promoted as complete.
`derivation`'s own `truncated` flag is not relied on because the pinned `show`
view is classification-gated, bounds its step list and may omit step identities.

Investigation calls are bounded children. Each call has a deadline (30 s, 5 s
for `--version`), a bounded stdin control request (512 KiB, 64 KiB for an
attachment request), bounded stdout (32 MiB) and stderr (64 KiB), a private
process group killed and reaped before the result is returned, and typed
failures: `BackendTimeout`, `BackendOutputTooLarge`, `RequestTooLarge` and
`StagingBusy`. A stalled backend therefore cannot hold the staging lock or the
calling process indefinitely. The staging directory lock is acquired with a
bounded wait and released by drop.

Failure evidence is kept, not discarded. Captured stderr is retained instead
of drained away, and every known native status is preserved. A child that
exits unsuccessfully without a well-formed Investigation error envelope fails
with `BackendFailed` rather than `Protocol`, so a crash or a diagnostic printed
only on stderr is distinguishable from a malformed successful reply; a
malformed reply from a child that exited successfully is still `Protocol`.
A `BackendTimeout` or `BackendOutputTooLarge` reached after the leader had
already exited, which a descendant holding an inherited pipe can cause, keeps
that exit code or signal. A status produced by this bridge's own group kill is
never reported as the backend's.

Every one of those failures carries a `BackendDiagnostic`: the native status
when it was observed, which bound ended capture, the exact captured stderr
length and digest, and one redacted single-line excerpt capped at 200 printable
ASCII characters. Raw stderr is never exposed, so untrusted backend content,
control bytes and terminal escapes cannot reach a log or a terminal through an
error message.

The child runner is deliberately a sibling of Teapot's rather than shared code.
This path needs replayable stdin, evidence's typed failures and the staged-exec
retry, and extracting a common runner would rewrite the reviewed Teapot
custody path from an evidence change. Both enforce the same contract: a private
process group, a deadline, a per-stream cap, and kill-before-reap so a numeric
group ID is never signalled after it can be recycled.

The verified executable is staged privately. The bridge creates its scratch
directory with mode 0700 under a parent that is either not writable by other
principals or protected and owned by this principal or the system root, then
writes the executable with mode 0600, restricts it to 0500, reopens it without
following links, and confirms the admitted inode is the checked one. The
read-only descriptor stays open for the life of the bridge and every call
executes `/proc/self/fd/<n>`, so replacing either the operator's source path or
the staging entry cannot change the bytes that run. A transient `ETXTBSY` (a
concurrently forked sibling can briefly inherit the writer) is retried within
the call deadline and never substitutes other bytes. A permissive umask cannot
widen the staged directory or the executable.

Run the bridge tests with the exact executable from the conformance record.

~~~sh
SCOURGE_INVESTIGATION_BIN=/absolute/path/to/investigation just evidence-bridge-check
~~~

The live bridge tests cover acknowledged-prefix recovery after killing the
producer between CLI calls and a 65-derivative chain whose withdrawn ancestor
sits beyond the pinned 64-record scan. An interruption during a call can leave
a private import file until the same attachment is retried. Concurrent writers,
power loss, retention and export remain outside the tested scope.

The bounded-runner regressions use controllable children rather than the pinned
binary, because a qualified executable cannot be made to crash on demand. They
cover a stderr-only nonzero exit, a signalled child with no exit code, a
timeout with no observed status, a leader that exits while a descendant keeps
the inherited pipes open until the deadline, stdout and stderr overflow after
the leader's status was observed, the redaction and length bound of the
diagnostic, and descriptor release across repeated failing calls. A live
backend exit that the pinned binary cannot reproduce is not claimed here.
