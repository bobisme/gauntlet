# Authenticated skeleton process collector

`lib/skeleton_process_monitor.py` is the host-only accounting boundary for the
M1.9 cold-agent trial. It launches the exact foreground rootless-Podman worker
under the pinned host `strace`, reconstructs the native Codex JSONL stream, and
binds every completed native command item to one closed process tree. It is an
evaluation instrument, not a Scourge product isolation claim.

The collector supports a deliberately small execution subset. Every executed
image in a Codex command tree must have an absolute path in the frozen
read-only image/mount map. The map binds the requested path to the executable
digest established by the outer boundary. Relative paths, `execveat`, deleted
or memfd images, writable/unresolved images, incomplete argv, unqualified signals,
unfinished syscalls, overlapping command trees, and unknown extra trees fail
the attempt. An executable named `scourge` is accepted only at the exact
frozen Scourge path and digest, with `argv[0]` either that path or the single
safe PATH-resolved spelling `scourge`. Each native item is additionally bound
to its direct `sh -c`/`bash -lc` command root and that root's actual exit.
Writes before the final exec epoch are excluded, and a non-final Scourge exec
is invalid. A Scourge execution may create threads and only the narrowly
approved direct child classes below:

- request-reference Teapot at the configured pinned path, or through
  `/proc/self/fd/N` with configured Teapot `argv[0]`, exact digest
  `c03bd1df...326abae`, and an exec-stop inode observation;
- qualified Investigation through `/proc/self/fd/N`, with that exact path as
  `argv[0]`, digest `c368ab4d...31d4fc`, and only the source-backed
  version/init/config/ingest/capture/receipt/show/evidence-read argv forms,
  always under the exact native actor `agent:scourge`.
- the built-in protected-demo fixture, only as an exact pinned Scourge child
  of the exact demo-start call. During this one preparation role the fixture
  may run the historical Teapot digest `6d15d625...b2f458` from an attempt-owned
  private 0500 path beneath the frozen preparation root. Its exact `proxy
  start` child and the later exact `proxy stop` child are separately bound to
  the authenticated external demo-stop, their compact JSONL outputs, event
  order, timestamps, exits and final quiescence. No other fixture or engine
  child is admitted.

The fixture's bootstrap, address and engine-start phases retain the 45-second
`BOOT` bound, and the public parent still waits at most two seconds for the
commit acknowledgement. The post-engine preparation phase has a separate
named 90-second `COMMIT_STAGE` bound. Raw v43 completed that traced phase in
37.30 seconds, while rejected v44 required 46.36 seconds and therefore proved
that reusing `BOOT` made correctness depend on scheduling. If the parent is
lost during this phase, the private engine may live until the larger finite
bound; expiry or a wrong stage rejects and drops the owned engine instead of
retaining it.

Both FD classes require a non-deleted regular 0500 inode owned by the monitor
principal. Their exact argv, parent PID, actual exec path, digest, exit and
stdout are retained. They must exit successfully and cannot create process
children. The role exec must be the lifetime's first and only successful exec;
failed/prefix execs and every pre-role stdout or non-stdout write reject rather
than being laundered into the final role. Every other Scourge child is invalid. The Scourge process exit must
equal the native command-item exit, so a shell cannot hide a failed Scourge
child.

## Fixed trace contract

The fixed arguments are source-pinned and included in the composite monitor
digest:

```text
-f -ttt -xx --decode-pids=pidns -s 262144
--inject=execve:delay_exit=250ms --inject=execveat:delay_exit=250ms
-e trace=%process,write,writev,pwrite64,pwritev,pwritev2,sendfile,splice,vmsplice,copy_file_range,io_uring_enter
```

`-v`, `--abbrev=none`, `-E`, environment decoding/expansion, and caller-supplied
trace flags are unavailable. The delay is fixed instrumentation: while ptrace
holds the successful exec exit, a host watcher hashes `/proc/PID/exe` and
records its target, device, inode, mode, owner and process-start identity.
This is the authority for an FD child; argv text is never treated as its
digest. Hashing uses two bounded in-process workers so hashing a large pinned
executable cannot starve the 2 ms discovery loop. Each worker holds the exact
opened executable FD, hashes in 1 MiB chunks, and requires identical pre/post
device, inode, full mode, link count, size, mtime and ctime plus the
target-derived expected digest. The limits are 384 MiB per executable, 512 MiB
of aggregate outstanding work, 32 jobs, and five seconds per hash/ten seconds
in the queue. The signed receipt records completion times, queue high-water
marks and post-completion cache reuse; pending work is never treated as a
cache hit. The fixed Debian usr-merge spelling `/bin/bash` is the only admitted
alias: `/bin` must resolve exactly to `usr/bin`, both opened paths must identify
the same inode, and the receipt retains requested and resolved paths. `execve`
retains only an opaque environment pointer/count. The launcher
constructs a minimal environment from fixed locale/path values plus
`HOME`, `XDG_RUNTIME_DIR`, `USER`, and `LOGNAME`; provider/API/credential
variables are never inherited by strace or Podman. The real qualification
places a credential canary in the host environment and confirms its plaintext
bytes and its `-xx` rendering are absent from the private trace and all derived
artifacts. Trace, raw JSONL and stderr ceilings are enforced during execution
with bounded overshoot and process-group termination, not only after exit.

The frozen configuration also binds the compact canonical digest of the exact,
ordered, assignment-specific Podman argv. At launch the collector re-computes
that digest and independently requires the one fixed `run` prefix, one valid
container name, and exactly one secure spelling of each runtime, network,
read-only, proxy, capability, security, pull, user-namespace and removal option.
Duplicate and last-wins forms, privilege/device/capability additions, host
namespace changes, detachment and environment/secret injection fail even if an
unsafe command was mistakenly pre-bound into a configuration.

Podman argv digest equality is not mount authority. Production configuration
also carries a typed live-fstat mount manifest. It binds each canonical host
source device/inode/mode/owner to one exact destination and access mode,
requires only `/workspace` and `/runtime` writable beneath the attempt-private
root, requires `/gateway` and every pinned executable explicitly read-only,
rehashes executable sources, and rejects protected credential roots, duplicate
or overlapping sources/destinations, symlinks, substitutions, and binary
shadowing. The native qualifier therefore copies the exact pinned installed
Codex bytes into its private attempt-owned tool root and mounts only that 0500
retained copy; it never bind-mounts through the host's protected `.codex` tree.

Production argv uses the exact ordered prefix
`/usr/bin/podman --remote=false --runtime=/usr/bin/crun run --rm
--unsetenv-all --interactive --pull=never --network=none --read-only
--http-proxy=false --cap-drop=all --security-opt=no-new-privileges
--pids-limit=128 --userns=keep-id --hostname=scourge-worker`, followed by one
name/cidfile, bind mounts, sorted environment rows, entrypoint, immutable image
ID and worker argv. Options after the image cannot satisfy any Podman
requirement. Production worker environment is a second launch input. The
caller passes
`worker_environment_rows(native_codex_boundary.worker_environment(...))` to
`MonitorConfig`; the collector requires the argv's sorted, two-token `--env
KEY=VALUE` rows to match it exactly once. The qualified fixed values cover only
runtime paths and inert terminal/locale controls, including
`HOSTNAME=scourge-worker` and a bounded two-socket `M0_PROXY_PORT`. Unknown
keys, duplicate keys, credential-like names, alternate
`--env=` spelling, newlines, NULs and host inheritance all fail closed.

`write(1)` and `writev(1)` are reconstructed from successful return lengths,
including partial writes. A successful alternative fd-1 output syscall is an
unsupported condition and invalidates the attempt. Writes from thread-group
members are ordered by the trace timestamps. The pinned Codex thread-group
stdout must equal the captured raw JSONL byte-for-byte. Scourge stdout is
retained separately even when a shell pipes, transforms, interleaves, or
redirects it; `stdout_offset` is conservatively null. Writes to other FDs are
not decoded, so a deliberately bounded/truncated trace rendering of the
private staged executable bytes cannot be confused with stdout loss.

The process-tree trace is synchronous ptrace evidence. `lost_events: 0` means
the complete descendant tree drained with every assessed process closed and no
unparsed assessed syscall; it is not a claim about an asynchronous kernel event
queue. Raw strace, raw JSONL, and stderr live in a host-private 0700 control
root as 0600 files. The key is opened `O_NOFOLLOW` and checked with `fstat`.
Private and retained roots stay open by directory FD and their device/inode is
rechecked; all collector I/O is relative to those held roots. The signed trace
binds the raw strace SHA-256 and the complete exec-stop snapshot digest. Raw
strace and raw snapshots are never worker-visible or public artifacts. A run
settles only after explicit pinned-Podman checks prove both the attempt CID and
assigned name absent. A CID watcher retains the private cidfile value before
`--rm` removes it; cleanup acts only on that CID after exact ID/name inspection
and never force-removes an unrelated colliding name.

Every signal-delivery record is parsed and retained. Only a normal
`SIGCHLD/CLD_EXITED` reconciled to the exact child host/namespace identity,
status, parent group and timestamp, plus the one exact historical demo fixture
orphan whose authenticated Codex-origin demo-start parent exits before it and
which the pinned supervisor's documented container-PID-1 reaper group later
receives, plus the exact same-thread-group
`SIGURG/SI_TKILL` preemption contract of the authenticated Codex process-setup
image, is admitted. Caught, ignored, foreign, malformed, or unmatched signals
reject. Numeric PID reuse, a second clone lifetime, and any event after a
terminal record also reject rather than collapsing two lifetimes.

## API and integration

The runner freezes an `ExecutablePin` for every permitted worker executable,
computes `podman_argv_digest(podman_argv)`, and constructs `MonitorConfig` with
that digest and the frozen worker-environment rows. Then it calls:

```python
pin = freeze_monitor(config)
key_path = create_monitor_key(private_control_root)
result = run_monitored(
    podman_argv,
    prompt=trusted_prompt_bytes,
    config=config,
    attempt_id=attempt_id,
    assignment_sha256=assignment_sha256,
    key_path=key_path,
    private_control_root=private_control_root,
    evidence_root=evidence_root,
    retained_path=f"{attempt_id}/retained/artifacts",
    producer_manifest_sha256=producer_manifest_sha256,
    monitor_key_commitment=monitor_key_commitment,
)
```

The trusted prompt is a required non-empty bounded byte string delivered to
the interactive production supervisor, which passes those exact bytes to
Codex stdin. The signed launch receipt contains only its digest and size, the
exact Podman argv digest, and a domain-separated launch digest; prompt content
is never copied into the host trace. The stable monitor digest excludes
per-attempt argv, environment and prompt values so four assignment cells share
one implementation/config pin while carrying distinct authenticated launches.

The 32-byte key is generated from the OS CSPRNG, stored mode 0600 outside the
worker, run root, gateway, transcript, and retained artifact tree. Only its
domain-separated commitment is public; that commitment and the clean producer
Git commit/tree plus all control-source hashes are bound into the assignment
and signed trace. The normalized trace is authenticated as:

```text
HMAC-SHA256(key,
  b"scourge.skeleton-host-process-trace.v1\0" +
  compact_sorted_ASCII_JSON(trace))
```

`MonitorResult` supplies the authenticated envelope, deterministic events
projection, per-Scourge stdout artifacts, exact Teapot and Investigation child
stdout artifacts, private raw paths, the private snapshot path, and the
container-absence result. Each `calls` row carries `exec_path` and `exit_code`.
Every retained reference is exactly `{path,sha256}` below
`ATTEMPT/retained/artifacts/`. `child_originals` is one signed execution-order
sequence across Teapot and Investigation; roles remain authenticated on the
corresponding executions, so Investigation transport cannot be projected as
Teapot surface evidence. The integrated runner
must feed retained files through the ordinary trial-capture seam; it must not
copy raw strace or raw snapshots into worker-visible or scored evidence. The
collector does not create assignment pins, decide finding validity, clean up
the rest of the trial, or substitute for capture settlement.

The collector trusts the host operator/referee, kernel, pinned `strace`, pinned
Podman/crun, and the frozen read-only image/mount digest map. It authenticates
what happened while traced; it does not prove equivalence to an untraced run,
and a worker may detect tracing.

Before `valid=true`, envelope, events, every call stdout and every approved
child original are reopened component-by-component through the caller's held
private evidence root with `O_NOFOLLOW`, rehashed, and checked for the exact
relative path. The envelope HMAC and exact events-to-trace projection are then
reverified. The legacy v1 JSONL migration is frozen byte-for-byte; a torn
suffix is an integrity failure and is never silently truncated. Live attempts
use a private v2 immutable event directory under one exclusive lock. Each
canonical mode `0600`, single-link event carries a contiguous sequence and
previous-event digest and is published by fsynced temporary file,
same-filesystem no-replace link, and parent-directory fsync.

An `attempt_started` event is durable before post-bootstrap mutable work. After
the stable no-follow artifact manifest is sealed, a receipt candidate binds
only the backward journal prefix, attempt nonce, producer, inventory and
absence evidence. The driver fsyncs that candidate and directory, appends
`publication_prepared`, no-replace links the exact bytes to the official output
and fsyncs its directory. It then reopens both canonical names relative to one
held no-follow parent descriptor and requires the same device/inode, exact
`nlink=2`, owner, `0600` mode, size, digest, and stable pre/post fstats. Only
then may it append
`attempt_finished=accepted` with the exact receipt/core digests. Acceptance is
external: both the durable output and matching v2 accepted event are required.
Recovery rejects start-only attempts without claiming container absence, or
revalidates the exact candidate, current artifact identities, and current
Podman absence of both signed CID and name before idempotently publishing a
prepared attempt. Recovery always fsyncs the output parent before acceptance,
including when it resumes after the link but before the original directory
fsync. Byte-equal distinct inodes, extra links, wrong owner/mode, symlinks,
replacement races, missing/tampered artifacts or absence evidence,
noncontiguous events,
unknown temps, unsafe modes/links, or an accepted event without its exact
receipt are integrity failures. The artifact root itself must be a canonical,
owner-only `0700` directory. The manifest then walks exclusively from a held
root descriptor with relative `O_NOFOLLOW` opens, requires every descendant
directory to have the same owner, owner read+execute access, no group/other
write access, and one of the observed `0500`, `0700`, or `0755` modes. It
records exact root, directory, and file fstats and rejects identity changes
between lookup, open, hashing, and the final held-descriptor check.

The bn-3plk producer's production composition must call its boundary builder
with pinned absolute `podman_executable=/usr/bin/podman`,
`oci_runtime=/usr/bin/crun`, `auto_remove=true`, and `interactive=true`. Its
entrypoint is the pinned two-socket supervisor; the worker suffix contains the
exact wrapper `--self-sha256 SUPERVISOR_SHA256 --codex-sha256 CODEX_SHA256 --
/opt/scourge-bin/codex ... -`. The embedded digests, boundary, Codex argv, and
disabled `code_mode`, `code_mode_host`, and `shell_snapshot` features are all
bound before launch. The collector separately authenticates
the supervisor -> Codex -> command-root lineage and rejects extra supervisor
children. Its separate
installed/two-socket qualification may use `auto_remove=false` so it can inspect
the stopped container before its own explicit removal; that argv is not a
collector production launch.

Codex 0.172 infrastructure is authenticated separately from Scourge calls:
the exact supervisor -> Codex lineage, six fixed OS-detection helpers, the
single process-setup self-exec and dash transition, immutable login-profile
helpers, and the one exact loopback proxy probe. Infrastructure rows cannot be
projected as Scourge calls or native child originals. The process-setup FD
contract prefers live pipe topology and otherwise accepts only the exact
trace-derived NUL signal in the authenticated exec epoch.

The offline Responses relay always refuses `previous_response_id`;
continuation uses only the append-only full input history. Provider SSE is
buffered and fully validated before any upstream byte is returned to Codex.
Each record is exactly one `event` line plus one strict-JSON `data` line under
closed blank-line framing. Unknown fields/types, invalid UTF-8, sentinel data,
bare CR, torn or duplicate/reordered events, inconsistent optional sequence
numbers, and budget overflow reject. Every present integer is an exact bounded
Python/JSON integer (never boolean, float, null, or container), optional field
absence is distinct from explicit null, and every required ID/name/text is an
exact bounded string matching its grammar. The verified Codex 0.172 compact form is
exact ordered `response.output_item.done` followed by `response.completed`. If
an incremental chain begins, added items/content parts, every
text/argument/input delta and done event, item completion and terminal output
must form one contiguous closed lifecycle with byte/semantic equality. Every
output item uses the documented completed assistant-message/function/custom
tool allowlist. Provider validation is one locked temporary transition. Any
mismatch or validation exception returns one fixed local JSON 502 with no
upstream body, removes only the exact provisional request artifact, poisons and
closes the listener, and restores all prior/new counters, inputs, IDs, pending
calls, and terminals. A malformed second response therefore cannot erase the
previous accepted tool chain; valid streams remain byte-identical.

## Checks

The ordinary offline parser/adversarial gate is:

```sh
just skeleton-process-monitor-check
```

The native qualification needs the already-cached Python image, rootless
Podman, pinned host tools, and the SHA-pinned `/usr/bin/gcc`. It makes no provider/model
call and uses `--network=none`:

```sh
python3 -B evals/scripts/qualify-skeleton-process-monitor.py \
  --output /tmp/skeleton-process-monitor.json
```

It exercises direct, nested-shell, piped, transformed, redirected, failed, and
short-lived Scourge executions, plus normal Teapot, FD Teapot, and FD
Investigation children with exact raw output. The disposable qualification
program uses its own recorded probe digest to exercise the mechanisms; its
frozen `qualification_child_pins` bit records that synthetic boundary, while
ordinary configurations reject anything except the two exact production
constants above. It also checks
exact Codex JSONL reconstruction, per-process exit binding, authenticated
settlement, credential-canary absence, exec-stop capture, and independently
proved container removal. The receipt hashes describe disposable private
evidence that is not committed.

The exact installed-Codex/native lane is explicit because it uses large local
binaries and a host-private evidence root. The Just target is deliberately a
non-authoritative refusal: a mutable checkout Justfile cannot establish
first-byte trust. The official launcher is the fixed `/bin/bash -c` body named
`TRUSTED_LAUNCHER_SCRIPT` in the committed bootstrap. An operator supplies the
expected 40-hex commit from outside the checkout (never deriving authority from
checkout `HEAD`) and invokes that literal with these positional arguments:

```text
/bin/bash -eu -o pipefail -c TRUSTED_LAUNCHER_SCRIPT -- REPO EXPECTED_COMMIT OUTPUT PREPARATION_TEAPOT REQUEST_REFERENCE_TEAPOT INVESTIGATION ATTEMPT ATTEMPT_HISTORY PRIOR_RECEIPT V36_DISPATCH_FAILURE_LOG
```

The literal reads only Git objects with root-owned `/usr/bin/git` and uses
root-owned `mkdir`, `dd`, `chmod`, `sha256sum`, `/bin/bash`, and shell
redirection before the bootstrap. It requires `EXPECTED_COMMIT^{commit}` to
equal the external operator value, creates a fresh private `0700` root, retains
its exact `/proc/$$/cmdline`, materializes the bootstrap blob at that commit as
mode `0500`, then invokes `/usr/bin/python3 -I -S -B` on that private file.
The stdlib-only bootstrap requires the exact fixed launcher argv/cmdline,
expected commit, blob OID/SHA-256 and held no-follow fstat before it checks the
complete checkout status, commit/tree, committed control blobs and ignored
import shadows. It copies those blobs into a fresh private runtime source root
and executes only the copied qualifier/modules. The qualifier independently
reopens and rehashes the retained launcher cmdline, bootstrap and committed
blobs. Modified or restored checkout Just/bootstrap bytes cannot influence
accepted evidence. Those exact launcher bytes and host paths remain only in
the private bootstrap receipt. The public producer manifest retains their
SHA-256s and identity metadata, replaces the private bootstrap/cmdline paths
with stable `control/...` references, and omits the full launcher/bootstrap
argv so an attempt output, history, or private evidence root is never
serialized into the public receipt.

The v36 Just syntax failure is retained separately as typed pre-bootstrap
dispatch evidence. It is truthfully outside the post-bootstrap attempt journal
and claims no known container state.

The formerly accepted v37 receipt and raw build trace are also retained as
typed rejected method evidence. The old projection counted 230 successful
execs and 18 unique paths; exhaustive split-record reconstruction found 269
successful execs and 25 unique paths, including seven omitted target build
scripts. It is never imported as accepted history.

The v38 raw trace is likewise retained as typed rejected method evidence. It
contains two otherwise-unresolved `???( <detached ...>` records, which strace
defines as syscalls from which it detached before return. Those records remain
a hard trace-loss refusal; the immutable v38 event truthfully leaves container
absence unknown. Any later independent Podman absence check is reported only
as separate corroboration and is not folded into that event.

The v39 build and real container lane completed, but publication correctly
refused the pre-fix producer manifest because it still projected the private
trusted-launcher argv/cmdline path. Its immutable rejected event likewise
leaves container absence unknown; the later host Podman absence observation is
separate corroboration. The retained v39 build trace independently reparses to
269 successful execs, 25 unique paths, 268 delayed successes, and zero
successful `execveat` calls.

The v40 build, real container lane, relay, collector, evidence HMACs and
teardown all completed, but the final predicate refused publication because a
stale pre-v2 check still expected the current attempt to appear incomplete in
the now-frozen v1 log. Its v2 journal truthfully contains a started event and a
rejected terminal with proved container absence. Current qualification instead
requires every frozen-v1 incomplete set to be empty, every earlier v2 attempt
to be terminal, and exactly one current started-only v2 event with the exact
nonce and initial producer identity before publication begins.

The v41 build and complete qualification predicate also succeeded, but the
first publication-manifest implementation incorrectly required every nested
directory to be exactly `0700`. It therefore refused the intentionally
read-only `0500` private toolchain/vendor directories and executable `0755`
runtime directories before a candidate or official receipt existed. Its v2
journal contains only the durable start and rejected terminal events. The
host-side post-failure Podman check found no remaining container, but that
corroboration is kept separate from the immutable rejected event.

The v42 predicate and teardown completed, and the broader held-dirfd directory
manifest passed. Publication still refused because Cargo had made the final
`build-target/debug/scourge` output and its one deterministic private
`debug/build/scourge/d2b4a4cdecdcb55f/out/scourge` path two names for the same
inode. No other hard links, symlinks, special files, or writable files existed;
the immutable v42 event remains rejected and host Podman absence is separate
corroboration. The current isolated build handles only that exact Cargo pair:
it holds both names, requires the same owner/mode/dev/inode, `nlink=2`, exact
two-name in-tree alias inventory and byte digest, copies to an `O_EXCL`
same-directory `0500` temporary, fsyncs it, atomically replaces only the
primary output and fsyncs the parent. Both names must then be distinct
single-link inodes with the same bytes and exact safe modes. The build receipt
domain-binds the pre/post fstats, paths, digest and operation; its independent
verifier reopens both names and rechecks the final one-name inode inventories.
Every other hard-link topology remains a refusal.

V43 is the sole accepted event created before publication-pair fstats were
added to terminal v2 events. Compatibility is limited to `attempt=v43` and the
exact immutable accepted-event SHA-256
`bb0332149c7677873283672c9d4029b5aacb6d6a9e83e03f2bc10774a4234810`;
that event's previous digest binds its prepared/start chain, and readback still
reopens and proves the live two-link candidate/output topology and full
artifact graph. No other old or new event without a matching signed pair row
is admitted.

V44 is retained as a rejected timing witness, not acceptance evidence. Its
fixture produced the engine PID, then its old 45-second commit receive expired
at 45.336 seconds; the parent attempted `Commit` at 46.358 seconds and received
`EPIPE`. The exact fixture exit 1 and resulting `SIGCHLD` were correctly
refused, the v2 history has a rejected terminal event, no official receipt was
published, and independent Podman inspection found no remaining container.
The distinct `COMMIT_STAGE` contract above removes this scheduling race without
relaxing signal or child-exit reconciliation.

The driver exports that exact commit into a private source root. For every
crates.io package in `Cargo.lock`, it opens the sole cached `.crate` archive
without following links, requires the archive SHA-256 to equal the lockfile
checksum, retains those archive bytes, safely extracts only regular files and
directories into a private read-only vendor tree, and generates Cargo
directory-source checksums. A fresh private `CARGO_HOME` points only at that
vendor tree; the mutable registry source tree is never admitted. Cargo runs
with working directory `/`, an absolute private manifest path, and an asserted
absent `/.cargo`, so no checkout, home, or ancestor Cargo configuration joins
the trust root. The complete
Rust 1.100 toolchain/sysroot is pre-manifested, copied into a private read-only
tree, post-manifested, and invoked by private absolute cargo/rustc paths. The
offline locked build uses a fresh target, no incremental compiler or wrapper,
a minimal recorded environment, and a bounded exec trace whose pinned strace
executable is identity-checked before and after the build and whose private
toolchain, fresh-target build scripts and root-owned linker/assembler identities
are all retained and rehashed. The build exec trace is one file capped at
8 MiB, 10,000 lines and 5,000 successful execs. Cargo is bound to one job by
both `--jobs=1` and `CARGO_BUILD_JOBS=1`. The trace covers both `execve` and
`execveat` with exact `signal=none` and 250 ms `delay_exit` injection for both
exec syscalls. The injection changes timing only, never a syscall result. The
signed command, environment and independent verifier all bind those controls.
The parser exhaustively correlates same-line and PID-keyed unfinished/resumed
records, rejects malformed/unmatched/incomplete records and every successful
`execveat`, and refuses detached, signal, or any other out-of-grammar line. It
independently reparses the raw bytes before
settlement. Thus a
split record cannot hide a build script from the typed executable manifest.
Its domain-separated build
receipt binds source
export, Cargo inputs, archives/vendor, toolchain/sysroot, external executables,
complete logs, output fstat/digest and staged `0500` Scourge bytes into the
assignment and authenticated trace; callers cannot supply or relabel a Scourge
binary.

It uses the exact static supervisor and installed Codex 0.172, the historical
`6d15...` Teapot plus exact Investigation for the real protected-demo path,
and authenticates `c03...` only as the separate request-reference recovery
probe. There is no supported public Scourge authority binding for `c03`, so the
receipt must never describe it as a Scourge child. The successful compatibility
environment is a deterministic, networkless
`Debian-unstable-derived qualification fixture`: it starts from the pinned
official unstable image and overlays only the audited host glibc 2.44 runtime.
It is not stock-Debian or production-image parity. Stock bookworm and unstable
loader refusals are retained. Model and proxy upstreams are local Unix-socket
fakes; no provider, model, credential, or external network is used.
The trace HMAC is supplemented by a distinct evidence-binding HMAC over the
envelope digest, events digest, and complete sorted path/size/digest manifest
for every exported call and child-original artifact.
