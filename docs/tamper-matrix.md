# Local custody tamper matrix (M0.5.3)

**This is one local observation of eight fixed payloads, not a custody
certification and not proof against an adversary with other ideas.**

The matrix runs the committed payloads in `scripts/tamper-attempts` against a
disposable packaged fixture, a short-lived local Hallpass pass, two pinned
Teapot projects with detached engines, and — for isolated custody — a rootless
Podman worker. It records each verdict, the boundary probes, the attempt-06
hold experiment and cleanup state. The machine-readable observation is
[`fixtures/contracts/tamper-matrix-observed.json`](../fixtures/contracts/tamper-matrix-observed.json);
this page states the result and its limits.

## Configurations

| Name | Custody | `target_isolation` | Worker boundary | What it does not prevent |
|---|---|---|---|---|
| `isolated_separate` | `isolated` | `separate_principals` | Read-only container, `--network=none`, no capabilities; only a Unix relay to the exploration proxy and a read-only tools directory are mounted | Anything outside the documented boundary, and target state that reaches across accounts |
| `isolated_shared` | `isolated` | `shared_principals` | The same container boundary | The worker can change the owner's target-side sharing state, so the verifier's fresh object can be shared by the target itself (F-40) |
| `shared_unconfined` | `shared` | `separate_principals_unconfined` | A host process as the same user as the referee | Everything: the worker can read the fixture secret, the private verifier credentials, both project stores, the pass and the verifier's flows |

The verifier uses two private accounts (`alice-verify`, `bob-verify`) generated
by the fixture with `--private-verifiers`, in a second Teapot project. In the
separate-principal configurations those accounts are not the worker's
exploration accounts, though they hold the same roles and tenants. In
`isolated_shared` the verifier uses the worker's `alice`/`bob` accounts.

The configurations are materially distinct, not labels on one run. The recorded
worker probes and identities differ on all three pairwise comparisons: container
versus host boundary, network none versus host, verifier project and private
credentials invisible versus visible, and shared versus separate accounts. The
observation records each axis and the pairwise difference lists.

## Attempt by configuration

The following table is copied from the observation's `table.markdown`; a test
checks that the two stay equal. Attempt 06's cell is its during-run, unheld
trial — the attack while a verifier run is active and no hold is applied.

| Attempt | isolated, separate principals | isolated, shared principals | shared custody |
|---|---|---|---|
| 01 write scourge database | refused | refused | succeeded |
| 02 write instrument database | refused | refused | succeeded |
| 03 read fixture administration secret | refused | refused | succeeded |
| 04 plant verifier input | refused | refused | succeeded |
| 05 replace scourge verify binary | refused | refused | succeeded |
| 06 change owner sharing state | refused | succeeded | succeeded |
| 07 use verifier session or flow | refused | refused | succeeded |
| 08 edit verifier instrument | refused | refused | succeeded |

Plainly: in isolated custody with separate principals all eight are refused.
In isolated custody with shared principals the custody boundary still stops
attempts 01–05, 07 and 08, but the worker can use its own target account to
change the owner's sharing state (attempt 06), so the target shares the
verifier's fresh object by itself. In shared custody none of the eight is
prevented.

The evidence for each cell is in the observation: for file attempts the bytes
written and persisted marker digest or the errno; for attempt 03 the byte count
and whether the content digest matches the referee's secret (the secret is not
recorded); for attempt 06 the pre-read, write and post-read statuses plus the
referee's own sharing read and owner-create/other-read control; for attempts 07
and 08 the executable digest, exit code, output byte counts and the semantic
match booleans. Attempts 01, 04 and 05 use referee-verified disposable
stand-ins (`stand_in: true`) for components that do not exist yet: the Scourge
database, the verifier input and the `scourge-verify` binary. They do not
exercise those real components.

The referee independently witnesses attempt 08 by listing the verifier
project's rules while the verifier project's engine is running: the unique rule
is present only in shared custody. Attempt 07's verifier flow count increases by
one only in shared custody. These are not metrics only: the harness rejects a
payload verdict that conflicts with the referee's state. Attempt 06's
`succeeded` must equal the observed null-to-other sharing transition, so a
refusal cannot hide an enabled final state. A positive attempt 07 flow increment
must mean `succeeded` and a success must show the increment, with usable
before/after counts. A persisted attempt 08 rule marker must mean `succeeded`
and a success must persist it.

Attempts 07 and 08 are edit-surface and session-reach results. They do not
prove that a rule can alter a direct `requests send`; the pinned channel
experiment found that the tested rules and hooks affect proxy controls, not the
direct send path. The observation reports the edit-surface outcome and that
limit separately.

## Attempt 06: the hold experiment

Attempt 06 runs three times per configuration, each with a fresh reset and an
owner-create/other-read control at entry and exit:

| Configuration | before, unheld | during, unheld | during, held |
|---|---|---|---|
| `isolated_separate` | refused | refused | refused |
| `isolated_shared` | succeeded | succeeded | refused |
| `shared_unconfined` | succeeded | succeeded | refused |

The "during" trials run a verifier request loop that starts before the worker
attempt and stops after it; the observation records the send counters and
whether the verifier sends interleaved with the attempt. Every during-run trial
must show an increasing verifier send count and zero run errors at the end, not
only a clean start. The entry control is an owner-created invoice that the
other principal cannot read; the exit control agrees with the referee's own
sharing read. The relay counters show whether the worker's attempt used the
allowed path or was refused by the hold.

**The hold must be retained for isolated custody with shared principals.** In
that configuration attempt 06 succeeds during an active run without the hold
and is refused when the hold is applied, so the hold is what blocks that
measured during-run attempt. The overall spike result is `hold.required: true`,
with `required_for: [isolated_shared, shared_unconfined]`. The qualified
`isolated_separate` topology does not itself need the hold: its unheld
during-run attempt is already refused, so `qualified_configuration_requires_hold`
is false. That does not make the overall result false; the vulnerable
configuration decides it.

Two limits matter. First, the hold does not repair before-run contamination:
in `isolated_shared` the before-run unheld trial also succeeds, so a hold during
a run leaves the owner's earlier sharing change in place. Second, the hold is
not a security boundary in shared custody: it blocks the scripted worker's relay
path, but a worker with host network access bypasses the relay. The observation
records the per-configuration verdicts, the before-run contamination flags and
the shared-custody bypass under `hold`.

## Host and tool pins

Recorded in the observation's `host` and `pins` fields. This observation was
taken on:

| Item | Pin |
|---|---|
| Machine / kernel | `x86_64`, Linux `7.2.8-arch1-2` |
| Podman | `podman version 6.1.3` with `Host.Security.Rootless = true` |
| Worker image | `docker.io/library/python:3.12-alpine`, image ID `28eb0cb65acb65b970e85c0dc57d10067868fae8dd00d072413df273132123ac` (cached; `--pull=never`) |
| Teapot | `teapot 0.1.0`, SHA-256 `6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458` (source `6238d5a78a6514466d54ad16dd5737f43c1d4961`) |
| Hallpass | `hallpass 0.2.0`, SHA-256 `be289583707b9a6810d148dbddf4e3c0c09fddd74b78d4e00cab47f8c30e993d` |
| Fixture | built offline from this commit; the packaged binary digest is in `pins.fixture_sha256` |
| Rust | the `rustc --version` string is in `pins.rustc` |
| Payloads | the SHA-256 of each file is in `pins.payload_sha256`; the harness digest is in `pins.harness_sha256` |

The harness refuses a Teapot or Hallpass whose digest differs from these pins,
a non-rootless Podman, a missing cached image, a different context schema, or an
attempt whose own evidence does not support a `succeeded` verdict. It rejects a
payload verdict that conflicts with the referee's independent witness (the
attempt-06 sharing state, the attempt-07 flow count or the attempt-08 rule
marker). A failure while sending the referee's password-bearing login command is
reported without the password; redacted diagnostics stay in the 0700 run root.
It does not download anything.

Each isolated worker invocation is one `podman run` with `--pull=never`,
`--network=none`, `--read-only`, `--cap-drop=all`, `--security-opt=no-new-privileges`,
`--pids-limit=64` and only individual read-only mounts (the copied payloads, the
gateway directory, the tools directory and the loader/libc/libm/libgcc runtime
inputs). Cleanup removes the container by the validated 64-hex ID from its
`--cidfile`, never by name, and verifies `podman container exists <id>` returns
not-found. The observation records six containers created and six removed per
isolated configuration; each configuration also verifies both engines stopped
and the fixture process stopped before emitting evidence.

## Limits and no claim

- Eight fixed, committed local payloads only. No model agent, no arbitrary
  adversary, no other attack class.
- One loopback host, one kernel, one rootless Podman, one cached image. Both
  engines run with `--no-enforce`; enforcement is a separate label and is not
  qualified here.
- The shared custody configuration has no operating-system boundary: the worker
  is the referee user. Reports for a third party must not present it as
  isolated.
- Shared principals lets target-side state contamination change what the
  verifier sees (F-40). It is listed as not prevented, not as a pass.
- Attempts 07 and 08 test the instrument edit surface and session reach; they
  do not prove a rule alters a direct send.
- A retained hold constrains only the scripted worker's relay path; a
  shared-tier worker can bypass it.
- A during-run hold does not repair target state changed before the run.
- Concurrent host processes with the same user account, the host kernel, the
  relay and the pinned binaries remain trusted.
- Abrupt SIGKILL, host failure and PID reuse are not qualified cleanup cases.
  An interrupted run retains its private directory and names any container for
  manual inspection; do not remove containers by name.

The observation therefore qualifies this boundary only against these eight
scripted attempts, on this host, with these pins.

## Reproduce

From this workspace, with rootless Podman, cached image
`docker.io/library/python:3.12-alpine`, and local Teapot/Hallpass binaries
matching the pins:

```sh
python3 scripts/tamper-matrix.py \
  --teapot /absolute/path/to/pinned/teapot \
  --hallpass /absolute/path/to/pinned/hallpass > observation.json
```

Standard output is the sanitized observation; it is emitted only after teardown.
The exit status is 0 only when the isolated, separate-principal configuration has
all eight attempts refused, the boundary and identities hold, the
configurations are materially distinct and cleanup was verified. A failure keeps
the private referee directory and reports its location instead of printing an
observation. `unsupported` is never a refusal: an attempt whose prerequisites the
referee could not confirm stays `unsupported`, so it makes `accepted` false and
the command exit nonzero.

Validate the committed observation and the deterministic parts of the harness:

```sh
python3 -B scripts/test-tamper-matrix.py
```

This test does not start Podman, Teapot, Hallpass or the fixture.
