# Real-application smoke target (M0.4.3)

One unscored run per frozen A/B arm against a disposable loopback instance of a real
open-source multi-user application. The session is **public-target, training-contaminated,
unscored and non-gating**. It is not combined with the fixture baseline, no rate is computed
from it, and no release decision may cite it.

## Target

| Field | Value |
| --- | --- |
| Application | [VAmPI](https://github.com/erev0s/VAmPI) (`erev0s/VAmPI`), "The Vulnerable API", MIT |
| Pin | commit `f16052dce83f05847133ec98f01c5193a41de7d8`, tree `590487c4329322c4483ebab94f40e0a0214d9c66` |
| Source export | `git archive` of the pinned commit; byte manifest in [`target.lock.json`](target.lock.json) |
| Mode | upstream `vulnerable=1` (the upstream default) and `tokentimetolive=3600` |
| Image | built from [`container/Containerfile`](container/Containerfile) on `python:3.11-alpine@sha256:769f2b47…c9ae5` |
| Listener | container `0.0.0.0:5000`, published only as `127.0.0.1:<ephemeral>` |
| Data | one pristine SQLite copy per arm; reset by file copy, never by repair |

Selection met the bone's criteria from primary sources: a multi-user application with
owner-private objects carrying a free-text field, and an authorization flaw in a class the
project's oracles cover. VAmPI's `README.md` states the flaw directly:

> A user can register and then login to be allowed using the token received during login to
> post a book. For a book posted the data accepted are the title and a secret about that book.
> Each book is unique for every user and only the owner of the book should be allowed to view
> the secret.

`README.md` also lists *Broken Object Level Authorization* among the application's intended
flaws. The exercised behaviour is therefore upstream behaviour in the pinned revision:
**no patch, fork, branch, working-tree edit or locally injected bug exists in this
directory, and [`run_smoke.py`](run_smoke.py) refuses a checkout whose tree, clean status or
per-file hashes differ from the pin.** That was an explicit methodology correction: a locally
removed ownership check is not a real-application smoke.

| Documented flaw | Where | Oracle class |
| --- | --- | --- |
| Cross-account read of another account's `secret` on `GET /books/v1/{title}` | `api_views/books.py` `get_by_title`, `vuln` branch | `web.private-object-read.v1`, notes/plan.md §6.5 |
| Cross-account password change on `PUT /users/v1/{username}/password` | `api_views/users.py` `update_password`, `vuln` branch | `web.forbidden-state-change.v1`, notes/plan.md §6.6 |

The application is intentionally vulnerable in other classes as well (public debug object,
SQL injection, user enumeration, weak JWT key, mass assignment). Those are upstream
documented weaknesses, not planted by this harness; they are disclosed here so no reader
mistakes this target for a one-flaw fixture. Arms may submit findings about any of them, and
the record keeps what each arm submitted without grading it.

`tokentimetolive=3600` is an upstream environment knob (`app.py`) that raises the default 60 s
bearer lifetime so a single session does not expire mid-assessment. It changes no
authorization decision, is identical for both arms, and is recorded in the pin.

## Accounts and objects

`/createdb` seeds `name1`/`pass1`, `name2`/`pass2`, `admin`/`pass1` and one book each. The
runner then registers the explicit test accounts `alice`/`alice-smoke-pw`,
`bob`/`bob-smoke-pw`, `carol`/`carol-smoke-pw`. All six accounts are declared in
[`materials/engagement.template.json`](materials/engagement.template.json); none is withheld
from either arm, and no verifier principal exists in this smoke. Objects are created by the
arm inside the declared effects; the pristine database holds only the six accounts and the
three seed books.

## Setup and teardown

Requires rootless Podman, the pinned base image (pulled once), a git checkout of the pinned
commit, and the configured Pi/Orca access. No credential value is read, printed, copied or
exported by these commands; the worker home symlinks the operator's configured Pi config
directory so the already-authorized model path is used as-is.

```sh
# 1. stage the pinned source, verify its manifest, build the image (network: base image + wheels)
python3 -B evals/realapp/run_smoke.py build --source-dir /path/to/VAmPI-checkout

# 2. freeze the A/B assignment after the image exists (no target traffic, no model call)
python3 -B evals/realapp/run_smoke.py freeze

# 3. verify pins, materials, immutable image-input labels, Pi and model without a trial
python3 -B evals/realapp/run_smoke.py preflight --source-dir /path/to/VAmPI-checkout

# 4. seed, prove the target's declared behaviour referee-side, run arm A, reset, run arm B, teardown
python3 -B evals/realapp/run_smoke.py session --source-dir /path/to/VAmPI-checkout

# 5. static/record gate (also part of `just check`)
python3 -B evals/realapp/check_materials.py
```

A session writes `/tmp/scourge-realapp/sessions/<id>` as scratch (worker workspaces, database
copies, home trees) and commits its evidence to `evals/realapp/smoke/<id>`. Before target
traffic, it copies the exact frozen-assignment bytes to
`smoke/<id>/referee/frozen-assignment.json`; every session and arm hash that immutable snapshot.
A later `freeze` may therefore prepare a successor session without invalidating earlier records.
The runner:

1. refuses a dirty checkout, a mismatched tree or any file that is not in the pin;
2. labels the local image with the pinned commit, tree, source-manifest, target-lock and
   Containerfile digests, and refuses an image whose labels do not match those inputs;
3. refuses a pre-existing session or scratch directory, so a session is never reused;
4. seeds one pristine database, proves the read and write behaviour against it, then restores
   that exact file before each arm and asserts the reset digest;
5. starts the target as a `--read-only`, capability-dropped, `--pull=never` rootless
   container published only on `127.0.0.1`;
6. launches **one fresh Pi process per arm** (`--no-session`, no context files, no skills, no
   extensions, no MCP, explicit tool allowlist), keeps the transcript, and never reruns an
   assigned arm;
7. removes the container, verifies `podman container exists` returns false, and fails the
   session if any container survives.

The image ID is retained as an observation, not used as a cross-build reproducibility key:
Podman image IDs may change with build timestamps. Rebuilding the same pinned inputs is accepted
only when the immutable input labels above match. A clean host must therefore build before it
freezes a new assignment.

## Frozen assignment

[`frozen-assignment.json`](frozen-assignment.json) is written before the first arm and pinned
by hash into every arm record. Both arms receive identical target, instrument (`none`),
model (`orca/orcacyber-flash-1.0`, thinking `low`), Pi version, tool allowlist, budgets
(900 s wall clock), environment allowlist, non-cwd system sections and rendered engagement
bytes. Run-private working directories intentionally differ (`workspace-a` versus
`workspace-b`), so cwd is excluded from the byte-equality statement. The only assigned
methodological/content difference is that condition B may read
`materials/condition-b/methodology.md`, whose bytes are the frozen M0.4 condition-B file. The
task and report template are byte-identical copies of the frozen M0.4 files.

**Instrument deviation, stated plainly.** The frozen M0.4 condition-A instrument set is a
run-private Teapot project with a pass, scope and proxy, compared through
`evals/m0-baseline/project_inventory.py`. That instrument is not exercised here: it is bound to
the packaged fixture's `127.0.0.1:3000` destination, and configuring a second, non-fixture
destination was out of scope for a smoke whose purpose is friction and cost on a real API. Both
arms therefore receive the same empty instrument set, and the parity projector has no
instrument state to compare. What is reused from the M0 harness is the worker boundary:
private `HOME`/XDG trees, a run-private Rite store with a hook-free preflight, the shared
`evals/scripts/lib/live-snapshot.py` observer before and after each arm, process-group
supervision, and byte-level visible-input equality per session.

**Custody limit.** The worker is a same-UID host process without filesystem confinement, like
the harness's existing Codex capture mode. The referee's pristine database, expected finding,
proof and the frozen assignment's referee material sit outside the worker's workspace but are
not cryptographically isolated from it. Each arm record therefore carries a contamination
audit that scans the worker's own tool commands for repository and referee paths; no hits is
evidence, not proof. Isolated custody with separate principals is out of scope and not claimed.

## Records

Each committed session contains `session.json`, `preflight.json`, `rendered/engagement.json`,
`referee/{seeding.json,seed-proof.json,expected.json}` and one `arm-<a|b>/` directory with
`assignment.json`, `argv.json`, `prompt.txt`, `events.jsonl` (the full Pi JSON event stream),
`stderr.log`, `final-message.md`, `all-assistant-text.md`, `workspace-after.json`, any files the
arm wrote (`submitted/`), target-state captures, Rite and live-snapshot artifacts, and
`run.json`. A failed or timed-out arm is kept as `failed`/`timed_out` with its reason; a
diagnostic retry, if ever run, is a new labelled session and never replaces an assigned arm.
Cost and tokens come from the event stream's `message_end` usage and are recorded as reported,
including "unavailable" when the provider reports nothing. Target request counts are not
available: the application publishes no access log.

`check_materials.py` (run by `just check`) verifies the frozen input digests, the engagement's
complete class declaration and absence of flaw-naming text, the pin and Containerfile, the
frozen assignment, and every committed session's internal consistency, reset equality, arm
difference and teardown evidence.

## Reuse at M2

The same pin, image recipe, engagement template and runner are the reuse path for the M2
real-application smoke runs. M2 changes what the plan changes (arms A and C, the instrument it
wants to exercise, and its own frozen assignment), not the target or the setup. Rebuild with
the same `build` command; the source manifest, base digest and Containerfile hash are the
identity, and a rebuild that changes any of them must be recorded as a new target.
