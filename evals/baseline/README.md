# M0.4 baseline runner (bn-1or)

This directory runs the frozen M0.4.2 experiment. It does not design a new one,
and it does not decide the M0 question.

- Frozen inputs: [`../m0-baseline/materials.lock.json`](../m0-baseline/materials.lock.json),
  [`../m0-baseline/PARITY.md`](../m0-baseline/PARITY.md),
  [`../m0-decision-rule.md`](../m0-decision-rule.md).
- Assignment: [`schedule.json`](schedule.json), generated from a recorded seed
  before the first scored model call.
- Runs: [`evidence/ledger.jsonl`](evidence/ledger.jsonl) plus one directory per
  assigned position under [`evidence/`](evidence/).
- One labelled, **unscored** pilot under [`pilot/`](pilot/) validates the runner.
  It is not part of the schedule, the ledger or the decision rule.

## Model and settings

Every scored session is a fresh Pi process, not a resumed session:

| Setting | Value |
| --- | --- |
| Provider | `orcacyber` |
| Model ID | `orca/orcacyber-flash-1.0` |
| Thinking level | `high` |
| Tools | `bash` only |
| Extensions, MCP, skills, context files, prompt templates | disabled |
| Agent retry | disabled in the run-private `settings.json` |
| Wall budget | 900 s |
| Prompt | the bytes of the frozen `common/task.txt` |

The condition-B arm additionally receives the frozen
`condition-b/methodology.md` at the same relative path in its workspace. Nothing
else differs between arms.

## Worker boundary

The whole Pi process runs inside rootless Podman:

- `--network=none`, `--read-only`, `--cap-drop=all`,
  `--security-opt=no-new-privileges`, `--http-proxy=false`, `--pull=never`;
- image `docker.io/library/debian:13-slim` by local image ID, recorded per run;
- no host loopback, no Podman socket, no source checkout, no fixture package, no
  ground truth, no administration secret, no verifier receipts, no scorer.

Two referee-owned Unix-socket relays are mounted read-only at `/gateway` and
exposed on worker loopback by `worker/forward.js`:

| Relay | Worker sees | Host relay can reach |
| --- | --- | --- |
| `proxy.sock` | `127.0.0.1:<Teapot proxy port>` | the pinned Teapot proxy listener only |
| `model.sock` | `CONNECT 127.0.0.1:18080` | `api.orcarouter.ai:443` only, as a raw byte tunnel |

The model relay performs no TLS termination and reads no credential: the Pi
process does its own TLS through the tunnel, using the configured Pi auth file.
The runner never reads, prints or copies a credential value. The auth file is
bind-mounted read-only at `/pi-agent/auth.json` for the model client; it is not
part of the target, referee or scoring secret set. The assessed shell does not
inherit the model transport proxy (`worker/bin/bash` unsets it).

This is an extension of the documented scripted-worker boundary: the scripted
qualification runs a fixture-only HTTP client in `python:3.12-alpine`; a model
agent needs Pi, Node, Teapot, curl and jq, so the model-worker image and the
model tunnel are additional. It is **not** the M0.5 custody qualification and it
does not certify egress, tamper resistance, concurrent activity or prompt
injection.

The worker's Teapot project store is mounted read-write because the native
instrument's CLI and engine are the treatment under test. That is shared
custody; M0.5 owns tamper measurement. The target itself is never reachable
directly: the only route is the Teapot proxy, whose pass allow-list is
`127.0.0.1:3000` and whose scope is `127.0.0.1`.

## Per-session order

1. Create a new run-private root. Every project, store, HOME, XDG directory,
   approval copy and workspace is new; a pre-existing path stops the run.
2. `projects init`, attach the frozen approval, add scope `127.0.0.1`, start a
   regular-mode proxy with `--no-enforce`, and capture all 24 inventory
   commands.
3. Project the raw inventory with the locked
   [`project_inventory.py`](../m0-baseline/project_inventory.py). Require
   `prelaunch.eligible` and a semantic digest equal to the frozen qualification
   digest `05aab34cb8c97a930ee7abd86224299ad0e1198e5c9f33910b1aeb5b25a083cd`.
4. Copy the frozen common inputs; for condition B only, add the frozen
   methodology. Record every visible input name and SHA-256.
5. Start a fresh fixture process on `127.0.0.1:3000` and run the existing
   referee acceptance checks, which end with the secret-authorized reset. Retain
   the receipt.
6. Launch the worker. Reset the fixture between runs by process replacement plus
   the referee reset; no fixture state is reused.
7. Retain the transcript, stderr, final message, agent-written workspace files,
   post-run instrument state, cost and timing, then tear down the container,
   relays, proxy (verified `running: false`) and fixture.

Every failure, timeout, zero-output and infrastructure failure is appended to
the ledger. An assigned run is never silently repeated. If a methodologically
necessary retry is added later it must be a new, explicitly labelled trial.

## Ledger and scoring

`evidence/ledger.jsonl` has ten immutable run objects, one per assigned schedule
position, with the assigned arm, exact model, pins, parity digest, fixture
receipt, transcript hash, tool-call count, tokens/cost, wall time, instrument
state, report hashes, cleanup result and status. Raw transcripts are committed
gzip-compressed; the run object records the SHA-256 of the decompressed bytes.

Nine run objects carry `score.status: pending_adjudication`. Position 5 ended
with `EDQUOT` before that placeholder could be written, so the ledger has one
typed append-only `score_amendment` bound to the exact original position-5 line
hash. It records `not_adjudicable_infrastructure_failure` without inferring a
claim score or unsupported-claim count. The original ten run lines and their
`run.json` files were not rewritten. Claim-level adjudication still belongs to
M0.4.4 (`bn-93a`); this runner records inputs and mechanical dispositions only.

## Required limitations

- Ten sessions are a small sample. They choose what to build; they support no
  claim about how often agents are wrong.
- One model, one host, one fixture, one prompt and one run per assigned position.
- The development fixture is visible to the implementing agent and documents its
  own planted flaw; a result here is not a held-out evaluation.
- The pilot is unscored and must not be counted in the denominator.

## Current status: all ten attempted, inconclusive (2026-11-23)

All ten assigned positions are committed in `evidence/ledger.jsonl`. Six
completed cleanly (`pos-03-a`, `pos-06-a`, `pos-07-a`, `pos-08-b`, `pos-09-a`,
`pos-10-b`); three ended with container exit 126 and truncated transcripts
(`pos-01-a`, `pos-02-b`, `pos-04-b`); one ended with a host `EDQUOT`
(`pos-05-b`). The preregistered rule needs ten valid sessions, so the result is
**inconclusive**. No failed position was retried or replaced. See
[`RESULT.md`](RESULT.md) for exact counts and costs, and
[`PAUSE-NOTES.md`](PAUSE-NOTES.md) for the diagnosis and collection history.

Positions 1–5 used `/tmp/scourge-evals`; positions 6–10 used `/home/bob/m0e` on
ext4 because `/tmp` produced `EDQUOT`. This is a host-filesystem collection
change only; materials, model, prompt, boundary, schedule and scoring were
unchanged.

`evidence/<position>/workspace-supplement/` carries nested agent files that the
first copy omitted, hashed separately without editing the original records.
`qualification/qualification-2` is a separately labelled, unscored collection
qualification that reached `agent_settled` with run roots on ext4; it is not a
condition A/B session and is not in the ledger or the decision-rule denominator.
`qualification/qualification-1` is a retained aborted qualification (base path
too long for the Teapot control socket).

`run_baseline.py verify` now requires exact ledger-to-`run.json` equality,
checks every `SHA256SUMS.json` entry and every supplementary hash, validates
typed score amendments, requires score coverage for all ten runs, and reports
the valid-session count. `run_baseline.py qualify` runs the unscored
qualification; `supplement_evidence.py` preserves nested workspace files.

## Evidence copy safety

`copy_evidence` now copies every regular file under `workspace/` recursively,
retains its relative path in the evidence tree, and records each SHA-256 in
`SHA256SUMS.json`. It does not follow symlinks, does not read or copy their
targets, and refuses a workspace, evidence target or destination component that
is a symlink or escapes its root. Source files with `st_nlink != 1` are treated
as hardlink escapes and skipped; every open is re-checked with `fstat` for
`S_ISREG` and `st_nlink == 1` before a byte is read. Skipped symlinks, special files and the
`.teapot` store are listed in `workspace-skipped.json` by relative path only.
`supplement_evidence.py` uses the same walker. `verify` resolves every manifest
and supplement name through the same no-escape, no-symlink join and rejects
unsafe paths instead of reading them. `test_evidence_paths.py` proves nested
retention, hashing, skipped escaping symlinks, traversal rejection, the
runner's `copy_evidence` and the supplement script. `just check` runs it.
