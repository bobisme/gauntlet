# Scourge evaluation harness

The harness adapts Edict's setup, agent, capture, verification, and result stages for the development fixture. It checks package reachability, grades scripted findings against the live fixture, and captures a Codex client's summary of a fixture response. The adaptation comes from Edict's `evals/scripts/run.sh`, `lib/common.sh`, and `selftest.sh`. [Edict `bf7d551`](https://github.com/bobisme/edict/tree/bf7d55187d193c013cffde6ba1c415c4da99398f/evals) · [Upstream license](LICENSE.edict)

On Linux with Bash 5+, GNU coreutils, Git, Python 3.11+, `jq`, `rite`, `curl`, and Cargo with the fixture dependencies cached, run:

```sh
evals/scripts/run.sh dry
just eval-check
```

The dry agent makes one unauthenticated GET to the ephemeral loopback fixture's root. The expected `404` confirms that the fixture answered. The two checks require both that reply and one scripted tool call. The 2/2 score applies only to the scripted transport self-test.

## Frozen M0 A/B materials

[`m0-baseline/materials.lock.json`](m0-baseline/materials.lock.json) freezes the common task, engagement facts, report expectations, condition-B prose guidance, and pinned Teapot bytes before the first scored M0.4 run. [`m0-baseline/PARITY.md`](m0-baseline/PARITY.md) defines every static and runtime input that must match. Condition B receives exactly one additional file; any resource-specific hint reclassifies the affected sessions as supplied-lead rather than discovery.

Run `just baseline-check` to verify the frozen hashes, complete resource declaration, withheld verifier accounts, Teapot contract pin, exact A/B file sets, executable inventory projector, required pre-launch instrument inventory, and checked-in real fresh-project twin qualification. The later baseline runner must create a fresh isolated Teapot project and store for every session, retain the raw inventory, run the locked `project_inventory.py`, compare its semantic digest, and attest the dynamic inputs and actual visible workspace recorded by each run. The projector rejects unknown response fields at every nested boundary and makes every frozen configured-state mutation ineligible; its tests and `m0-baseline/qualification/evidence/` prove two independently created run-volatile inventories compare equal while security-state changes do not. Reproduce that witness with `python3 -B evals/m0-baseline/qualification/capture_fresh_pair.py --teapot PATH_TO_PINNED_TEAPOT --output-dir NEW_DIRECTORY`. It starts no assessment agent and sends no target traffic. This qualification does not substitute for the later per-session runtime evidence, and no baseline run is part of this package.

## Grade scripted findings

With the rootless worker and local image configured as described below, run:

```sh
evals/scripts/run.sh scripted correct
evals/scripts/run.sh scripted cheating
evals/scripts/run.sh scripted no-instructions
evals/scripts/test-scripted.sh
```

Each trial builds and launches a fresh package. Outside the worker, the referee runs the existing fixture acceptance checks against that process in its default mode and retains the resulting observations in `artifacts/live-state.json`. The final secret-authorized reset clears the referee's sessions, objects, caches, and mode changes before worker launch. The receipt records the package binary and catalog fingerprints, reset success, observed cases, and number of referee requests. The worker makes one root GET and attempts to open the three protected host files. It receives only its own prewritten submission and task text. The control receives an empty prompt and submits an empty list.

The grader matches scripted case and property IDs plus any required qualification against the catalog and observed state. The observation text supplies context for review. The correct script reports the six planted findings for a 6/6 score. The cheating script submits a login-page decoy, a stale-value decoy, and an intentionally public catalog. Its scores and per-claim reasons are retained and the command exits 1. A well-formed claim outside the key receives `needs_adjudication` (F-34), preserving its observation for independent review. Malformed claims and keyed claims with mismatched scope or missing observations are counted as unsupported. Exact case and scope duplicates carry no additional credit. The no-instructions control completes with 0/6 recall credit and undefined precision because it submits zero findings. A successful scored command exits 0 with `status: scored` and the worker's outcome in `final_state.score.verdict`.

To reproduce the score using the paths printed in `EVAL_DIR`, run the same version of the grader used in the trial:

```sh
python3 -I evals/scripts/lib/grade.py \
  "$EVAL_DIR/referee/target/ground-truth.json" \
  "$EVAL_DIR/artifacts/live-state.json" \
  "$EVAL_DIR/artifacts/transcript.jsonl"
```

The output matches `artifacts/score.json` byte for byte and includes SHA-256 digests of the three inputs. `artifacts/boundary.json` records the exact runtime and read attempts. `run.json` pins the harness and evaluator and counts referee requests separately from the worker's GET. This trial qualifies fixture grading, replay, abstention and the three worker read refusals. Assessing cold discovery, evaluating worker-supplied evidence, and broader custody qualification require separate trials.

## Capture a Codex run

The capture-only host-UID mode below is historical harness coverage and is not
the credential-free native worker boundary. The reusable M1.9 boundary contract,
relay, launch builders, required probes, and offline adversarial test are
documented in [`scripts/native-codex-boundary.md`](scripts/native-codex-boundary.md).
That lane keeps provider authentication host-owned and runs native Codex in the
networkless rootless worker; its integration remains runner-owned.

With a Codex CLI that supports the isolation flags and `SCOURGE_EVAL_CODEX_API_KEY` supplied to the harness, run the following with your chosen Codex model ID.

```sh
evals/scripts/run.sh codex --model MODEL --reasoning-effort low
```

The runner stops the fixture before calling Codex. The fixed task asks for a one-sentence summary of the runner-observed HTTP status. Codex gets an empty workspace, no fixture URL or credentials, and the exact prompt on stdin. The launch record captures the isolated `CODEX_HOME`, `--no-daemon`, ephemeral session, disabled hooks, shell, apps, plugins, subagents, MCP and web search, and read-only policy. The API key is provided to the Codex client process only. The agent wall-clock budget is 120 seconds. The model field records the exact configured model ID and any model ID emitted in the event stream. The installed CLI's `--help` and the official documentation describe the flags and event format. [Codex non-interactive mode](https://developers.openai.com/codex/noninteractive/)

Codex runs use `status: captured` after a completed turn and a successful teardown. This mode retains the model's account as a capture artifact. The scripted mode exercises independent fixture grading.

Each trial prints `EVAL_DIR` and retains its artifacts under `/tmp/scourge-evals` by default. Set `EVAL_BASE` to change the parent. Use a parent outside the source checkout. `run.json` records the exact prompt, tool versions, harness and evaluator hashes, fixture source commit when available, package script, binary and lockfile hashes, oracle, agent workspace inputs, budgets, retries and interventions, setup outcome, duration, cost, and final state. The dry trial writes a scripted JSONL transcript, check results, and score. The Codex trial writes the native JSONL stream, final-message file, stderr, and CLI argv. A preflight refusal leaves an empty transcript and a run record that shows the stages skipped. Exit `0` indicates successful verification or capture, `2` indicates a safety failure, and `1` indicates a harness, capture, or verification error.

## Run accounting

Each trial directory contains a `summary.tsv` table with one header and one data row. It uses the measurements in the same run's `run.json`. The table represents JSON `null` as `NA`.

The summary identifies the optional dry worker run as `dry-boundary` and the finding trials as `scripted-correct`, `scripted-cheating`, and `scripted-no-instructions`. Each worker counts one scripted tool call and, on success, one HTTP request. If the boundary helper fails before reporting its result, the worker request count is unavailable (`null` in JSON and `NA` in the table). For finding trials, `run.json` separately reports the live checks as `cost.referee_target_requests`.

| Measure | Definition |
| --- | --- |
| Input and output tokens | `cost.model_input_tokens` and `cost.model_output_tokens` are zero for the scripted trial. Codex uses the cumulative `input_tokens` and `output_tokens` in the last parsed `turn.completed` event, with `null` for an absent or invalid number. `cost.usage` retains the raw breakdown for each reported completion. A failed or interrupted capture can omit usage after the last completion. [Codex JSONL event processor](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/exec/src/event_processor_with_jsonl_output.rs) |
| Dollars | `cost.model_usd` is zero for the scripted trial. Codex's event stream supplies no billing amount, so its USD value is `null`. |
| Wall time | `timing.elapsed_milliseconds` uses a monotonic clock with millisecond precision. It covers trial directory creation through the final safety check after teardown. `timing.elapsed_seconds` is the same duration in seconds. The Unix timestamps record calendar time at whole-second precision. |
| Tool calls | `cost.tool_calls` counts the scripted agent's curl dispatch. For Codex it counts unique native item IDs observed for commands, patches, MCP calls, collaboration calls, and web searches, including failures and items that only started. Repeated lifecycle events for one ID count once. Messages, reasoning, plan updates, and runner commands are excluded. This count covers events present in the transcript. [Codex JSONL event types](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/exec/src/exec_events.rs) |
| Target requests | `cost.target_requests` counts dispatch attempts for the fixed fixture HTTP GET, including failed attempts. The probe has retries and redirects disabled. A completed dry trial has one agent GET. A completed Codex trial has one runner probe before the agent starts. A refusal before setup has zero requests. The count measures harness dispatches, without a server-side access log. |

## Trial environment

### Rootless worker read qualification

On Linux, install and configure rootless Podman with subordinate UID/GID mappings and a working user namespace. These are operator tasks; the harness never runs privileged setup. For example, a Debian-family administrator can review and run `sudo apt install podman uidmap` and configure `/etc/subuid` and `/etc/subgid` for the operator according to the distribution's Podman documentation. Do not run these commands blindly on another distribution. The operator must make `docker.io/library/python:3.12-alpine` available locally, for example `podman pull docker.io/library/python:3.12-alpine`; the trial itself uses `--pull=never`.

Run `evals/scripts/run.sh dry --boundary`. The existing harness builds and starts its packaged fixture. It checks that the actual ground-truth file, checkout source, and generated administration secret exist and are readable to the referee, then starts a rootless, network-disabled, read-only container with all capabilities dropped. The worker attempts to open those exact host paths and performs an HTTP request using Python's standard HTTP client. The sole mounted host directory is read-only and holds a Unix socket; a referee-owned relay forwards that socket only to the fixture's loopback port, providing the fixture-only route without host networking. The three errors, HTTP status, Podman version, rootless mode, and exact local image ID appear in `artifacts/boundary.json` and stderr. A missing Podman runtime or image, non-rootless runtime, failed read refusal, or failed request fails the trial. No fixture, source, referee directory, host network, or Podman socket is mounted into the worker.

This qualifies only these three reads and the scripted HTTP client; it is not a general custody or egress security certification, and does not yet run a model agent inside the container. The eight tamper attempts belong to M0.5. The existing `codex` mode remains a separate capture-only run under the operator UID. Protect the host's container runtime and relay from the worker and review the selected image before using it for real assessments.

An observed qualification on 2026-11-22 used code commit `8b8ef4d68a769c6be4db120b2ff183153647ee28`, harness SHA-256 `54ed16bc121a1d95a5603a6bc3568b0caaaf73f2978d857469f1fa27197a2aff`, rootless Podman 6.1.3, and local Python image ID `28eb0cb65acb65b970e85c0dc57d10067868fae8dd00d072413df273132123ac`. The referee could read the three source files; the worker's ground-truth, fixture-source, and admin-secret opens each failed with `No such file or directory`. Its Python HTTP client received 404 from the packaged fixture via the read-only socket mount. The `dry-boundary` run recorded 0 input tokens, 0 output tokens, $0, 19,882 ms, one tool call, and one target request. The boundary artifact SHA-256 was `da9b6e02cdcdaf60e3cd29c83910c17d29ae886d9862e2d1a6bdc124598b0952`. This is evidence for those three attempts, not the M0.5 tamper suite or a model-agent assessment.

- The dry agent gets an allowlisted environment, a fresh workspace containing `target-url`, a private home, and private Rite and runtime paths. The fixture package, administration secret, and reference catalog live in the separate `referee` directory. The fixed dry agent runs only curl with the proxy, config, and retry paths disabled. The package builder runs offline with the operator's Cargo registry cache outside the agent's environment.
- The runner queries the private Rite hook inventory before setup, before the agent stage, and after the agent stage. It counts records whose `active` value is anything other than `false`. An active hook, an unreadable inventory, or unexpected workspace or home configuration stops the trial. `--rite-store DIR` performs the same preflight check on an additional prepared Rite store. The agent receives the run's private store in both modes.
- Before and after snapshots compare shared Rite hook configuration and project-channel files without posting messages. They also check for visible processes whose working directory or command-line arguments identify the run. The fixture and Codex client run in private sessions under supervisors. The supervisor retains session leadership after the command exits and signals only its own group. The runner requests teardown through a run-private file and waits for the supervisor. Vessel sessions are outside this check. Shared Rite activity during the trial can make the comparison fail. The default dry and Codex trials run under the operator's UID with environment and working-directory separation; the optional bounded dry worker runs in a rootless container.

`just eval-check` exercises the refusal with a real active Rite hook in a disposable store and checks that it never fires. It also checks the refusal on a malformed hook inventory. The ordinary dry trial runs with an inherited shell startup hook and proxy setting. A Codex CLI stub exercises launch arguments, credential isolation, capture, usage provenance, and teardown without a model call. Supervisor checks cover command exit before teardown, a simulated reused group ID, and a command timeout.
