# Scourge evaluation harness

The harness adapts Edict's setup, agent, capture, verification, and result stages for the development fixture. Its scripted trial checks the package and transport. Its Codex trial captures a real client's summary of a fixture response. The adaptation comes from Edict's `evals/scripts/run.sh`, `lib/common.sh`, and `selftest.sh`. [Edict `bf7d551`](https://github.com/bobisme/edict/tree/bf7d55187d193c013cffde6ba1c415c4da99398f/evals) · [Upstream license](LICENSE.edict)

On Linux with Bash 5+, GNU coreutils, Git, Python 3.11+, `jq`, `rite`, `curl`, and Cargo with the fixture dependencies cached, run:

```sh
evals/scripts/run.sh dry
just eval-check
```

The dry agent makes one unauthenticated GET to the ephemeral loopback fixture's root. The expected `404` confirms that the fixture answered. The two checks require both that reply and one scripted tool call. The 2/2 score applies only to the scripted transport self-test.

## Capture a Codex run

With a Codex CLI that supports the isolation flags and `SCOURGE_EVAL_CODEX_API_KEY` supplied to the harness, run the following with your chosen Codex model ID.

```sh
evals/scripts/run.sh codex --model MODEL --reasoning-effort low
```

The runner stops the fixture before calling Codex. The fixed task asks for a one-sentence summary of the runner-observed HTTP status. Codex gets an empty workspace, no fixture URL or credentials, and the exact prompt on stdin. The launch record captures the isolated `CODEX_HOME`, `--no-daemon`, ephemeral session, disabled hooks, shell, apps, plugins, subagents, MCP and web search, and read-only policy. The API key is provided to the Codex client process only. The agent wall-clock budget is 120 seconds. The model field records the exact configured model ID and any model ID emitted in the event stream. The installed CLI's `--help` and the official documentation describe the flags and event format. [Codex non-interactive mode](https://developers.openai.com/codex/noninteractive/)

Codex runs use `status: captured` after a completed turn and a successful teardown. Scoring is disabled for Codex mode. The transcript is the model's account and independent state grading remains with `bn-2nt`, including the correct and cheating scripted cases and the no-instructions control. Cold-model assessment and OS-level custody remain separate qualification gates.

Each trial prints `EVAL_DIR` and retains its artifacts under `/tmp/scourge-evals` by default. Set `EVAL_BASE` to change the parent. Use a parent outside the source checkout. `run.json` records the exact prompt, tool versions, harness and evaluator hashes, fixture source commit when available, package script, binary and lockfile hashes, oracle, agent workspace inputs, budgets, retries and interventions, setup outcome, duration, cost, and final state. The dry trial writes a scripted JSONL transcript, check results, and score. The Codex trial writes the native JSONL stream, final-message file, stderr, and CLI argv. A preflight refusal leaves an empty transcript and a run record that shows the stages skipped. Exit `0` indicates successful verification or capture, `2` indicates a safety failure, and `1` indicates a harness, capture, or verification error.

## Run accounting

Each trial directory contains a `summary.tsv` table with one header and one data row. It uses the measurements in the same run's `run.json`. The table represents JSON `null` as `NA`.

| Measure | Definition |
| --- | --- |
| Input and output tokens | `cost.model_input_tokens` and `cost.model_output_tokens` are zero for the scripted trial. Codex uses the cumulative `input_tokens` and `output_tokens` in the last parsed `turn.completed` event, with `null` for an absent or invalid number. `cost.usage` retains the raw breakdown for each reported completion. A failed or interrupted capture can omit usage after the last completion. [Codex JSONL event processor](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/exec/src/event_processor_with_jsonl_output.rs) |
| Dollars | `cost.model_usd` is zero for the scripted trial. Codex's event stream supplies no billing amount, so its USD value is `null`. |
| Wall time | `timing.elapsed_milliseconds` uses a monotonic clock with millisecond precision. It covers trial directory creation through the final safety check after teardown. `timing.elapsed_seconds` is the same duration in seconds. The Unix timestamps record calendar time at whole-second precision. |
| Tool calls | `cost.tool_calls` counts the scripted agent's curl dispatch. For Codex it counts unique native item IDs observed for commands, patches, MCP calls, collaboration calls, and web searches, including failures and items that only started. Repeated lifecycle events for one ID count once. Messages, reasoning, plan updates, and runner commands are excluded. This count covers events present in the transcript. [Codex JSONL event types](https://github.com/openai/codex/blob/rust-v0.171.0/codex-rs/exec/src/exec_events.rs) |
| Target requests | `cost.target_requests` counts dispatch attempts for the fixed fixture HTTP GET, including failed attempts. The probe has retries and redirects disabled. A completed dry trial has one agent GET. A completed Codex trial has one runner probe before the agent starts. A refusal before setup has zero requests. The count measures harness dispatches, without a server-side access log. |

## Trial environment

- The dry agent gets an allowlisted environment, a fresh workspace containing `target-url`, a private home, and private Rite and runtime paths. The fixture package, administration secret, and reference catalog live in the separate `referee` directory. The fixed dry agent runs only curl with the proxy, config, and retry paths disabled. The package builder runs offline with the operator's Cargo registry cache outside the agent's environment.
- The runner queries the private Rite hook inventory before setup, before the agent stage, and after the agent stage. It counts records whose `active` value is anything other than `false`. An active hook, an unreadable inventory, or unexpected workspace or home configuration stops the trial. `--rite-store DIR` performs the same preflight check on an additional prepared Rite store. The agent receives the run's private store in both modes.
- Before and after snapshots compare shared Rite hook configuration and project-channel files without posting messages. They also check for visible processes whose working directory or command-line arguments identify the run. Each worker runs in a private session under a supervisor. The supervisor retains session leadership after the command exits and signals only its own group. The runner requests teardown through a run-private file and waits for the supervisor. Vessel sessions are outside this check. Shared Rite activity during the trial can make the comparison fail. Both trials run under the operator's UID with environment and working-directory separation.

`just eval-check` exercises the refusal with a real active Rite hook in a disposable store and checks that it never fires. It also checks the refusal on a malformed hook inventory. The ordinary dry trial runs with an inherited shell startup hook and proxy setting. A Codex CLI stub exercises launch arguments, credential isolation, capture, usage provenance, and teardown without a model call. Supervisor checks cover command exit before teardown, a simulated reused group ID, and a command timeout.
