#!/bin/bash -p
# Adapted from Edict evals/scripts/run.sh and selftest.sh. See ../LICENSE.edict.
set -euo pipefail
umask 077
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/codex-agent.sh
source "$SCRIPT_DIR/lib/codex-agent.sh"

usage() {
  printf '%s\n' 'Usage: evals/scripts/run.sh dry [--rite-store DIR]' \
    '       evals/scripts/run.sh dry --boundary [--rite-store DIR]' \
    '       evals/scripts/run.sh codex --model MODEL [--reasoning-effort low|medium|high] [--rite-store DIR]' \
    'Dry runs the scripted fixture reachability trial. Codex captures a fixture-status summary.' \
    'Set SCOURGE_EVAL_CODEX_API_KEY for Codex. EVAL_BASE selects the artifact parent.' \
    '--rite-store checks an additional prepared Rite store before setup.'
}

if [[ ${1:-} == --help ]]; then usage; exit 0; fi
mode=${1:-}
if [[ $mode != dry && $mode != codex ]]; then usage >&2; exit 1; fi
shift
prepared_rite=
boundary=false
CODEX_MODEL=
REASONING_EFFORT=low
CODEX_TIMEOUT=120
export -n SCOURGE_EVAL_CODEX_API_KEY
while (($#)); do
  if [[ $1 == --boundary && $mode == dry ]]; then boundary=true; shift; continue; fi
  if [[ $# -lt 2 || -z $2 ]]; then usage >&2; exit 1; fi
  case "$1" in
    --rite-store) prepared_rite=$2 ;;
    --model) [[ $mode == codex ]] || die '--model requires codex mode'; CODEX_MODEL=$2 ;;
    --reasoning-effort) [[ $mode == codex ]] || die '--reasoning-effort requires codex mode'; REASONING_EFFORT=$2 ;;
    *) usage >&2; exit 1 ;;
  esac
  shift 2
done
if [[ $mode == codex ]]; then
  [[ $CODEX_MODEL =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] || die 'codex mode requires a model ID via --model'
  case "$REASONING_EFFORT" in low|medium|high) ;; *) die 'expected --reasoning-effort low, medium, or high' ;; esac
fi

PYTHON_BIN=$(command -v python3)
RITE_BIN=$(command -v rite)
CURL_BIN=$(command -v curl)
CARGO_BIN=$(command -v cargo)
if command -v rustup >/dev/null && toolchain_cargo=$(rustup which cargo 2>/dev/null); then
  CARGO_BIN=$toolchain_cargo
fi
CARGO_PATH=$(dirname "$CARGO_BIN"):/usr/bin:/bin
for tool in git jq sha256sum awk timeout; do command -v "$tool" >/dev/null || die "missing $tool"; done

HOST_DEFAULT_RITE=${XDG_DATA_HOME:-$HOME/.local/share}/rite
HOST_EFFECTIVE_RITE=${RITE_DATA_DIR:-$HOST_DEFAULT_RITE}
operator_registry=${CARGO_HOME:-$HOME/.cargo}/registry
monotonic_ms() { "$PYTHON_BIN" -I -c 'import time; print(time.monotonic_ns() // 1_000_000)'; }

started=$EPOCHSECONDS
started_ms=$(monotonic_ms)
EVAL_DIR=$(eval_new_dir "$mode")
ART=$EVAL_DIR/artifacts
PROJECT_DIR=$EVAL_DIR/workspace
CHECKS=$ART/checks.tsv
sbx_write_env "$EVAL_DIR"
sbx_load "$EVAL_DIR"
transcript=$ART/transcript.jsonl
: >"$transcript"
if [[ $mode == dry ]]; then
  printf '%s\n' 'Confirm the local service responds to an HTTP GET at its root. Record the status code.' >"$EVAL_DIR/prompt.txt"
else
  : >"$EVAL_DIR/prompt.txt"
fi
printf '%s\n' '{}' >"$ART/tools.json"
printf '%s\n' 'null' >"$ART/score.json"
printf '%s\n' '{"provider_reported_model":null,"usage":[],"completed_turns":0}' >"$ART/agent-summary.json"
printf 'EVAL_DIR=%s\n' "$EVAL_DIR"

package_limit=300
request_limit=5
target_requests=0
tool_calls=0
agent_exit=null
agent_pid=
agent_stopped=null
http_status=
fixture_pid=
fixture_url=
fixture_version=
fixture_hash=
fixture_started=false
fixture_stopped=null
agent_started=false
safety_snapshot=false
safety_ok=null
reason=

fingerprint() { sha256sum -- "$1" | cut -d ' ' -f1; }
harness_version=$(
  cd "$SCRIPT_DIR"
  sha256sum run.sh lib/boundary.py lib/common.sh lib/live-snapshot.py lib/codex-agent.sh lib/codex-launch.py lib/supervise.py | sha256sum | cut -d ' ' -f1
)
evaluator_version=$harness_version
lock_hash=$(fingerprint "$EVAL_REPO_DIR/Cargo.lock")
package_hash=$(fingerprint "$EVAL_REPO_DIR/fixtures/target/package.py")
source_commit=$(sbx git -C "$EVAL_REPO_DIR" rev-parse --verify HEAD 2>/dev/null || true)

write_run_summary() {
  jq -r '
    ["mode", "status", "model_input_tokens", "model_output_tokens", "model_usd", "wall_ms", "tool_calls", "target_requests"],
    [(if .environment_setup.worker_boundary then "dry-boundary" else .mode end), .status,
      (.cost.model_input_tokens // "NA"), (.cost.model_output_tokens // "NA"),
      (.cost.model_usd // "NA"), .timing.elapsed_milliseconds, (.cost.tool_calls // "NA"), (.cost.target_requests // "NA")]
    | @tsv' "$EVAL_DIR/run.json.tmp" >"$EVAL_DIR/summary.tsv.tmp"
}

finish() {
  local rc=$1 status=failed ended_ms
  trap - EXIT INT TERM
  set +e
  if [[ -n "$agent_pid" ]]; then
    agent_stopped=true
    if ! stop_process_group "$ART/agent" "$agent_pid"; then
      agent_stopped=false
      reason='agent process group remained after teardown'
      rc=2
    fi
    if ! codex_capture; then
      reason="${reason:+$reason. }Could not summarize Codex events"
      if ((rc == 0)); then rc=1; fi
    fi
    if ((rc == 0)) && ! jq -e '.completed_turns > 0' "$ART/agent-summary.json" >/dev/null; then
      reason='Codex event capture contains no completed turn'
      rc=1
    fi
  fi
  if [[ -n "$fixture_pid" ]]; then
    fixture_stopped=true
    if ! stop_process_group "$ART/fixture" "$fixture_pid"; then
      fixture_stopped=false
      reason='fixture process group remained after teardown'
      rc=2
    fi
  fi
  if [[ $safety_snapshot == true ]]; then
    if live_compare; then
      safety_ok=true
    else
      safety_ok=false
      reason="${reason:+$reason. }Live safety snapshot changed or was unavailable"
      rc=2
    fi
  fi
  if ((rc == 0)); then
    if [[ $mode == dry ]]; then status=passed; else status=captured; fi
  fi
  if ((rc == 2)) && [[ $fixture_started == false ]]; then status=refused; fi
  if ((rc == 2)) && [[ $fixture_started == true ]]; then status=safety_failed; fi
  if ((rc != 0)) && [[ -z $reason ]]; then reason='trial failed before verification completed'; fi

  if ! ended_ms=$(monotonic_ms); then
    printf '%s\n' 'FATAL: could not measure elapsed trial time' >&2
    exit 1
  fi

  if ! jq -n \
    --arg status "$status" --arg reason "$reason" --arg harness "$harness_version" \
    --arg mode "$mode" --arg model "$CODEX_MODEL" --arg effort "$REASONING_EFFORT" \
    --arg evaluator "$evaluator_version" --arg pack "$fixture_hash" --arg fixture_version "$fixture_version" \
    --arg source_commit "$source_commit" --arg package_hash "$package_hash" \
    --arg lock "$lock_hash" --arg url "$fixture_url" --arg code "$http_status" \
    --rawfile prompt "$EVAL_DIR/prompt.txt" --slurpfile tools "$ART/tools.json" --slurpfile score "$ART/score.json" \
    --slurpfile summary "$ART/agent-summary.json" --argjson agent_limit "$CODEX_TIMEOUT" \
    --argjson exit_code "$rc" --argjson agent_exit "$agent_exit" --argjson agent_started "$agent_started" \
    --argjson agent_stopped "$agent_stopped" --argjson agent_pid "${agent_pid:-null}" \
    --argjson fixture_started "$fixture_started" --argjson fixture_stopped "$fixture_stopped" \
    --argjson started "$started" --argjson ended "$EPOCHSECONDS" --argjson safety_ok "$safety_ok" \
    --argjson elapsed_ms "$((ended_ms - started_ms))" \
    --argjson package_limit "$package_limit" --argjson request_limit "$request_limit" --argjson boundary "$boundary" \
    --argjson tool_calls "$tool_calls" --argjson target_requests "$target_requests" \
    '{schema_version:1, scenario:"fixture-reachability", $mode, $status, $reason, $exit_code,
      model:(if $mode == "dry" then {provider:null, name:"scripted", version:1}
        else {provider:"OpenAI", name:$model, reasoning_effort:$effort,
          provider_reported_model:$summary[0].provider_reported_model} end),
      harness_version:{sha256:$harness, upstream:"edict@bf7d55187d193c013cffde6ba1c415c4da99398f"},
      evaluator_version:(if $mode == "dry" then {sha256:$evaluator, rubric:"root-response-v1"} else null end),
      pack_version:{name:"scourge-fixture", version:($fixture_version | if . == "" then null else . end),
        binary_sha256:($pack | if . == "" then null else . end), cargo_lock_sha256:$lock,
        source_commit:($source_commit | if . == "" then null else . end), package_sha256:$package_hash},
      oracle_version:{name:"root-response", version:1},
      $prompt, tool_versions:$tools[0],
      agent_inputs:{workspace_files:(if $mode == "dry" and $url != "" and ($boundary | not) then ["target-url"] else [] end),
        target_url:(if $mode == "dry" and $url != "" and ($boundary | not) then $url else null end),
        boundary_inputs:(if $boundary and $agent_started then ["three host paths for read probes", "fixture Unix socket"] else [] end), credentials:[], instructions:[]},
      budgets:{package_seconds:$package_limit, request_seconds:$request_limit, requests:1,
        agent_seconds:(if $mode == "dry" then null else $agent_limit end),
        model_usd:(if $mode == "dry" then 0 else null end), model_tokens:(if $mode == "dry" then 0 else null end)},
      retries:[], human_interventions:[],
      environment_setup:{fresh_workspace:true, agent_environment:(if $boundary then "rootless-container" else "sandbox.env" end), isolated_rite_store:true, worker_boundary:$boundary,
        codex_home:(if $mode == "codex" then "codex-home" else null end),
        codex_auth:(if $mode == "codex" then "exec-only-api-key" else null end),
        fixture_bind:"127.0.0.1:0", cargo_offline:true, fixture_started:$fixture_started, fixture_stopped:$fixture_stopped,
        live_snapshot_unchanged:$safety_ok},
      timing:{started_unix_seconds:$started, ended_unix_seconds:$ended,
        elapsed_milliseconds:$elapsed_ms, elapsed_seconds:($elapsed_ms / 1000)},
      cost:({$target_requests} +
        (if $mode == "dry" then {$tool_calls, model_usd:0, model_input_tokens:0, model_output_tokens:0}
        else {tool_calls:(if $agent_started then $summary[0].tool_calls else 0 end), model_usd:null,
          model_input_tokens:$summary[0].model_input_tokens, model_output_tokens:$summary[0].model_output_tokens,
          usage_available:($summary[0] | .model_input_tokens != null and .model_output_tokens != null),
          usage:$summary[0].usage} end)),
      final_state:{agent_started:$agent_started, agent_exit_code:$agent_exit,
        agent_process_group:$agent_pid, agent_stopped:$agent_stopped, completed_turns:$summary[0].completed_turns,
        http_status:($code | if . == "" then null else . end), score:$score[0]},
      artifacts:({transcript:"artifacts/transcript.jsonl", tools:"artifacts/tools.json", summary:"summary.tsv"}
        + (if $boundary and $agent_started then {boundary:"artifacts/boundary.json"} else {} end)
        + (if $mode == "codex" and $agent_started then {final_message:"artifacts/final-message.txt",
          agent_stderr:"artifacts/agent.stderr", agent_argv:"artifacts/agent-argv.json"} else {} end))}' \
    >"$EVAL_DIR/run.json.tmp" || ! write_run_summary ||
    ! mv -- "$EVAL_DIR/summary.tsv.tmp" "$EVAL_DIR/summary.tsv" ||
    ! mv -- "$EVAL_DIR/run.json.tmp" "$EVAL_DIR/run.json"; then
    printf '%s\n' 'FATAL: could not write run.json and summary.tsv' >&2
    exit 1
  fi
  if ((rc != 0)); then printf 'Trial %s. %s\n' "$status" "$reason" >&2; fi
  exit "$rc"
}
trap 'finish "$?"' EXIT
trap 'die "trial interrupted" 130' INT
trap 'die "trial terminated" 143' TERM

# Record the versions of the exact tools used. Only this fixed set runs in a trial.
rite_version=$(sbx "$RITE_BIN" --version)
cargo_version=$(sbx "$CARGO_BIN" --version)
rustc_version=$(sbx env "PATH=$CARGO_PATH" rustc --version)
python_version=$(sbx "$PYTHON_BIN" --version)
curl_version=$(sbx "$CURL_BIN" --version)
jq -n --arg rite "$rite_version" --arg cargo "$cargo_version" --arg rustc "$rustc_version" --arg python "$python_version" \
  --arg git "$(sbx git --version)" --arg jq "$(jq --version)" --arg curl "${curl_version%%$'\n'*}" --arg bash "$BASH_VERSION" \
  '{$rite,$cargo,$rustc,$python,$git,$jq,$curl,$bash}' >"$ART/tools.json"
if [[ $mode == codex ]]; then
  CODEX_BIN=$(command -v codex) || die 'codex mode requires the Codex CLI'
  CODEX_BIN=$(realpath -e -- "$CODEX_BIN")
  codex_prepare
  codex_version=$(sbx env "CODEX_HOME=$CODEX_HOME_DIR" "$CODEX_BIN" --version) || die 'cannot read Codex CLI version'
  jq --arg codex "$codex_version" '. + {$codex}' "$ART/tools.json" >"$ART/tools.json.tmp"
  mv -- "$ART/tools.json.tmp" "$ART/tools.json"
  [[ -n ${SCOURGE_EVAL_CODEX_API_KEY:-} ]] || die 'codex mode requires SCOURGE_EVAL_CODEX_API_KEY'
fi

live_snapshot "$ART/live-before.json" || die 'cannot snapshot live environment' 2
safety_snapshot=true
if [[ -n "$prepared_rite" ]]; then
  prepared_rite=$(realpath -e -- "$prepared_rite") || die 'cannot resolve prepared Rite store' 2
  [[ -d "$prepared_rite" ]] || die 'prepared Rite store is not a directory' 2
  require_hook_free "$prepared_rite" prepared
fi
require_hook_free "$EVAL_DIR/rite" trial-before-setup

# Reuse the fixture package builder. Give its build only a Cargo registry cache,
# with a clean Cargo home and offline dependency resolution.
[[ -d "$operator_registry" ]] || die 'offline Cargo registry cache unavailable'
mkdir -m 700 -- "$EVAL_DIR/cargo" "$EVAL_DIR/referee"
ln -s -- "$(realpath -e -- "$operator_registry")" "$EVAL_DIR/cargo/registry"
(
  exec env -i "${SBX_ENV[@]}" "PATH=$CARGO_PATH" CARGO_HOME="$EVAL_DIR/cargo" CARGO_NET_OFFLINE=true \
    CARGO_BUILD_JOBS=2 "$PYTHON_BIN" -I "$SCRIPT_DIR/lib/supervise.py" "$$" "$package_limit" "$ART/fixture" 0 \
    "$PYTHON_BIN" -I "$EVAL_REPO_DIR/fixtures/target/package.py" \
    --agent-tree "$PROJECT_DIR" --package-dir "$EVAL_DIR/referee/target" --port 0
) </dev/null >"$ART/fixture.stdout" 2>"$ART/fixture.stderr" &
fixture_pid=$!
for ((attempt = 0; attempt < package_limit * 10; attempt++)); do
  fixture_url=$(sed -n 's/^fixture  listening  \(http:\/\/127\.0\.0\.1:[1-9][0-9]*\)$/\1/p' "$ART/fixture.stderr")
  [[ ! -f "$ART/fixture.exit" ]] || die "fixture setup exited early. See $ART/fixture.stderr"
  if [[ -n "$fixture_url" ]]; then break; fi
  kill -0 "$fixture_pid" 2>/dev/null || die "fixture setup exited early. See $ART/fixture.stderr"
  sleep 0.1
done
[[ "$fixture_url" =~ ^http://127\.0\.0\.1:[1-9][0-9]{0,4}$ ]] || die 'fixture did not announce a loopback port'
fixture_started=true
fixture_binary=$EVAL_DIR/referee/target/scourge-fixture
fixture_version=$(sbx "$fixture_binary" --version)
fixture_hash=$(fingerprint "$fixture_binary")

# Only the harness-owned inputs may be present before the agent stage.
require_hook_free "$EVAL_DIR/rite" trial-before-agent
[[ -z $(find "$PROJECT_DIR" "$EVAL_DIR/home" -mindepth 1 -print -quit) ]] || die 'unexpected trial workspace or HOME configuration' 2
command=("$CURL_BIN" -q --silent --show-error --noproxy '*' --proto '=http' --retry 0
  --max-time "$request_limit" --output /dev/null --write-out '%{http_code}' -- "$fixture_url/")
probe_fixture() {
  ((target_requests += 1))
  http_status=$(cd "$PROJECT_DIR" && sbx "${command[@]}")
}

if [[ $mode == codex ]]; then
  probe_fixture || die 'fixture reachability probe failed'
  [[ $http_status =~ ^[1-5][0-9]{2}$ ]] || die 'fixture returned an invalid HTTP status'
  stop_process_group "$ART/fixture" "$fixture_pid" || die 'fixture process group remained before Codex launch' 2
  fixture_pid=
  fixture_stopped=true
  printf '%s\n' 'Summarize this development-fixture health check in one sentence using only the supplied observation.' \
    "An unauthenticated GET to the root returned HTTP $http_status." >"$EVAL_DIR/prompt.txt"
  codex_run
  require_hook_free "$EVAL_DIR/rite" trial-after-agent
  ((agent_exit == 0)) || die "Codex exited with status $agent_exit"
  exit 0
fi

# Scripted agent. Edict's transcript shape preserves the command and result.
printf '%s\n' "$fixture_url" >"$PROJECT_DIR/target-url"
read -r target_url <"$PROJECT_DIR/target-url"
[[ "$target_url" == "$fixture_url" ]] || die 'trial target URL changed' 2
printf -v command_text '%q ' "${command[@]}"
if [[ $boundary == true ]]; then command_text='rootless Podman worker: Python read probes and HTTP request via fixture socket'; fi
jq -nc --arg command "${command_text% }" \
  '{type:"assistant",message:{content:[{type:"tool_use",name:"Bash",input:{command:$command}}]}}' >>"$transcript"
agent_started=true
agent_exit=0
((tool_calls += 1))
if [[ $boundary == true ]]; then
  target_requests=null
  "$PYTHON_BIN" -I "$SCRIPT_DIR/lib/boundary.py" "$fixture_url" \
    "$EVAL_DIR/referee/target/ground-truth.json" "$EVAL_REPO_DIR/fixtures/target/src/main.rs" \
    "$EVAL_DIR/referee/target/admin-secret" >"$ART/boundary.json" || die 'worker boundary qualification failed'
  target_requests=1
  http_status=$(jq -r .http_status "$ART/boundary.json")
  cat "$ART/boundary.json" >&2
else
  probe_fixture || agent_exit=$?
fi
jq -nc --arg result "$http_status" --argjson code "$agent_exit" \
  '{type:"result",subtype:(if $code == 0 then "success" else "error" end),result:$result,
    exit_code:$code,num_turns:0,total_cost_usd:0}' >>"$transcript"

transcript_extract
verify_response() {
  jq -e '.exit_code == 0 and .result == "404"' "$ART/result.json" >/dev/null
}
verify_agent_calls() {
  jq -es 'length == 1 and .[0].name == "Bash"' "$ART/tool-calls.jsonl" >/dev/null
}
pass_if RESP 1 'The fixture root returned its expected HTTP status' verify_response
pass_if CALL 1 'The transcript contains one scripted tool call' verify_agent_calls
score_summary
require_hook_free "$EVAL_DIR/rite" trial-after-agent
jq -e '.total == 2 and .points == .total' "$ART/score.json" >/dev/null || die 'dry trial failed verification'
