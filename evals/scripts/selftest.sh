#!/bin/bash -p
# Exercise the real preflight and package path without a model.
set -euo pipefail
umask 077
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
python3 -I "$SCRIPT_DIR/test-supervisor.py"
test_dir=$(mktemp -d /tmp/scourge-eval-selftest-XXXXXX)
export EVAL_BASE=$test_dir/trials
rite_bin=$(command -v rite)
mkdir "$test_dir/home" "$test_dir/prepared-rite"

# If the hook fires, the marker shows that preflight had an external effect.
env -i PATH=/usr/bin:/bin HOME="$test_dir/home" RITE_DATA_DIR="$test_dir/prepared-rite" \
  "$rite_bin" hooks add --agent eval-selftest --cwd "$test_dir" --channel eval-selftest --mention eval-selftest \
  -- /usr/bin/touch "$test_dir/hook-fired" >/dev/null

set +e
refused=$(
  "$SCRIPT_DIR/run.sh" dry --rite-store "$test_dir/prepared-rite" 2>"$test_dir/refusal.stderr"
)
rc=$?
set -e
[[ $rc == 2 && $refused == EVAL_DIR=* ]]
refused=${refused#EVAL_DIR=}
jq -e '.status == "refused" and .exit_code == 2 and (.reason | contains("active Rite hooks"))
  and (.final_state.agent_started == false) and (.environment_setup.fixture_started == false)
  and (.environment_setup.live_snapshot_unchanged == true)' "$refused/run.json" >/dev/null
[[ ! -s "$refused/artifacts/transcript.jsonl" && ! -e "$refused/referee" && ! -e "$test_dir/hook-fired" ]]
printf 'Pass: active Rite hook refused before setup. %s\n' "$refused/run.json"

mkdir "$test_dir/malformed-rite"
printf '%s\n' 'invalid JSON' >"$test_dir/malformed-rite/hooks.jsonl"
set +e
malformed=$("$SCRIPT_DIR/run.sh" dry --rite-store "$test_dir/malformed-rite" 2>"$test_dir/malformed.stderr")
rc=$?
set -e
[[ $rc == 2 && $malformed == EVAL_DIR=* ]]
malformed=${malformed#EVAL_DIR=}
jq -e '.status == "refused" and .exit_code == 2 and (.reason | contains("hook inventory"))
  and (.final_state.agent_started == false) and (.environment_setup.fixture_started == false)' \
  "$malformed/run.json" >/dev/null
[[ ! -e "$malformed/referee" ]]
printf 'Pass: invalid Rite hook inventory refused before setup. %s\n' "$malformed/run.json"

# Bash startup hooks and proxy settings from the caller cannot reach the agent.
printf 'touch %q\n' "$test_dir/shell-hook-fired" >"$test_dir/bash-env"
BASH_ENV="$test_dir/bash-env" http_proxy=http://127.0.0.1:1 "$SCRIPT_DIR/run.sh" dry >"$test_dir/dry.log"
passed=$(cat "$test_dir/dry.log")
printf '%s\n' "$passed"
passed=${passed%%$'\n'*}
[[ $passed == EVAL_DIR=* ]]
passed=${passed#EVAL_DIR=}
jq -e '.status == "passed" and .mode == "dry" and .exit_code == 0
  and .final_state.http_status == "404" and .final_state.agent_started == true
  and .final_state.score == {points:2,total:2,passed:2,failed:0}
  and .environment_setup.fixture_started and .environment_setup.fixture_stopped
  and .environment_setup.live_snapshot_unchanged
  and (.model.name == "scripted") and (.prompt | length > 0)
  and (.harness_version.sha256 | length == 64) and (.evaluator_version.sha256 | length == 64)
  and (.pack_version.binary_sha256 | length == 64) and (.oracle_version.version == 1)
  and (.tool_versions | has("rite") and has("curl") and has("cargo"))
  and (.agent_inputs.workspace_files == ["target-url"] and .agent_inputs.credentials == [])
  and .budgets.requests == 1 and .retries == [] and .human_interventions == []
  and .cost.model_usd == 0 and .timing.elapsed_seconds >= 0' "$passed/run.json" >/dev/null
jq -es 'map(.type) == ["assistant", "result"] and .[1].result == "404"' "$passed/artifacts/transcript.jsonl" >/dev/null
[[ ! -e "$test_dir/shell-hook-fired" ]]
[[ $(stat -c '%a' "$passed/referee/target") == 700 ]]
printf 'Pass: packaged fixture verified and stopped. %s\n' "$passed/run.json"

# Stand in for the Codex host to check wiring and capture without a model call.
mkdir "$test_dir/bin"
cat >"$test_dir/bin/codex" <<'EOF'
#!/bin/bash -p
set -euo pipefail
if [[ $1 == --version ]]; then printf '%s\n' 'codex test stub'; exit 0; fi
[[ $CODEX_API_KEY == 'scourge-selftest-only' && -z ${SCOURGE_EVAL_CODEX_API_KEY:-} ]]
[[ -d $CODEX_HOME && $CODEX_HOME != "$HOME/.codex" && -z $(find . -mindepth 1 -print -quit) ]]
while [[ $1 != --output-last-message ]]; do shift; done
final=$2
shift 2
[[ "$#" == 1 && $1 == '-' ]]
input=$(cat)
[[ $input == *'An unauthenticated GET to the root returned HTTP 404.' && $input != *127.0.0.1* ]]
printf '%s\n' 'The fixture responded with HTTP 404.' >"$final"
printf '%s\n' '{"type":"thread.started","thread_id":"stub"}' \
  '{"type":"turn.completed","usage":{"input_tokens":12,"cached_input_tokens":1,"output_tokens":6}}'
EOF
chmod 700 "$test_dir/bin/codex"
captured=$(PATH="$test_dir/bin:$PATH" SCOURGE_EVAL_CODEX_API_KEY=scourge-selftest-only \
  "$SCRIPT_DIR/run.sh" codex --model eval-stub --reasoning-effort medium)
[[ $captured == EVAL_DIR=* ]]
captured=${captured#EVAL_DIR=}
jq -e 'index("--no-daemon") != null and index("--json") != null and index("--ephemeral") != null and index("--ignore-user-config") != null
  and index("--ignore-rules") != null and index("--strict-config") != null and index("read-only") != null
  and index("never") != null and index("hooks") != null and index("shell_tool") != null
  and index("apps") != null and index("plugins") != null and index("multi_agent") != null
  and index("model_provider=\"openai\"") != null and index("mcp_servers={}") != null and index("web_search=\"disabled\"") != null
  and index("eval-stub") != null and index("model_reasoning_effort=\"medium\"") != null and .[-1] == "-"' \
  "$captured/artifacts/agent-argv.json" >/dev/null
jq -e '.status == "captured" and .mode == "codex" and .exit_code == 0
  and .evaluator_version == null and .final_state.score == null and .final_state.agent_stopped
  and .final_state.agent_exit_code == 0 and .final_state.completed_turns == 1
  and (.final_state.agent_process_group | type) == "number"
  and .environment_setup.fixture_stopped and .environment_setup.live_snapshot_unchanged
  and (.pack_version.package_sha256 | length == 64)
  and (.pack_version.source_commit == null or (.pack_version.source_commit | length >= 40))
  and .tool_versions.codex == "codex test stub" and .model.name == "eval-stub"
  and .model.reasoning_effort == "medium" and .model.provider_reported_model == null
  and .cost.model_usd == null and .cost.usage_available and .cost.usage[0].input_tokens == 12
  and .agent_inputs == {workspace_files:[],target_url:null,credentials:[],instructions:[]}
  and (.prompt | contains("returned HTTP 404.")) and .retries == [] and .human_interventions == []' \
  "$captured/run.json" >/dev/null
jq -es 'map(.type) == ["thread.started", "turn.completed"]' "$captured/artifacts/transcript.jsonl" >/dev/null
[[ $(cat "$captured/artifacts/final-message.txt") == 'The fixture responded with HTTP 404.' ]]
if grep -ra -q -- 'scourge-selftest-only' "$captured"; then
  printf '%s\n' 'Unexpected credential in Codex records' >&2
  exit 1
else
  [[ $? == 1 ]]
fi
printf 'Pass: Codex host argv, provenance, capture, and teardown using a stub. %s\n' "$captured/run.json"
