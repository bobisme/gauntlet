# shellcheck shell=bash
# Real-host adaptation of Edict's isolated run_claude stage.

codex_prepare() {
  CODEX_HOME_DIR=$EVAL_DIR/codex-home
  mkdir -m 700 -- "$CODEX_HOME_DIR"
  CODEX_COMMAND=("$CODEX_BIN" --no-daemon --ask-for-approval never exec --json --ephemeral
    --ignore-user-config --ignore-rules --strict-config --skip-git-repo-check
    --sandbox read-only --cd "$PROJECT_DIR" --model "$CODEX_MODEL"
    --disable hooks --disable shell_tool --disable apps --disable plugins
    --disable multi_agent --disable multi_agent_v2 --disable code_mode
    -c 'model_provider="openai"' -c 'mcp_servers={}' -c 'web_search="disabled"' -c 'project_doc_max_bytes=0'
    -c "model_reasoning_effort=\"$REASONING_EFFORT\""
    --output-last-message "$ART/final-message.txt" -)
  jq -n --args '$ARGS.positional' -- "${CODEX_COMMAND[@]}" >"$ART/agent-argv.json"
}

codex_run() {
  : >"$ART/final-message.txt"
  (
    cd "$PROJECT_DIR"
    exec env -i "${SBX_ENV[@]}" "CODEX_HOME=$CODEX_HOME_DIR" \
      "$PYTHON_BIN" -I "$SCRIPT_DIR/lib/supervise.py" "$$" "$CODEX_TIMEOUT" "$ART/agent" 3 \
      "$PYTHON_BIN" -I "$SCRIPT_DIR/lib/codex-launch.py" "${CODEX_COMMAND[@]}"
  ) 3< <(printf '%s' "$SCOURGE_EVAL_CODEX_API_KEY") \
    <"$EVAL_DIR/prompt.txt" >"$transcript" 2>"$ART/agent.stderr" &
  agent_pid=$!
  agent_started=true
  for ((attempt = 0; attempt < (CODEX_TIMEOUT + 5) * 10; attempt++)); do
    if [[ -f "$ART/agent.exit" ]]; then
      read -r agent_exit <"$ART/agent.exit"
      return
    fi
    kill -0 "$agent_pid" 2>/dev/null || die 'Codex supervisor exited without a command status'
    sleep 0.1
  done
  die 'Codex supervisor did not publish a command status'
}

codex_capture() {
  local summary=$ART/agent-summary.json
  # Preserve the native event stream even when a timeout leaves a partial line.
  jq -Rn '
    def token_count:
      if type != "number" then null
      elif . < 0 or . != floor then null
      else . end;
    def tool_item_id:
      select(.type == "item.started" or .type == "item.updated" or .type == "item.completed")
      | .item | objects
      | select(.type == "command_execution" or .type == "file_change" or .type == "mcp_tool_call"
               or .type == "collab_tool_call" or .type == "web_search")
      | .id | strings | select(length > 0);
    [inputs | fromjson? | objects]
    | map(select(.type == "turn.completed")) as $turns
    | (($turns | last | .usage | objects) // {}) as $totals
    | {provider_reported_model: ([.[] | .model | strings] | last // null),
       usage: [$turns[] | .usage | objects],
       model_input_tokens: ($totals.input_tokens | token_count),
       model_output_tokens: ($totals.output_tokens | token_count),
       completed_turns: ($turns | length),
       tool_calls: ([.[] | tool_item_id] | unique | length)}' \
    "$transcript" >"$summary.tmp" && mv -- "$summary.tmp" "$summary"
}
