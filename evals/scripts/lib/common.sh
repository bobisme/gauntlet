# shellcheck shell=bash
# Adapted from Edict evals/scripts/lib/common.sh. See ../../LICENSE.edict.

EVAL_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EVAL_SCRIPTS_DIR=$(dirname "$EVAL_LIB_DIR")
EVAL_REPO_DIR=$(cd "$EVAL_SCRIPTS_DIR/../.." && pwd)
EVAL_BASE=${EVAL_BASE:-/tmp/scourge-evals}

die() {
  reason=$1
  printf 'FATAL: %s\n' "$reason" >&2
  exit "${2:-1}"
}

eval_new_dir() {
  EVAL_BASE=$(realpath -m -- "$EVAL_BASE")
  [[ $EVAL_BASE != *$'\n'* ]] || die 'EVAL_BASE must be a single-line path'
  case "$EVAL_BASE/" in
    "$EVAL_REPO_DIR/"*) die 'EVAL_BASE must be outside the Scourge checkout' ;;
  esac
  mkdir -p -- "$EVAL_BASE"
  mktemp -d -- "$EVAL_BASE/$1-XXXXXX"
}

sbx_write_env() {
  local d=$1
  mkdir -m 700 -- "$d/home" "$d/rite" "$d/run" "$d/tmp" "$d/artifacts" "$d/workspace"
  cat >"$d/sandbox.env" <<EOF
EVAL_SANDBOX=1
PATH=/usr/bin:/bin
HOME=$d/home
LANG=C.UTF-8
TMPDIR=$d/tmp
RITE_DATA_DIR=$d/rite
XDG_DATA_HOME=$d/home/.local/share
XDG_CONFIG_HOME=$d/home/.config
XDG_CACHE_HOME=$d/home/.cache
XDG_STATE_HOME=$d/home/.local/state
XDG_RUNTIME_DIR=$d/run
VESSEL_SOCKET=$d/run/vessel.sock
TMUX_TMPDIR=$d/run
EOF
}

sbx_load() {
  mapfile -t SBX_ENV <"$1/sandbox.env"
}

sbx() { env -i "${SBX_ENV[@]}" "$@"; }

live_snapshot() {
  # Unlike `vessel list`, the observer cannot auto-start a host Vessel server.
  sbx "$PYTHON_BIN" -I "$EVAL_LIB_DIR/live-snapshot.py" \
    "$EVAL_DIR" "$HOST_DEFAULT_RITE" "$HOST_EFFECTIVE_RITE" >"$1"
}

live_compare() {
  live_snapshot "$ART/live-after.json" &&
    cmp -s "$ART/live-before.json" "$ART/live-after.json" &&
    jq -e '.trial_processes == 0' "$ART/live-after.json" >/dev/null
}

require_hook_free() {
  local store=$1 label=$2 count
  # Only read the configured hook inventory. Never send, drain, or remove hooks.
  if ! count=$(sbx timeout 5 env "RITE_DATA_DIR=$store" "$RITE_BIN" hooks list --format json \
      2>"$ART/$label-rite.stderr" |
      jq -es 'if length == 1 and (.[0].hooks | type) == "array" then
                .[0].hooks | if all(.[]; type == "object") then
                  map(select(.active != false)) | length
                else error("invalid Rite hook entry") end
              else error("expected one Rite hook inventory") end'); then
    die "cannot verify Rite hooks in $label store" 2
  fi
  [[ ! -s "$ART/$label-rite.stderr" ]] || die "Rite reported a hook inventory diagnostic in $label store" 2
  [[ "$count" == 0 ]] || die "active Rite hooks in $label store ($count)" 2
}

stop_process_group() {
  local prefix=$1 supervisor=$2 status=0 state
  # The private stop request is consumed by the live group leader. The shell
  # only waits for its child, so an exited leader's former PGID is never signaled.
  : >"$prefix.stop" || return 1
  wait "$supervisor" 2>/dev/null || status=$?
  [[ -f "$prefix.stopped" ]] || return 1
  read -r state <"$prefix.stopped" || return 1
  [[ ( $state == clean && $status == 0 ) || ( $state == forced && $status == 137 ) ]]
}

transcript_extract() {
  local transcript=$ART/transcript.jsonl
  jq -c 'select(.type == "assistant") | .message.content[] | select(.type == "tool_use") | {name, input}' \
    "$transcript" >"$ART/tool-calls.jsonl"
  jq -s 'map(select(.type == "result")) | last // {}' "$transcript" >"$ART/result.json"
}

check() {
  local id=$1 points=$2 state=$3 description=$4
  printf '%s\t%s\t%s\t%s\n' "$id" "$points" "$state" "$description" >>"$CHECKS"
  printf '%-4s %-5s %3s  %s\n' "$id" "${state^^}" "$points" "$description"
}

pass_if() {
  local id=$1 points=$2 description=$3
  shift 3
  if "$@"; then check "$id" "$points" pass "$description"; else check "$id" "$points" fail "$description"; fi
}

score_summary() {
  awk -F '\t' '
    $3=="pass"{points+=$2; passed++} $3=="fail"{failed++} {total+=$2}
    END{printf "{\"points\":%d,\"total\":%d,\"passed\":%d,\"failed\":%d}\n", points, total, passed, failed}' \
    "$CHECKS" >"$ART/score.json"
}
