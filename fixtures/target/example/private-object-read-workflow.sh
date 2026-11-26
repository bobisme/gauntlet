#!/usr/bin/env bash
# Generated-example witness for INV-34. Run only against the disposable
# development fixture and its operator-authorized workspace.
set -euo pipefail

if (( $# != 2 )); then
    echo "usage: $0 WORKSPACE ENGAGEMENT" >&2
    exit 2
fi

workspace=$1
engagement=$2
scourge_bin=${SCOURGE_BIN:-scourge}
jq_bin=${JQ_BIN:-jq}
common=(--format json --workspace "$workspace" --engagement "$engagement")

lead_json=$(
    "$scourge_bin" "${common[@]}" lead add "bob reads alice's order" \
        --class web-authz/private-object-read \
        --property orders \
        --slot other=bob
)
lead_id=$(printf '%s\n' "$lead_json" | "$jq_bin" -er '.lead.id')

plan_json=$("$scourge_bin" "${common[@]}" verify "$lead_id" --plan)
printf '%s\n' "$plan_json" | "$jq_bin" -e \
    '.experiment.target_traffic == false
     and .experiment.oracle_guide == "docs/oracles/web.private-object-read.v1.md"
     and (.experiment.known_misses | length == 7)' >/dev/null

verification_json=$("$scourge_bin" "${common[@]}" verify "$lead_id")
record_id=$(printf '%s\n' "$verification_json" | "$jq_bin" -er '.verification.record_id')

show_json=$("$scourge_bin" "${common[@]}" show "$record_id" --depth full)
printf '%s\n' "$show_json" | "$jq_bin" -e \
    '.record.oracle_guide == "docs/oracles/web.private-object-read.v1.md"
     and (.record.known_misses | length > 0)' >/dev/null
printf '%s\n' "$show_json"
