#!/usr/bin/env bash
# Check the guide workflow's argv and reply parsing without a native toolchain.
set -euo pipefail

witness=$1
bash -n "$witness"
export witness_trace
witness_trace=$(mktemp)
trap 'rm -f "$witness_trace"' EXIT

witness_cli() {
    local actual rendered step reply
    printf -v actual '%q ' "$@"
    local expected common=(--format json --workspace 'workspace with spaces' --engagement demo)
    case ${7-} in
        lead)
            expected=(lead add "bob reads alice's order" --class web-authz/private-object-read
                --property orders --slot other=bob)
            step=lead
            reply='{"lead":{"id":"L-guide-witness"}}'
            ;;
        verify)
            expected=(verify L-guide-witness)
            if [[ ${9-} == --plan ]]; then
                expected+=(--plan)
                step=plan
                reply='{"experiment":{"target_traffic":false,"oracle_guide":"docs/oracles/web.private-object-read.v1.md","known_misses":[1,2,3,4,5,6,7]}}'
            else
                step=verify
                reply='{"verification":{"record_id":"V-guide-witness"}}'
            fi
            ;;
        show)
            expected=(show V-guide-witness --depth full)
            step=show
            reply='{"record":{"oracle_guide":"docs/oracles/web.private-object-read.v1.md","known_misses":[1]}}'
            ;;
        *)
            echo "oracle guide example: unexpected command $actual" >&2
            return 1
            ;;
    esac
    printf -v rendered '%q ' "${common[@]}" "${expected[@]}"
    if [[ $actual != "$rendered" ]]; then
        echo "oracle guide example: unexpected argv $actual" >&2
        return 1
    fi
    printf '%s\n' "$step" >>"$witness_trace"
    printf '%s\n' "$reply"
}

witness_jq() {
    local reply filter
    reply=$(cat)
    filter=${2//[[:space:]]/}
    case "$1 $filter $reply" in
        '-er .lead.id {"lead":{"id":"L-guide-witness"}}') echo L-guide-witness ;;
        '-e .experiment.target_traffic==falseand.experiment.oracle_guide=="docs/oracles/web.private-object-read.v1.md"and(.experiment.known_misses|length==7) {"experiment":'*) ;;
        '-er .verification.record_id {"verification":{"record_id":"V-guide-witness"}}') echo V-guide-witness ;;
        '-e .record.oracle_guide=="docs/oracles/web.private-object-read.v1.md"and(.record.known_misses|length>0) {"record":'*) ;;
        *)
            echo "oracle guide example: unexpected assertion $1 $2" >&2
            return 1
            ;;
    esac
}

export -f witness_cli witness_jq
result=$(SCOURGE_BIN=witness_cli JQ_BIN=witness_jq bash "$witness" 'workspace with spaces' demo)
if [[ $(cat "$witness_trace") != $'lead\nplan\nverify\nshow' || $result != '{"record":'* ]]; then
    echo "oracle guide example: expected lead, plan, verify and full record in order" >&2
    exit 1
fi
