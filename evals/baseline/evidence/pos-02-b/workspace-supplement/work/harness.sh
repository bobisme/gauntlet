#!/bin/bash
# Cross-user access harness for the in-scope fixture.
set -uo pipefail
P=http://127.0.0.1:37657
B=http://127.0.0.1:3000
J=/workspace/jars
OUT=/workspace/work/matrix.tsv
: > "$OUT"

# req actor method path [json]
req() {
  local actor=$1 method=$2 path=$3 body=${4-}
  local args=(-sS -m 10 -x "$P" -X "$method" -D /tmp/hdr -o /tmp/body -w '%{http_code}')
  if [ "$actor" != anon ]; then args+=(-b "$J/$actor.txt"); fi
  if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' --data "$body"); fi
  local st
  st=$(curl "${args[@]}" "$B$path")
  local cc
  cc=$(grep -i '^cache-control:' /tmp/hdr | tr -d '\r' | sed 's/^[^:]*: *//')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$actor" "$method" "$path" "$st" "$cc" "$(tr -d '\n' </tmp/body | cut -c1-400)" "$body" >> "$OUT"
  printf '%s' "$st"
}

creater() { # actor resource json -> id
  local actor=$1 res=$2 json=$3 st id
  st=$(req "$actor" POST "/app/api/$res" "$json")
  if [ "$st" = 201 ] || [ "$st" = 200 ]; then
    id=$(jq -r '.id // empty' /tmp/body)
    printf '%s' "$id"
  else
    printf ''
  fi
}

mark() { printf '%s-%s-%s-%s' "$1" "$2" "${3:-x}" "$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"; }

json_for() { # res marker
  local res=$1 m=$2
  case $res in
    orders|private_reports|cached_reports) printf '{"note":"%s","detail":"%s"}' "$m" "$m-detail";;
    *) printf '{"note":"%s"}' "$m";;
  esac
}

RESOURCES="orders invoices tenant_notes bulletins catalog private_reports cached_reports login_reports stale_reports forbidden_reports echo_reports expiring_reports"
ACTORS="alice bob admin"
echo "phase	resource	owner	obj	id	marker	actor	op	status	body" > /workspace/work/summary.tsv

# ---------- Phase 1: unshared baseline matrix ----------
for owner in $ACTORS; do
  for res in $RESOURCES; do
    m=$(mark "$res" "$owner" base)
    id=$(creater "$owner" "$res" "$(json_for "$res" "$m")")
    echo -e "P1\t$res\t$owner\t$res\t${id}\t$m\t$owner\tbaseline-read\t$(req "$owner" GET "/app/api/$res/$id")\t$(tr -d '\n' </tmp/body | cut -c1-300)" >> /workspace/work/summary.tsv
    for actor in alice bob admin anon; do
      [ "$actor" = "$owner" ] && continue
      st=$(req "$actor" GET "/app/api/$res/$id")
      echo -e "P1\t$res\t$owner\t$res\t${id}\t$m\t$actor\tread\t$st\t$(tr -d '\n' </tmp/body | cut -c1-300)" >> /workspace/work/summary.tsv
    done
    # update test for resources declaring update
    if [ "$res" = orders ] || [ "$res" = stale_reports ]; then
      for actor in alice bob admin; do
        [ "$actor" = "$owner" ] && continue
        m2="$m-UTRY-$actor"
        st=$(req "$actor" PATCH "/app/api/$res/$id" "$(json_for "$res" "$m2")")
        echo -e "P1\t$res\t$owner\t$res\t${id}\t$m2\t$actor\tupdate\t$st\t$(tr -d '\n' </tmp/body | cut -c1-300)" >> /workspace/work/summary.tsv
        st=$(req "$owner" GET "/app/api/$res/$id")
        echo -e "P1\t$res\t$owner\t$res\t${id}\t$m\t$owner\tafter-update\t$st\t$(tr -d '\n' </tmp/body | cut -c1-300)" >> /workspace/work/summary.tsv
      done
    fi
    # delete test (last)
    for actor in alice bob admin; do
      [ "$actor" = "$owner" ] && continue
      st=$(req "$actor" DELETE "/app/api/$res/$id")
      echo -e "P1\t$res\t$owner\t$res\t${id}\t$m\t$actor\tdelete\t$st\t$(tr -d '\n' </tmp/body | cut -c1-300)" >> /workspace/work/summary.tsv
      st=$(req "$owner" GET "/app/api/$res/$id")
      echo -e "P1\t$res\t$owner\t$res\t${id}\t$m\t$owner\tafter-delete\t$st\t$(tr -d '\n' </tmp/body | cut -c1-300)" >> /workspace/work/summary.tsv
    done
  done
done
echo "P1 done"
