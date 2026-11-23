#!/bin/bash
set -uo pipefail
P=http://127.0.0.1:37657; B=http://127.0.0.1:3000; J=/workspace/jars
OUT=/workspace/work/phase2.tsv
: > "$OUT"
req() {
  local actor=$1 method=$2 path=$3 body=${4-}
  local args=(-sS -m 10 -x "$P" -X "$method" -D /tmp/hdr -o /tmp/body -w '%{http_code}')
  [ "$actor" != anon ] && args+=(-b "$J/$actor.txt")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data "$body")
  local st; st=$(curl "${args[@]}" "$B$path")
  printf '%s' "$st"
}
log(){ printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$OUT"; }
creater(){ local st id; st=$(req "$1" POST "/app/api/$2" "$3"); if [ "$st" = 201 ]; then id=$(jq -r .id /tmp/body); else id="ERR$st"; fi; printf '%s' "$id"; }
json_for(){ case $1 in orders|private_reports|cached_reports) printf '{"note":"%s","detail":"%s"}' "$2" "$2-d";; *) printf '{"note":"%s"}' "$2";; esac; }
mark(){ printf '%s-%s-%s' "$1" "$2" "$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"; }

RES="orders invoices tenant_notes private_reports cached_reports login_reports stale_reports forbidden_reports echo_reports expiring_reports bulletins catalog"

echo "--- identity probes before sharing ---"
for a in alice bob admin; do st=$(req $a GET /app/api/me); log pre-identity $a GET /app/api/me $st "$(tr -d '\n' </tmp/body)"; done

# pre-sharing objects owned by alice
declare -A PRE
for res in $RES; do
  m=$(mark "$res" pre-share)
  PRE[$res]=$(creater alice "$res" "$(json_for "$res" "$m")")
  log pre-create $res alice "${PRE[$res]}" "$m"
done

echo "--- set alice sharing to bob ---"
st=$(req alice PUT /app/api/settings/sharing '{"share_new_with":"bob"}')
log sharing-set alice PUT /app/api/settings/sharing "$st" "$(tr -d '\n' </tmp/body)"
st=$(req alice GET /app/api/settings/sharing); log sharing-state alice GET /app/api/settings/sharing "$st" "$(tr -d '\n' </tmp/body)"
st=$(req bob GET /app/api/settings/sharing); log sharing-state bob GET /app/api/settings/sharing "$st" "$(tr -d '\n' </tmp/body)"

echo "--- post-sharing objects owned by alice ---"
declare -A POST
for res in $RES; do
  m=$(mark "$res" post-share)
  POST[$res]=$(creater alice "$res" "$(json_for "$res" "$m")")
  st=$(req alice GET "/app/api/$res/${POST[$res]}"); log post-owner-baseline $res alice "${POST[$res]}" "$m" "$st" "$(tr -d '\n' </tmp/body)"
  # bob read (should be allowed only for orders/invoices/tenant_notes)
  st=$(req bob GET "/app/api/$res/${POST[$res]}"); log post-bob-read $res bob "${POST[$res]}" "$m" "$st" "$(tr -d '\n' </tmp/body)"
  # admin read (should be denied for all non-public)
  st=$(req admin GET "/app/api/$res/${POST[$res]}"); log post-admin-read $res admin "${POST[$res]}" "$m" "$st" "$(tr -d '\n' </tmp/body)"
  # retroactive read of pre-share object by bob
  st=$(req bob GET "/app/api/$res/${PRE[$res]}"); log retro-bob-read $res bob "${PRE[$res]}" "pre" "$st" "$(tr -d '\n' </tmp/body)"
  # bob write where supported
  if [ "$res" = orders ] || [ "$res" = stale_reports ]; then
    wm="$m-bobwrite"
    st=$(req bob PATCH "/app/api/$res/${POST[$res]}" "$(json_for "$res" "$wm")"); log post-bob-patch $res bob "${POST[$res]}" "$wm" "$st" "$(tr -d '\n' </tmp/body)"
    st=$(req alice GET "/app/api/$res/${POST[$res]}"); log post-owner-after-patch $res alice "${POST[$res]}" "$wm" "$st" "$(tr -d '\n' </tmp/body)"
  fi
  # bob delete
  st=$(req bob DELETE "/app/api/$res/${POST[$res]}"); log post-bob-delete $res bob "${POST[$res]}" "$m" "$st" "$(tr -d '\n' </tmp/body)"
  st=$(req alice GET "/app/api/$res/${POST[$res]}"); log post-owner-after-delete $res alice "${POST[$res]}" "$m" "$st" "$(tr -d '\n' </tmp/body)"
done

echo "--- reset sharing to null ---"
st=$(req alice PUT /app/api/settings/sharing '{"share_new_with":null}'); log sharing-reset alice PUT /app/api/settings/sharing "$st" "$(tr -d '\n' </tmp/body)"
st=$(req alice GET /app/api/settings/sharing); log sharing-state alice GET /app/api/settings/sharing "$st" "$(tr -d '\n' </tmp/body)"
echo "--- identity probes after sharing ---"
for a in alice bob admin; do st=$(req $a GET /app/api/me); log post-identity $a GET /app/api/me $st "$(tr -d '\n' </tmp/body)"; done
