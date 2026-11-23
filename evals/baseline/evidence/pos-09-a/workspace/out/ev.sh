#!/bin/bash
cd /workspace/out
LOG=/workspace/out/evidence.log
: > $LOG
say(){ echo "$@" | tee -a $LOG; }
login(){ curl -x http://127.0.0.1:46433 -s -c /workspace/out/$1.jar -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$1-password\"}" http://127.0.0.1:3000/app/login >/dev/null; }
ensure(){ # ensure valid session, re-login if needed
  if [ "$1" = "-" ]; then return; fi
  c=$(curl -x http://127.0.0.1:46433 -s -o /dev/null -w '%{http_code}' -b /workspace/out/$1.jar http://127.0.0.1:3000/app/api/me)
  if [ "$c" != 200 ]; then login $1; say "   (session for $1 re-established)"; fi
}
R(){ # R jar method path [json]
  local jar=$1 m=$2 p=$3 d=$4
  [ "$jar" != "-" ] && ensure "$jar"
  local body=$(mktemp)
  local args=(-x http://127.0.0.1:46433 -s -o "$body" -w '%{http_code}' -D /tmp/hdr.$$ -X "$m" "http://127.0.0.1:3000$p")
  [ "$jar" != "-" ] && args+=(-b /workspace/out/$jar.jar)
  [ -n "$d" ] && args+=(-H 'Content-Type: application/json' -d "$d")
  local code=$(curl "${args[@]}")
  say "$m $p"
  say "  request : $( [ "$jar" = "-" ] && echo 'no session cookie (unauthenticated)' || echo "Cookie: scourge_session=<session of $jar>" )${d:+ ; body=$d}"
  say "  response: HTTP $code ; cache-control: $(grep -i '^cache-control' /tmp/hdr.$$ | tr -d '\r' | cut -d' ' -f2) ; body: $(cat $body)"
  echo "$code" > /tmp/code.$$
  rm -f "$body"
}
say "=== identity baselines ==="
login alice; login bob; login admin
for u in alice bob admin; do
  R $u GET /app/api/me
  say "  (session cookie for $u: $(grep -o 'scourge_session.*' $u.jar | awk '{print $2}'))"
done
