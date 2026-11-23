#!/bin/bash
P=http://127.0.0.1:43307; T=http://127.0.0.1:3000; W=/workspace/w
: > $W/results.tsv
mk() { head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
R() { # R label  <curl args>
  local label="$1"; shift
  local hdr=$(mktemp) body=$(mktemp) code
  code=$(curl -s -D "$hdr" -o "$body" -w '%{http_code}' --max-time 10 "$@")
  local cc=$(grep -i '^cache-control:' "$hdr" | tr -d '\r' | sed 's/^[^:]*: //I' | head -1)
  printf '%-58s %-4s %-12s %s\n' "$label" "$code" "${cc:-<none>}" "$(tr -d '\n' < "$body" | head -c 300)"
  printf '%s\t%s\t%s\t%s\n' "$label" "$code" "$cc" "$(tr -d '\n' < "$body")" >> $W/results.tsv
  rm -f "$hdr" "$body"
}
create() { # create <resource> <jar> <marker> -> prints id
  local r=$1 jar=$2 m=$3
  curl -s --max-time 10 -x $P -b $W/$jar -H 'Content-Type: application/json' \
    -d "{\"note\":\"$m\",\"detail\":\"${m}-detail\"}" "$T/app/api/$r" |
    sed -n 's/.*"id":"\([^"]*\)".*/\1/p'
}
RES="orders invoices tenant-notes bulletins catalog private-reports cached-reports login-reports stale-reports forbidden-reports echo-reports expiring-reports"
for r in $RES; do
  echo "================ $r ================"
  M="MK$(mk)A"
  ID=$(create $r alice.jar "$M")
  echo "created id=$ID marker=$M"
  R "alice GET $r/$ID (owner baseline)"        -x $P -b $W/alice.jar "$T/app/api/$r/$ID"
  R "bob   GET $r/$ID (other user)"            -x $P -b $W/bob.jar   "$T/app/api/$r/$ID"
  R "admin GET $r/$ID (admin/other tenant)"    -x $P -b $W/admin.jar "$T/app/api/$r/$ID"
  R "anon  GET $r/$ID (no session)"            -x $P                   "$T/app/api/$r/$ID"
  R "alice GET $r/00000000-0000-0000-0000-000000000000 (absence ctrl)" -x $P -b $W/alice.jar "$T/app/api/$r/00000000-0000-0000-0000-000000000000"
  # delete test
  MD="MK$(mk)D"; IDD=$(create $r alice.jar "$MD")
  R "bob   DELETE $r/$IDD (other user)"        -x $P -b $W/bob.jar -X DELETE "$T/app/api/$r/$IDD"
  R "alice GET $r/$IDD (state after bob del)"  -x $P -b $W/alice.jar "$T/app/api/$r/$IDD"
  # update test where declared
  if [ "$r" = orders ] || [ "$r" = stale-reports ]; then
    MU="MK$(mk)U"; IDU=$(create $r alice.jar "$MU")
    R "bob   PATCH $r/$IDU note=bob-write"     -x $P -b $W/bob.jar -H 'Content-Type: application/json' -X PATCH -d '{"note":"bob-write"}' "$T/app/api/$r/$IDU"
    R "alice GET $r/$IDU (state after bob patch)" -x $P -b $W/alice.jar "$T/app/api/$r/$IDU"
  fi
done
