#!/bin/bash
cd /workspace/out
LOG=/workspace/out/evidence.log; : > $LOG
say(){ echo "$@" | tee -a $LOG; }
login(){ curl -x http://127.0.0.1:46433 -s -c /workspace/out/$1.jar -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$1-password\"}" http://127.0.0.1:3000/app/login >/dev/null; }
ensure(){ [ "$1" = "-" ] && return; c=$(curl -x http://127.0.0.1:46433 -s -o /dev/null -w '%{http_code}' -b /workspace/out/$1.jar http://127.0.0.1:3000/app/api/me); [ "$c" != 200 ] && { login $1; say "   (session for $1 re-established)"; }; }
R(){ local jar=$1 m=$2 p=$3 d=$4 body=/tmp/b.$$ hdr=/tmp/h.$$
  [ "$jar" != "-" ] && ensure "$jar"
  local args=(-x http://127.0.0.1:46433 -s -o "$body" -D "$hdr" -w '%{http_code}' -X "$m" "http://127.0.0.1:3000$p")
  [ "$jar" != "-" ] && args+=(-b /workspace/out/$jar.jar)
  [ -n "$d" ] && args+=(-H 'Content-Type: application/json' -d "$d")
  local code=$(curl "${args[@]}")
  say "$m $p"
  say "  request : $( [ "$jar" = "-" ] && echo 'no session cookie (unauthenticated)' || echo "Cookie: scourge_session=<session of $jar>" )${d:+ ; body=$d}"
  say "  response: HTTP $code ; cache-control: $(grep -i '^cache-control' $hdr | tr -d '\r' | cut -d' ' -f2) ; body: $(cat $body)"
  rm -f "$body" "$hdr"; LAST_CODE=$code; }
create(){ curl -x http://127.0.0.1:46433 -s -b /workspace/out/$1.jar -H 'Content-Type: application/json' -d "$3" http://127.0.0.1:3000/app/api/$2 | sed -E 's/.*"id":"([^"]+)".*/\1/'; }

say "=== 0. identity baselines (/app/api/me) ==="
login alice; login bob; login admin
for u in alice bob admin; do R $u GET /app/api/me; done
say ""
say "=== 1. sharing state before the cross-user tests ==="
R alice GET /app/api/settings/sharing
R bob GET /app/api/settings/sharing
say ""
say "=== 2. CONTROL: documented sharing semantics (invoices, owner user-alice) ==="
PRE=$(create alice invoices '{"note":"alice-invoice-created-BEFORE-sharing"}')
say "  invoice created before any share, id = $PRE"
R alice PUT /app/api/settings/sharing '{"share_new_with":"bob"}'
R alice GET /app/api/settings/sharing
R bob GET /app/api/settings/sharing
SH2=$(create alice invoices '{"note":"alice-invoice-created-AFTER-sharing-to-bob"}')
say "  invoice created after share_new_with=bob, id = $SH2"
R bob GET /app/api/invoices/$SH2
R bob DELETE /app/api/invoices/$SH2
R bob GET /app/api/invoices/$PRE
R alice PUT /app/api/settings/sharing '{"share_new_with":null}'
R alice GET /app/api/settings/sharing
R bob GET /app/api/invoices/$SH2
say ""
say "=== 3. orders: peer read and peer write (sharing = null) ==="
OID=$(create alice orders '{"note":"alice-order-original","detail":"alice-order-detail-ORIG"}')
say "  order id = $OID"
R alice GET /app/api/orders/$OID
R bob GET /app/api/orders/$OID
R - GET /app/api/orders/$OID
R bob PATCH /app/api/orders/$OID '{"note":"B0B-OVERWROTE-THIS","detail":"bob-replaced-detail"}'
R alice GET /app/api/orders/$OID
R bob DELETE /app/api/orders/$OID
R bob PATCH /app/api/orders/00000000-0000-0000-0000-000000000000 '{"note":"x"}'
say ""
say "=== 4. private-reports: unauthenticated read of a fresh object ==="
PID=$(create alice private-reports '{"note":"alice-private-P1","detail":"alice-private-detail"}')
say "  private report id = $PID (created and then read without any prior owner read)"
R - GET /app/api/private-reports/$PID
R bob GET /app/api/private-reports/$PID
R alice GET /app/api/private-reports/$PID
say ""
say "=== 5. cached-reports: anonymous read after owner read ==="
CID=$(create alice cached-reports '{"note":"alice-cached-C1","detail":"alice-cached-detail"}')
say "  cached report id = $CID"
R - GET /app/api/cached-reports/$CID
R bob GET /app/api/cached-reports/$CID
R alice GET /app/api/cached-reports/$CID
say "  -- same object, after the owner's read --"
R - GET /app/api/cached-reports/$CID
R bob GET /app/api/cached-reports/$CID
say ""
say "=== 6. stale-reports: peer and anonymous read after owner read ==="
SID=$(create alice stale-reports '{"note":"alice-stale-S1"}')
say "  stale report id = $SID"
R bob GET /app/api/stale-reports/$SID
R - GET /app/api/stale-reports/$SID
R alice GET /app/api/stale-reports/$SID
say "  -- same object, after the owner's read --"
R bob GET /app/api/stale-reports/$SID
R - GET /app/api/stale-reports/$SID
R bob PATCH /app/api/stale-reports/$SID '{"note":"bob-patch"}'
say ""
say "=== 7. forbidden-reports: record body returned with 403 ==="
FID=$(create alice forbidden-reports '{"note":"alice-forbidden-F1"}')
say "  forbidden report id = $FID"
R alice GET /app/api/forbidden-reports/$FID
R bob GET /app/api/forbidden-reports/$FID
R - GET /app/api/forbidden-reports/$FID
say ""
say "=== 8. echo-reports: id-independent global echo ==="
EID=$(create alice echo-reports '{"note":"alice-echo-E1"}')
say "  echo report id = $EID"
R alice GET /app/api/echo-reports/$EID
R bob GET /app/api/echo-reports/$EID
R - GET /app/api/echo-reports/$EID
R - GET /app/api/echo-reports/00000000-0000-0000-0000-000000000000
say ""
say "=== 9. login-reports: guard page with 200 for non-owner ==="
LID=$(create alice login-reports '{"note":"alice-login-L1"}')
say "  login report id = $LID"
R alice GET /app/api/login-reports/$LID
R bob GET /app/api/login-reports/$LID
R - GET /app/api/login-reports/$LID
R bob GET /app/api/login-reports/11111111-1111-1111-1111-111111111111
say "  -- logout revokes the session (control) --"
R alice POST /app/logout
R alice GET /app/api/me
R alice GET /app/api/login-reports/$LID
say ""
say "=== 10. expiring-reports and correct classes (no peer deviation observed) ==="
XID=$(create alice expiring-reports '{"note":"alice-expiring-X1"}')
say "  expiring report id = $XID"
R alice GET /app/api/expiring-reports/$XID
R bob GET /app/api/expiring-reports/$XID
R - GET /app/api/expiring-reports/$XID
IID=$(create alice invoices '{"note":"alice-invoice-CTRL2"}')
say "  invoice id = $IID"
R bob GET /app/api/invoices/$IID
TID=$(create alice tenant-notes '{"note":"alice-tenantnote-CTRL"}')
say "  tenant note id = $TID (owner tenant-a; bob is tenant-b)"
R bob GET /app/api/tenant-notes/$TID
R - GET /app/api/tenant-notes/$TID
BID=$(create alice bulletins '{"note":"alice-bulletin-CTRL"}')
say "  bulletin id = $BID (readers: any authenticated account)"
R - GET /app/api/bulletins/$BID
R bob GET /app/api/bulletins/$BID
KID=$(create alice catalog '{"note":"alice-catalog-CTRL"}')
say "  catalog id = $KID (readers: anyone)"
R - GET /app/api/catalog/$KID
R bob GET /app/api/catalog/$KID
say "  -- unknown ids --"
R bob GET /app/api/invoices/00000000-0000-0000-0000-000000000000
R - GET /app/api/orders/00000000-0000-0000-0000-000000000000
