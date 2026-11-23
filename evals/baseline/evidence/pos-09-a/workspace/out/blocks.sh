#!/bin/bash
source /dev/stdin <<< "$(sed -n '1,40p' /workspace/out/ev.sh)"
say ""
say "=== BLOCK 1: orders (owner user-alice, actor user-bob / unauthenticated) ==="
R alice POST /app/api/orders '{"note":"alice-order-original","detail":"alice-order-detail-ORIG"}'
OID=$(curl -x http://127.0.0.1:46433 -s -b alice.jar http://127.0.0.1:3000/app/api/orders/../orders 2>/dev/null; true)
# create again capturing id properly
create(){ local jar=$1 r=$2 d=$3; curl -x http://127.0.0.1:46433 -s -b $jar.jar -H 'Content-Type: application/json' -d "$d" http://127.0.0.1:3000/app/api/$r | sed -E 's/.*"id":"([^"]+)".*/\1/'; }
OID=$(create alice orders '{"note":"alice-order-original","detail":"alice-order-detail-ORIG"}')
say "  created id = $OID"
R alice GET /app/api/orders/$OID
R bob   GET /app/api/orders/$OID
R -     GET /app/api/orders/$OID
R bob   PATCH /app/api/orders/$OID '{"note":"B0B-OVERWROTE-THIS","detail":"bob-replaced-detail"}'
R alice GET /app/api/orders/$OID
R bob   DELETE /app/api/orders/$OID
R bob   PATCH /app/api/orders/00000000-0000-0000-0000-000000000000 '{"note":"x"}'
say ""
say "=== BLOCK 2: private-reports (owner user-alice) ==="
PID=$(create alice private-reports '{"note":"alice-private-P1","detail":"alice-private-detail"}')
say "  created id = $PID (never read before the unauthenticated request)"
R -     GET /app/api/private-reports/$PID
R bob   GET /app/api/private-reports/$PID
R admin GET /app/api/private-reports/$PID
R alice GET /app/api/private-reports/$PID
say ""
say "=== BLOCK 3: cached-reports (owner user-alice) ==="
CID=$(create alice cached-reports '{"note":"alice-cached-C1","detail":"alice-cached-detail"}')
say "  created id = $CID"
R -     GET /app/api/cached-reports/$CID
R bob   GET /app/api/cached-reports/$CID
R alice GET /app/api/cached-reports/$CID
say "  -- same object, after the owner's read --"
R -     GET /app/api/cached-reports/$CID
R bob   GET /app/api/cached-reports/$CID
say ""
say "=== BLOCK 4: stale-reports (owner user-alice) ==="
SID=$(create alice stale-reports '{"note":"alice-stale-S1"}')
say "  created id = $SID"
R bob   GET /app/api/stale-reports/$SID
R -     GET /app/api/stale-reports/$SID
R alice GET /app/api/stale-reports/$SID
say "  -- same object, after the owner's read --"
R bob   GET /app/api/stale-reports/$SID
R -     GET /app/api/stale-reports/$SID
R bob   PATCH /app/api/stale-reports/$SID '{"note":"bob-patch"}'
say ""
say "=== BLOCK 5: forbidden-reports (owner user-alice) ==="
FID=$(create alice forbidden-reports '{"note":"alice-forbidden-F1"}')
say "  created id = $FID"
R alice GET /app/api/forbidden-reports/$FID
R bob   GET /app/api/forbidden-reports/$FID
R -     GET /app/api/forbidden-reports/$FID
say ""
say "=== BLOCK 6: echo-reports (owner user-alice) ==="
EID=$(create alice echo-reports '{"note":"alice-echo-E1"}')
say "  created id = $EID"
R alice GET /app/api/echo-reports/$EID
R bob   GET /app/api/echo-reports/$EID
R -     GET /app/api/echo-reports/$EID
R -     GET /app/api/echo-reports/00000000-0000-0000-0000-000000000000
say ""
say "=== BLOCK 7: login-reports (owner user-alice) ==="
LID=$(create alice login-reports '{"note":"alice-login-L1"}')
say "  created id = $LID"
R alice GET /app/api/login-reports/$LID
R bob   GET /app/api/login-reports/$LID
R -     GET /app/api/login-reports/$LID
R bob   GET /app/api/login-reports/11111111-1111-1111-1111-111111111111
say ""
say "=== BLOCK 8: controls on correctly-scoped classes ==="
IID=$(create alice invoices '{"note":"alice-invoice-CTRL"}')
say "  invoices id = $IID"
R alice GET /app/api/invoices/$IID
R bob   GET /app/api/invoices/$IID
TID=$(create alice tenant-notes '{"note":"alice-tenantnote-CTRL"}')
say "  tenant-notes id = $TID"
R alice GET /app/api/tenant-notes/$TID
R bob   GET /app/api/tenant-notes/$TID
BID=$(create alice bulletins '{"note":"alice-bulletin-CTRL"}')
say "  bulletins id = $BID (readers: any authenticated)"
R -     GET /app/api/bulletins/$BID
R bob   GET /app/api/bulletins/$BID
KID=$(create alice catalog '{"note":"alice-catalog-CTRL"}')
say "  catalog id = $KID (readers: anyone)"
R -     GET /app/api/catalog/$KID
R bob   GET /app/api/catalog/$KID
say "  -- unknown ids --"
R bob   GET /app/api/invoices/00000000-0000-0000-0000-000000000000
R -     GET /app/api/orders/00000000-0000-0000-0000-000000000000
