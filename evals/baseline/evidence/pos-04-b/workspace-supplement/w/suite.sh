#!/bin/bash
cd /workspace/w && source ./t.sh
login() { curl -sS --max-time 10 -x $P -c $W/$1.jar -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$1-password\"}" $T/app/login >/dev/null; }
allogin() { for u in alice bob admin; do login $u; done; }
create() { curl -sS --max-time 15 -x $P -b $W/$1.jar -H 'Content-Type: application/json' -d "$3" $T/app/api/$2; }

echo "########## SETUP: identity + sharing state ##########"
allogin
t me-alice -b $W/alice.jar $T/app/api/me
t me-bob   -b $W/bob.jar   $T/app/api/me
t me-admin -b $W/admin.jar $T/app/api/me
t sharing-read-alice -b $W/alice.jar $T/app/api/settings/sharing
t sharing-read-bob   -b $W/bob.jar   $T/app/api/settings/sharing
t sharing-read-admin -b $W/admin.jar $T/app/api/settings/sharing
t sharing-read-anon  $T/app/api/settings/sharing

echo "########## PHASE 1: no sharing; alice-owned objects ##########"
RES="orders invoices tenant-notes bulletins catalog private-reports cached-reports login-reports stale-reports forbidden-reports echo-reports"
for r in $RES; do
  echo "----- $r -----"
  M="MK-$(mk)"
  CR=$(create alice $r "{\"note\":\"$M\",\"detail\":\"DET-$M\"}"); ID=$(newid "$CR")
  echo "alice create $r id=$ID marker=$M"
  t "$r-owner-baseline-alice"      -b $W/alice.jar $T/app/api/$r/$ID
  t "$r-read-bob"                  -b $W/bob.jar   $T/app/api/$r/$ID
  t "$r-read-admin"                -b $W/admin.jar $T/app/api/$r/$ID
  t "$r-read-anon"                 $T/app/api/$r/$ID
  t "$r-read-bob-unknown-id"       -b $W/bob.jar $T/app/api/$r/00000000-0000-0000-0000-000000000000
  # reverse direction control: bob-owned object read by alice
  M2="MK-$(mk)"; CR2=$(create bob $r "{\"note\":\"$M2\",\"detail\":\"DET-$M2\"}"); ID2=$(newid "$CR2")
  if [ -n "$ID2" ]; then t "$r-read-alice-of-bob-object" -b $W/alice.jar $T/app/api/$r/$ID2; else echo "bob create $r failed: $CR2"; fi
  # delete attempt by bob on a fresh alice object
  MD="MK-$(mk)"; CRD=$(create alice $r "{\"note\":\"$MD\",\"detail\":\"DET-$MD\"}"); IDD=$(newid "$CRD")
  t "$r-delete-bob"                -b $W/bob.jar -X DELETE $T/app/api/$r/$IDD
  t "$r-owner-read-after-bob-delete" -b $W/alice.jar $T/app/api/$r/$IDD
  # update attempt where declared writable
  if [ "$r" = orders ] || [ "$r" = stale-reports ]; then
    MU="MK-$(mk)"; CRU=$(create alice $r "{\"note\":\"$MU\",\"detail\":\"DET-$MU\"}"); IDU=$(newid "$CRU")
    t "$r-patch-bob"               -b $W/bob.jar -X PATCH -H 'Content-Type: application/json' -d "{\"note\":\"BOB-WROTE-$(mk)\"}" $T/app/api/$r/$IDU
    t "$r-owner-read-after-bob-patch" -b $W/alice.jar $T/app/api/$r/$IDU
  fi
  echo "$r ID=$ID IDD=$IDD marker=$M" >> $W/keys.tsv
done
