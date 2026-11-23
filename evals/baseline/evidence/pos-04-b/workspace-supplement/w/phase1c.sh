#!/bin/bash
cd /workspace/w && source ./t.sh
create() { curl -sS --max-time 15 -x $P -b $W/$1.jar -H 'Content-Type: application/json' -d "$3" $T/app/api/$2; }
echo "########## PHASE 1c: anonymous delete, cache staleness, sharing isolation ##########"
for r in private-reports cached-reports stale-reports; do
  echo "----- $r anon delete -----"
  M="MK1C-$(mk)"; CR=$(create alice $r "{\"note\":\"$M\"}"); ID=$(newid "$CR"); echo "created id=$ID marker=$M"
  t "$r-anon-delete"            -X DELETE $T/app/api/$r/$ID
  t "$r-owner-read-after-anon-delete" -b $W/alice.jar $T/app/api/$r/$ID
done

echo "----- stale-reports cache staleness (owner update) -----"
M="MKST-$(mk)"; CR=$(create alice stale-reports "{\"note\":\"$M\"}"); ID=$(newid "$CR"); echo "id=$ID marker=$M"
t stale-populate-owner-read -b $W/alice.jar $T/app/api/stale-reports/$ID
t stale-bob-read-cached      -b $W/bob.jar   $T/app/api/stale-reports/$ID
t stale-owner-patch          -b $W/alice.jar -X PATCH -H 'Content-Type: application/json' -d "{\"note\":\"UPDATED-$M\"}" $T/app/api/stale-reports/$ID
t stale-owner-read-after-patch -b $W/alice.jar $T/app/api/stale-reports/$ID
t stale-bob-read-after-owner-patch -b $W/bob.jar $T/app/api/stale-reports/$ID
t stale-owner-delete         -b $W/alice.jar -X DELETE $T/app/api/stale-reports/$ID
t stale-owner-read-after-own-delete -b $W/alice.jar $T/app/api/stale-reports/$ID
t stale-bob-read-after-owner-delete -b $W/bob.jar $T/app/api/stale-reports/$ID
echo "STALE_ID=$ID marker=$M" >> keys1c.tsv

echo "----- sharing isolation -----"
t sharing-bob-write-admin -b $W/bob.jar -X PUT -H 'Content-Type: application/json' -d '{"share_new_with":"admin"}' $T/app/api/settings/sharing
t sharing-alice-read-after-bob-write -b $W/alice.jar $T/app/api/settings/sharing
t sharing-bob-read-own -b $W/bob.jar $T/app/api/settings/sharing
t sharing-bob-reset-null -b $W/bob.jar -X PUT -H 'Content-Type: application/json' -d '{"share_new_with":null}' $T/app/api/settings/sharing
t sharing-anon-write -X PUT -H 'Content-Type: application/json' -d '{"share_new_with":"bob"}' $T/app/api/settings/sharing
t sharing-alice-read-final -b $W/alice.jar $T/app/api/settings/sharing
