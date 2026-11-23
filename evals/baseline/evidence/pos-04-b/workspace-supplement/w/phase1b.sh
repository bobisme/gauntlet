#!/bin/bash
cd /workspace/w && source ./t.sh
create() { curl -sS --max-time 15 -x $P -b $W/$1.jar -H 'Content-Type: application/json' -d "$3" $T/app/api/$2; }
echo "########## PHASE 1b: cache/population differentials ##########"
for r in stale-reports cached-reports private-reports forbidden-reports echo-reports; do
  echo "----- $r -----"
  M="MK1B-$(mk)"
  CR=$(create alice $r "{\"note\":\"$M\",\"detail\":\"DET-$M\"}"); ID=$(newid "$CR"); echo "created id=$ID marker=$M (owner has NOT fetched)"
  t "$r-bob-read-before-any-fetch"   -b $W/bob.jar $T/app/api/$r/$ID
  t "$r-anon-read-before-any-fetch"  $T/app/api/$r/$ID
  t "$r-owner-fetch-populate"        -b $W/alice.jar $T/app/api/$r/$ID
  t "$r-bob-read-after-owner-fetch"  -b $W/bob.jar $T/app/api/$r/$ID
  t "$r-anon-read-after-owner-fetch" $T/app/api/$r/$ID
  t "$r-admin-read-after-owner-fetch" -b $W/admin.jar $T/app/api/$r/$ID
  echo "$r ID=$ID marker=$M" >> $W/keys1b.tsv
done
