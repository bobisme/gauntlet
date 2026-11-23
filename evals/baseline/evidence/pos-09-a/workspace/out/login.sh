#!/bin/bash
u=$1
curl -x http://127.0.0.1:46433 -s -c /workspace/out/$u.jar -H 'Content-Type: application/json' -d "{\"username\":\"$u\",\"password\":\"$u-password\"}" http://127.0.0.1:3000/app/login >/dev/null
