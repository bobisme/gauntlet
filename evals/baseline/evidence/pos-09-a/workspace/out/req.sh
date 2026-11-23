#!/bin/bash
# usage: req.sh <jar|-> <method> <path> [json]
jar="$1"; m="$2"; p="$3"; d="$4"
args=(-x http://127.0.0.1:46433 -s -o /tmp/body.$$ -w '%{http_code}' -X "$m" "http://127.0.0.1:3000$p")
[ "$jar" != "-" ] && args+=(-b "/workspace/out/$jar.jar")
[ -n "$d" ] && args+=(-H 'Content-Type: application/json' -d "$d")
code=$(curl "${args[@]}")
echo "--- $m $p [$jar] -> $code"
cat /tmp/body.$$; echo
rm -f /tmp/body.$$
