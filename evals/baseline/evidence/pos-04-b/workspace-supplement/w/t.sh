#!/bin/bash
P=http://127.0.0.1:43307; T=http://127.0.0.1:3000; W=/workspace/w; E=$W/evidence
CNT=$W/.cnt
t() {
  local slug="$1"; shift
  local n; n=$(cat "$CNT" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$CNT"
  local f; f=$(printf "%s/%03d-%s" "$E" "$n" "$slug")
  { printf '### %03d %s\n' "$n" "$slug"
    printf 'REQUEST: curl -sS -x %s' "$P"; for a in "$@"; do case "$a" in *" "*) printf " '%s'" "$a";; *) printf ' %s' "$a";; esac; done; printf '\n'
    curl -sS -D - --max-time 15 -x "$P" "$@"; printf '\n---\n'
  } > "$f.txt" 2>&1
  local code=$(grep -m1 -E '^HTTP/' "$f.txt" | tr -d '\r')
  local body=$(sed -n '/^\r*$/,$p' "$f.txt" | grep -v '^$' | tr -d '\r' | head -c 200)
  printf '%-62s | %-24s | %s\n' "$slug" "$code" "$body"
}
mk() { head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
newid() { printf '%s' "$1" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'; }
