P=http://127.0.0.1:43307
T=http://127.0.0.1:3000
W=/workspace/w
req() { # req <label> <curl args...>
  local label="$1"; shift
  local hdr=/tmp/h.$$ body=/tmp/b.$$
  local code
  code=$(curl -s -D "$hdr" -o "$body" -w '%{http_code}' --max-time 10 "$@")
  local cc=$(grep -i '^cache-control:' "$hdr" | tr -d '\r' | head -1)
  printf '%s | %s | %s | %s\n' "$label" "$code" "$cc" "$(cat "$body" | head -c 400)"
  echo "$label|$code|$(cat "$body")" >> $W/results.tsv
  $W/dump "$label" "$hdr" "$body" 2>/dev/null
  rm -f "$hdr" "$body"
  return 0
}
dump() { :; }
mk() { head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
