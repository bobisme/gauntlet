#!/bin/sh
printf '%s\0' "$PWD" "${FORMAT+set}" "$#" "$@" > "$SCOURGE_ACTION_TRACE"
exec "$SCOURGE_ACTION_BINARY" "$@"
