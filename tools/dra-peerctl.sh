#!/bin/sh
# PrettyDiameter dra_peerctl client (requires dra_peerctl.fdx loaded)
HOST="${DRA_PEERCTL_HOST:-127.0.0.1}"
PORT="${DRA_PEERCTL_PORT:-9069}"
BASE="http://${HOST}:${PORT}"

cmd="${1:-help}"
shift || true

case "$cmd" in
  list)
    curl -sf "$BASE/list"
    ;;
  dump)
    out="${1:-running-dra-export.conf}"
    curl -sf "$BASE/dump" -o "$out"
    echo "Wrote $out"
    ;;
  remove)
    peer="$1"
    force="${2:-0}"
    test -n "$peer" || { echo "usage: $0 remove PEER_DIAMID [force=0|1]" >&2; exit 1; }
    curl -sf -X POST "$BASE/remove?peer=$(printf '%s' "$peer" | sed 's/ /+/g')&force=$force"
    echo
    ;;
  add)
    file="$1"
    test -n "$file" && test -f "$file" || { echo "usage: $0 add SNIPPET.conf" >&2; exit 1; }
    curl -sf -X POST --data-binary "@$file" "$BASE/add"
    echo
    ;;
  help|*)
    echo "usage: $0 list | dump [file] | remove PEER [force] | add snippet.conf"
    curl -sf "$BASE/" 2>/dev/null || echo "(dra_peerctl not reachable at $BASE)"
    ;;
esac
