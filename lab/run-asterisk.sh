#!/usr/bin/env bash
# Starts a throwaway Asterisk on 127.0.0.1 for Sidetone tests:
#   UDP 127.0.0.1:5070, WebSocket ws://127.0.0.1:8088/ws
#   2001/secret2001 and 3001/secret3001 (UDP), 4001/secret4001 (WebRTC)
#   600 echo, 601 read 4 digits, 602 busy, 603 unallocated, 700 rings 3001, 800 rings 4001
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="${1:-$(mktemp -d)}"
mkdir -p "$dir"/{run,log,spool,db}
cp "$here"/asterisk/*.conf "$dir"/
sed "s#@DIR@#$dir#g" "$here/asterisk/asterisk.conf.in" > "$dir/asterisk.conf"
asterisk -C "$dir/asterisk.conf" -f > "$dir/asterisk.out" 2>&1 &
echo $! > "$dir/asterisk.pid"
for _ in $(seq 1 30); do
  if asterisk -C "$dir/asterisk.conf" -rx "pjsip show transports" 2>/dev/null | grep -q transport-udp; then
    echo "Asterisk ready (config in $dir)"
    exit 0
  fi
  sleep 1
done
echo "Asterisk did not start; see $dir/asterisk.out" >&2
exit 1
