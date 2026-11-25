#!/bin/sh
# Run in a disposable namespace containing a local non-loopback fixture IP.
set -eu
core=$1
reference=$2
probe=$3
: "${MAGICBOX_SS_ORIGIN:?set to a local test interface address}"
dir=$(mktemp -d)
client_pid=
server_pid=
stop_process() {
    if [ -n "$1" ]; then kill "$1" 2>/dev/null || :; wait "$1" 2>/dev/null || :; fi
}
cleanup() { stop_process "$client_pid"; stop_process "$server_pid"; rm -rf "$dir"; }
trap cleanup EXIT
for method in aes-128-gcm aes-256-gcm chacha20-ietf-poly1305; do
    "$reference" -s 127.0.0.1 -p 21835 -k interop-password -m "$method" > "$dir/reference.log" 2>&1 &
    server_pid=$!
    sleep 0.15
    kill -0 "$server_pid" || { cat "$dir/reference.log"; exit 1; }
    for pass in interop-password unrelated-key; do
        printf 'listen = "127.0.0.1:0"\nupstream = "ss://%s:%s@127.0.0.1:21835"\n' "$method" "$pass" > "$dir/profile"
        "$core" run "$dir/profile" 2> "$dir/client.log" &
        client_pid=$!
        tries=0
        until grep -q '^ready ' "$dir/client.log"; do
            kill -0 "$client_pid" && [ "$tries" -lt 100 ] || { cat "$dir/client.log"; exit 1; }
            tries=$((tries + 1)); sleep 0.05
        done
        port=$(sed -n 's/^ready 127\.0\.0\.1://p' "$dir/client.log")
        if [ "$pass" = interop-password ]; then
            "$probe" "$MAGICBOX_SS_ORIGIN" "$port" socks
            "$probe" "$MAGICBOX_SS_ORIGIN" "$port" http
        else
            "$probe" "$MAGICBOX_SS_ORIGIN" "$port" wrong
        fi
        stop_process "$client_pid"; client_pid=
    done
    stop_process "$server_pid"; server_pid=
    echo "$method: SOCKS5, pipelined CONNECT, 180123-byte echo and wrong-key origin isolation passed"
done
