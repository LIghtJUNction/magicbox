#!/bin/sh
# sudo unshare --net --mount --propagation private sh tests/dns_guard.sh /abs/guard /abs/probe
set -eu
guard=$1
probe=$2
ip link set lo up
root=/sys/fs/cgroup
[ -f "$root/cgroup.controllers" ] || { echo 'test requires a mounted cgroup v2 hierarchy' >&2; exit 1; }
work=$(mktemp -d)
group=$(mktemp -d "$root/magicbox-test.XXXXXX")
first=
second=
occupant=
cleanup() {
    for pid in "$first" "$second" "$occupant"; do
        if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    done
    rmdir "$group/child" "$group" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
mkdir "$group/child"
start_guard() {
    "$guard" attach "$group" >"$work/$1" &
    started=$!
    for _ in $(seq 1 100); do
        if grep -qx ready "$work/$1"; then return; fi
        kill -0 "$started" || { wait "$started"; exit 1; }
        sleep .05
    done
    kill "$started" || true
    echo 'guard did not report ready' >&2; exit 1
}
reject_path() {
    status=0
    timeout 3 "$guard" attach "$1" >"$work/unexpected" || status=$?
    [ "$status" -eq 1 ] && [ ! -s "$work/unexpected" ] || { echo 'invalid path accepted' >&2; exit 1; }
}
ln -s "$group" "$work/link"
for bad in "$root" "$work" "$work/link" .; do reject_path "$bad"; done
# Confirm refusal of a live group without ever moving the test harness itself.
sh -c 'echo 0 >"$1/cgroup.procs"; exec sleep 15' sh "$group" &
occupant=$!
for _ in $(seq 1 100); do grep -qx 'populated 1' "$group/cgroup.events" && break; sleep .05; done
grep -qx 'populated 1' "$group/cgroup.events"
reject_path "$group"
kill "$occupant"; wait "$occupant" || true; occupant=
# With room for only one link fd the second BPF_LINK_CREATE must fail.
# The activation map remains zero and all partially acquired links disappear.
status=0
(ulimit -n 7 && exec "$guard" attach "$group") >"$work/partial" 2>"$work/partial.err" || status=$?
[ "$status" -eq 1 ] && grep -q 'link cgroup hook 11:' "$work/partial.err" || {
    cat "$work/partial.err" >&2; echo 'failed to exercise partial attach rollback' >&2; exit 1;
}
[ ! -s "$work/partial" ]
"$probe" "$group/cgroup.procs" open
start_guard first
first=$started
start_guard second
second=$started
"$probe" "$group/cgroup.procs" protected
"$probe" "$group/child/cgroup.procs" protected
"$probe" - open
kill "$first"; wait "$first" || true; first=
"$probe" "$group/cgroup.procs" protected
kill -KILL "$second"; wait "$second" || true; second=
"$probe" "$group/cgroup.procs" open
echo 'PASS scope inheritance, multi-attach preservation and fd cleanup'
