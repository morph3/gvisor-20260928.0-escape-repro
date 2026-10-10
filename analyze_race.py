#!/usr/bin/env python3
"""analyze_race.py: find reval→open windows invaded by renames, per thread.

Win condition: for a given thread T:
  reval:   openat(33, "A", O_PATH)  [succeeds]
  open:    openat(33, "A", O_RDWR...)  [the next one from T]
  rename:  renameat2(33, "C", 33, "A") from ANY thread between reval and open
"""
import re, sys
from collections import defaultdict

LOG = "/tmp/strace_race.log"

events = []  # (seq, thread, kind)
with open(LOG) as f:
    for i, line in enumerate(f):
        m = re.match(r"^(\d+) (?:<... )?(\w+)", line)
        if not m:
            continue
        tid, call = m.group(1), m.group(2)
        if call == "openat" and '"A"' in line:
            if "O_PATH" in line:
                events.append((i, tid, "reval"))
            elif "O_RDWR" in line:
                events.append((i, tid, "open"))
        elif call == "renameat2" and '"C", 33, "A"' in line:
            events.append((i, tid, "rename_cuse"))

# per thread: walk events in order; a rename_cuse between a reval(T) and the next open(T) = window hit
# build global sequence with thread tags
seq = sorted(events, key=lambda e: e[0])
last_reval = {}
hits = 0
opens = 0
revals = 0
for i, tid, kind in seq:
    if kind == "reval":
        last_reval[tid] = i
        revals += 1
    elif kind == "open":
        opens += 1
        if tid in last_reval:
            # any rename_cuse between last_reval[tid] and i?
            for j, t2, k2 in seq:
                if last_reval[tid] < j < i and k2 == "rename_cuse":
                    hits += 1
                    break
            del last_reval[tid]

print(f"revals={revals} opens={opens} window_hits={hits}")
