#!/usr/bin/env python3
"""analyze_race2.py: count TRUE wins: reval(statx=REG) -> rename(C->A) -> openat(O_RDWR)."""
import re

LOG = "/tmp/strace_race.log"
lines = open(LOG).read().splitlines()

events = []  # (seq, tid, kind)
pending_reval_statx = {}  # tid -> (seq of openat O_PATH, expecting statx next)

for i, line in enumerate(lines):
    m = re.match(r"^(\d+) (?:<... )?(\w+)", line)
    if not m:
        continue
    tid, call = m.group(1), m.group(2)
    if call == "openat" and '"A"' in line:
        if "O_PATH" in line:
            pending_reval_statx[tid] = i  # wait for its statx
        elif "O_RDWR" in line:
            events.append((i, tid, "open"))
    elif call == "statx" and tid in pending_reval_statx:
        if "S_IFREG" in line:
            events.append((pending_reval_statx.pop(tid), tid, "reval_reg"))
        elif "S_IFCHR" in line:
            pending_reval_statx.pop(tid)
    elif call == "renameat2" and '"C", 33, "A"' in line:
        events.append((i, tid, "rename"))

seq = sorted(events, key=lambda e: e[0])
last_reval = {}
true_hits = 0
reg_revals = 0
for i, tid, kind in seq:
    if kind == "reval_reg":
        last_reval[tid] = i
        reg_revals += 1
    elif kind == "open" and tid in last_reval:
        for j, t2, k2 in seq:
            if last_reval[tid] < j < i and k2 == "rename":
                true_hits += 1
                break
        del last_reval[tid]

print(f"reg_revals={reg_revals} true_window_hits={true_hits}")
