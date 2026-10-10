#!/usr/bin/env python3
"""analyze_race3.py: dump full context around TRUE window hits."""
import re, sys

LOG = "/tmp/strace_race.log"
lines = open(LOG).read().splitlines()

events = []
pending = {}
for i, line in enumerate(lines):
    m = re.match(r"^(\d+) (?:<... )?(\w+)", line)
    if not m: continue
    tid, call = m.group(1), m.group(2)
    if call == "openat" and '"A"' in line:
        if "O_PATH" in line: pending[tid] = i
        elif "O_RDWR" in line: events.append((i, tid, "open"))
    elif call == "statx" and tid in pending:
        if "S_IFREG" in line: events.append((pending.pop(tid), tid, "reval_reg"))
        elif "S_IFCHR" in line: pending.pop(tid)
    elif call == "renameat2" and '"C", 33, "A"' in line:
        events.append((i, tid, "rename"))

seq = sorted(events, key=lambda e: e[0])
last_reval = {}
hits = []
for i, tid, kind in seq:
    if kind == "reval_reg": last_reval[tid] = i
    elif kind == "open" and tid in last_reval:
        for j, t2, k2 in seq:
            if last_reval[tid] < j < i and k2 == "rename":
                hits.append((last_reval[tid], j, i, tid)); break
        del last_reval[tid]

n = int(sys.argv[1]) if len(sys.argv) > 1 else 2
for h in hits[:n]:
    print("=== TRUE HIT reval@%d rename@%d open@%d tid=%s ===" % h)
    for k in range(h[0], min(len(lines), h[2]+12)):
        print("  ", lines[k][:160])
