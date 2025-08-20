#!/usr/bin/env python3
import sys

stack = []
last_ts = None
samples = {}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    parts = line.split("|")
    #if len(parts) < 4:
        #continue
    ev, ts, _, func = parts[0:4]
    ts = int(ts)

    if last_ts is not None and stack:
        dur = ts - last_ts
        key = ";".join(stack)
        samples[key] = samples.get(key, 0) + dur

    if ev == "CALL":
        stack.append(func)
    elif ev == "RET":
        if stack and stack[-1] == func:
            stack.pop()
        else:
            print(f"Mismatched return: {line}", file=sys.stderr)

    last_ts = ts

for k, v in samples.items():
    print(f"{k} {v}")

