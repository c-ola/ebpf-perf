import sys
import json

log_file_path = sys.argv[1]
with open(log_file_path, 'r') as f:
    lines = f.readlines()

call_stack = []
perf = []

for line in lines:
    ret_or_enter, vals = line.split(':')
    is_ret = ret_or_enter == "ret"
    vals = vals.split(',')
    pid = vals[0].split('=')[-1]
    name = vals[1].split('=')[-1]
    t = int(vals[2].split('=')[-1])
    addr = int(vals[3].split('=')[-1], 16)
    print(f"is_ret={is_ret}, {name}, {t}")
    if not is_ret:
        call_stack.append({"name": name,  "t": t})
    if len(call_stack) > 0 and is_ret:
        if call_stack[-1]['name'] == name:
            enter_t = call_stack[-1]['t']
            perf.append({"name": name, "t": t, "len": (t - enter_t)})
            call_stack.pop()


print(json.dumps(perf, indent=2))
total_t = 0
for p in perf:
    print(f"call to {p['name']} took {p['len'] / 1_000_000}ms")
    total_t += p["len"]
print(f"{total_t / 1_000_000}ms")

