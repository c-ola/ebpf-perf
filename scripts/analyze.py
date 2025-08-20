import sys
import json

log_file_path = sys.argv[1]
with open(log_file_path, 'r') as f:
    lines = f.readlines()

threads = {}
perf = []

for line in lines:
    vals = line.strip().split(',')
    t = int(vals[0].split('=')[-1])
    name = vals[1].split('=')[-1]
    tid = int(vals[2].split('=')[-1])
    pid = int(vals[3].split('=')[-1])
    addr = int(vals[4].split('=')[-1], 16)
    is_ret = vals[5].split('=')[0].strip() == "ret"
    #print(f"is_ret={is_ret}, {name}, {t}")
    if threads.get(tid) is None:
        threads[tid] = []
    call_stack = threads[tid]

    if not is_ret:
        call_stack.append({"name": name,  "t": t})
    if len(call_stack) > 0 and is_ret:
        if call_stack[-1]['name'] == name:
            enter_t = call_stack[-1]['t']
            perf.append({"name": name, "t": t, "len": (t - enter_t)})
            call_stack.pop()
    print(f"{'RET' if is_ret else 'CALL'}|{t}|label|{name}")
    #print(f"{'RET' if is_ret else 'CALL'}_{name}|{t}|label|{name}")
for k, thread in threads.items():
    if len(thread) != 0:
        print(threads)
        exit()

#print(json.dumps(perf, indent=2))
#for p in perf:
    #print(f"call to {p['name']} took {p['len'] / 1_000_000}ms")

