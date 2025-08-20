import sys
import json

log_file_path = sys.argv[1]
with open(log_file_path, 'r') as f:
    lines = f.readlines()

symbol_path = sys.argv[2]
with open(symbol_path, 'r') as f:
    symbols = json.load(f)

threads = {}
perf = []

def find_function(addr: int):
    for f in symbols["functions"]:
        if f["addr"] == addr:
            return f
        elif addr in f["returns"]:
            return f
    return {}

for line in lines:
    vals = line.strip().split(',')
    tsc = int(vals[0].split('=')[-1])
    tid = int(vals[1].split('=')[-1])
    ip = int(vals[2].split('=')[-1], 16)
    function = find_function(ip)
    name = function["label"]
    is_ret = ip != function["addr"]
    if threads.get(tid) is None:
        threads[tid] = []
    call_stack = threads[tid]
    if not is_ret:
        call_stack.append({"name": name,  "t": tsc})
    if len(call_stack) > 0 and is_ret:
        if call_stack[-1]['name'] == name:
            enter_t = call_stack[-1]['t']
            perf.append({"name": name, "t": tsc, "len": (tsc - enter_t)})
            call_stack.pop()
    print(f"{'RET' if is_ret else 'CALL'}|{tsc}|label|{name}|tid|{tid}")
    #print(f"{'RET' if is_ret else 'CALL'}_{name}|{t}|label|{name}")
#print(threads)
#print(json.dumps(perf, indent=2))
#for p in perf:
    #print(f"call to {p['name']} took {p['len'] / 1_000_000}ms")

