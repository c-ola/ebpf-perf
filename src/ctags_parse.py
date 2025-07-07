import json
with open("tags", 'r') as f:
    lines = f.readlines()

import re

def extract_args(line: str, func_name: str) -> str:
    # Match the function and extract the argument list inside parentheses
    pattern = rf'{re.escape(func_name)}\s*\(([^)]*)\)'
    match = re.search(pattern, line)
    if match:
        return match.group(1).strip()
    return ""


structs = {}
type_map = {}
vars = {}
functions = {}
for line in lines:
    if line.startswith('!'):
        continue
    l, r = line.split('/^')
    l = l.split()
    name, file = l
    decl, r = r.replace("unsigned long", "unsigned_long").split('$/')
    rest = r.split()
    kind = rest[1]
    match kind:
        case 't':
            type_map[name] = rest[2].split(':')[-1]
        case 'v':
            vars[name] = rest[2].split(':')[-1]
        case 'f':
            args = extract_args(decl, name).split(',')
            args = [arg.split() for arg in args]
            functions[name] = {
                "args": args,
                "ret": rest[2].split(':')[-1]
            }
        case 's':
            type_map[name] = name
            structs[name] = []
        case 'm':
            parent_struct = rest[2].split(':')[-1]
            t = rest[3].split(':')[-1]
            if not structs.get(parent_struct):
                structs[parent_struct] = []
            structs[parent_struct].append((t, name))
with open('desc.json', 'w') as f:

    json.dump({
        "structs": structs,
        "vars": vars,
        "functions": functions,
        "type_map": type_map
        }, f, indent=2)
