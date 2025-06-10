import re
import sys
import json
from elftools.elf.elffile import ELFFile

if len(sys.argv) < 2:
    print("Please pass in a map file to parse")

if len(sys.argv) < 2:
    print("Please pass in an elf file to analyze")

trace_path = sys.argv[1]
elf_path = sys.argv[2]

with open(trace_path) as f:
    lines = f.readlines()

pattern = re.compile(r'^\s*(0x[0-9a-fA-F]+)\s+(\S+)$')

functions = []
text = None
fini = None

with open(elf_path, 'rb') as f:
    elffile = ELFFile(f)
    for section in elffile.iter_sections():
        #print(f"{section.name}, 0x{section['sh_addr']:x}")
        if section.name == ".text":
            text = int(section['sh_addr'])
        if section.name == ".fini":
            fini = int(section['sh_addr'])

for line in lines:
    match = pattern.match(line)
    if match:
        addr, symbol = match.groups()
        addr = int(addr, 16)
        if addr < fini and addr >= text:
            functions.append({"addr": addr, "symbol": symbol})

with open("symbols.json", 'w') as f:
    json.dump(functions, f, indent=2)


