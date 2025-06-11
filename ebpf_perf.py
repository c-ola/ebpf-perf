import re
import sys
import json
from elftools.elf.elffile import ELFFile
from capstone import *

if len(sys.argv) < 2:
    print("Please pass in a map file to parse")

if len(sys.argv) < 3:
    print("Please pass in an elf file to analyze")


trace_path = sys.argv[1]
elf_path = sys.argv[2]
out_path = "symbols.json"
if len(sys.argv) >= 4:
    out_path = sys.argv[3]

with open(trace_path) as f:
    lines = f.readlines()

pattern = re.compile(r'^\s*(0x[0-9a-fA-F]+)\s+(\S+)$')

functions = []
text = None
fini = None
init = 0

with open(elf_path, 'rb') as f:
    elffile = ELFFile(f)
    for section in elffile.iter_sections():
        #print(f"{section.name}, 0x{section['sh_addr']:x}")
        if section.name == ".text":
            text = int(section['sh_addr'])
        if section.name == ".init":
            init = int(section['sh_offset'])
        if section.name == ".fini":
            fini = int(section['sh_addr'])

if fini and text:
    for line in lines:
        match = pattern.match(line)
        if match:
            addr, symbol = match.groups()
            addr = int(addr, 16)
            if addr < fini and addr >= text:
                functions.append({"addr": addr, "symbol": symbol})


with open(elf_path, 'rb') as f:
    elf = f.read()


md = Cs(CS_ARCH_X86, CS_MODE_64)

for idx, function in enumerate(functions):
    print(f"Dissassembling {function['symbol']}")
    addr = function['addr']
    code = elf[addr:]
    next_sym_addr = functions[idx + 1]['addr'] if idx < len(functions) - 1 else fini
    found_returns = []
    if function['symbol'] == "main":
        found_returns.append(fini)
    addr_offset = 0
    while True:
        instrs = md.disasm(code[addr_offset:addr_offset + 18], addr + addr_offset, 1)
        for i in instrs:
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            addr_offset += len(i.bytes)
            if i.bytes == b'\xc3':
                found_returns.append(i.address)
        if addr + addr_offset >= next_sym_addr:
            break
    functions[idx]['returns'] = found_returns
    print(found_returns)

with open(out_path, 'w') as f:
    json.dump({"offset": init, "symbols": functions}, f, indent=2)
