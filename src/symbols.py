import os
import sys
import json
from elftools.elf.elffile import ELFFile
from capstone import *

if len(sys.argv) < 2:
    print("Please pass in a map file to parse")

if len(sys.argv) < 3:
    print("Please pass in an elf file to analyze")

syms_path = sys.argv[1]
elf_path = sys.argv[2]
out_path = "symbols.json"
if len(sys.argv) >= 4:
    out_path = sys.argv[3]

def get_elf_info(elf_path):
    text, init, fini = None, 0, None
    base_addr = None
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
        for segment in elffile.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                vaddr = segment['p_vaddr']
                if base_addr is None or vaddr < base_addr:
                    base_addr = vaddr
    with open(elf_path, 'rb') as f:
        elf = f.read()
    return elf, base_addr, text, init, fini

def get_symbols(syms_path, elf_path):
    functions = []
    globals = []

    elf, base_addr, text, init, fini = get_elf_info(elf_path)

    arch, mode = None, None
    match os.uname().machine:
        case "x86_64":
            arch, mode = CS_ARCH_X86, CS_MODE_64
        case "aarch64":
            arch, mode = CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        case _:
            print("Unmatched system architecture")
    md = Cs(arch, mode)

    with open(syms_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            parts = line.split()
            if len(parts) != 4:
                continue
            addr = int(parts[0], 16)
            size = int(parts[1], 16)
            sec = parts[2]
            label = parts[3]
            # skip _start
            if label == "_start":
                continue
            if sec == 'T' or sec == 't':
                rets = get_rets(md, elf, addr, size, base_addr)
                functions.append({"addr": addr, "label": label, "returns": rets})
            elif sec == 'd':
                globals.append({"addr": addr, "label": label, "size": size})

    with open(out_path, 'w') as f:
        json.dump({"offset": init, "functions": functions, "globals": globals}, f, indent=2)
    return functions, globals

def get_rets(md, elf, addr, size, base_addr):
    code = elf[addr - base_addr:]
    end_addr = addr + size + 0x1
    found_returns = []
    addr_offset = 0
    while True:
        instrs = md.disasm(code[addr_offset:addr_offset + 18], addr + addr_offset, 1)
        for i in instrs:
            #print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            addr_offset += len(i.bytes)
            if i.mnemonic == "ret":
                found_returns.append(i.address)
        if addr + addr_offset >= end_addr:
            break
    return found_returns

functions, globals = get_symbols(syms_path, elf_path)
#print(functions, globals)
