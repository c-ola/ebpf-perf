#!/bin/bash

set -v

PIN_DIR="/home/nikola/research/pin-intel/"

g++ -Wall -Werror -Wno-unknown-pragmas -DPIN_CRT=1 -fno-stack-protector -fno-exceptions -funwind-tables -fasynchronous-unwind-tables -fno-rtti -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX -fabi-version=2 -faligned-new -I${PIN_DIR}/source/include/pin -I${PIN_DIR}/source/include/pin/gen -isystem ${PIN_DIR}/extras/cxx/include -isystem ${PIN_DIR}/extras/crt/include -isystem ${PIN_DIR}/extras/crt/include/arch-x86_64 -isystem ${PIN_DIR}/extras/crt/include/kernel/uapi -isystem ${PIN_DIR}/extras/crt/include/kernel/uapi/asm-x86 -I${PIN_DIR}/extras/components/include -I${PIN_DIR}extras/xed-intel64/include/xed -I${PIN_DIR}source/tools/Utils -I${PIN_DIR}source/tools/InstLib -O3 -fomit-frame-pointer -fno-strict-aliasing  -Wno-dangling-pointer -c -o trace.o trace.cpp
g++ -shared -Wl,--hash-style=sysv ${PIN_DIR}/intel64/runtime/pincrt/crtbeginS.o -Wl,-Bsymbolic -Wl,--version-script=${PIN_DIR}/source/include/pin/pintool.ver -fabi-version=2  -o trace.so trace.o ${PIN_DIR}/source/tools/InstLib/obj-intel64/controller.a -L${PIN_DIR}/intel64/runtime/pincrt -L${PIN_DIR}/intel64/lib -L${PIN_DIR}/intel64/lib-ext -L${PIN_DIR}/extras/xed-intel64/lib -lpin -lxed ${PIN_DIR}/intel64/runtime/pincrt/crtendS.o -lpindwarf -ldwarf -ldl-dynamic -nostdlib -lc++ -lc++abi -lm-dynamic -lc-dynamic -lunwind-dynamic

