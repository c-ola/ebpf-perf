//#include "vmlinux.h"
struct perf_data {
    int pid;
    int tid;
    unsigned long call_time;
    unsigned long ip;
    unsigned long base_code_addr;
    unsigned long params[6]; // rdi, rsi, rdx, rcx, r8, r9
    unsigned long ret; // rax for returns (x86_64)
    // other args are passed on the stack
};
