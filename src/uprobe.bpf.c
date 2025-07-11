//#include <linux/bpf.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char _license[] SEC("license") = "GPL";

// this is used to store data that you send through the ringbuf on the heap if you want
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct perf_data);
} perf_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

typedef struct _astruct {
    int a;
    unsigned long b;
    float c;
    char d;
} astruct;

SEC("uprobe/entry_uprobe")
int BPF_KPROBE(uprobe_entry) {
    u64 start = bpf_ktime_get_ns();
    u64 ip = bpf_get_func_ip(ctx);
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    struct mm_struct* mm;
    bpf_probe_read_kernel(&mm, sizeof(struct mm_struct*), &task->mm);
    unsigned long base_code_addr;
    bpf_probe_read_kernel(&base_code_addr, sizeof(unsigned long), &mm->start_code);
    struct perf_data d = {
        .pid = pid,
        .ip = ip,
        .call_time = start,
        .base_code_addr = base_code_addr,
        .params = {ctx->di, ctx->si, ctx->dx, ctx->r8, ctx->r9},
        .ret = ctx->ax
    };
    bpf_ringbuf_output(&rb, &d, sizeof(d), 0);
    bpf_printk("entry, start=%lu, rip=0x%lx, base_code_addr=0x%lx", start, ip, base_code_addr);
    astruct t;
    bpf_probe_read_user(&t, sizeof(astruct), (void*)(0x4020 + base_code_addr - 4096));
    bpf_printk("a: %d, b: %lu, d: %c", t.a, t.b, t.d);
    return 0;
}

SEC("uretprobe/ret_uprobe")
int BPF_KRETPROBE(uprobe_ret){//, long ret) {
    u64 start = bpf_ktime_get_ns();
    u64 ip = bpf_get_func_ip(ctx);
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    struct mm_struct* mm;
    bpf_probe_read_kernel(&mm, sizeof(struct mm_struct*), &task->mm);
    unsigned long base_code_addr;
    bpf_probe_read_kernel(&base_code_addr, sizeof(unsigned long), &mm->start_code);
    struct perf_data d = {
        .pid = pid,
        .ip = ip,
        .call_time = start,
        .base_code_addr = base_code_addr,
        .params = {0},
        .ret = ctx->ax,
    };
    bpf_ringbuf_output(&rb, &d, sizeof(d), 0);
    bpf_printk("ret, start=%lu, rip=0x%lx, base_code_addr=0x%lx", start, ip, base_code_addr);
    return 0;
}
