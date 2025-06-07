//#include <linux/bpf.h>
#include "../libbpf-bootstrap/vmlinux.h/include/x86_64/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

struct data {
    pid_t pid;
    u64 call_time;
    u64 ip;
};


// this is used to store data that you send through the ringbuf on the heap
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct data);
} perf_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe/entry_uprobe")
int BPF_UPROBE(uprobe_entry) {
    u64 start = bpf_ktime_get_ns();
    u64 ip = bpf_get_func_ip(ctx);
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct data d = {
        .pid = pid,
        .ip = ip,
        .call_time = start,
    };
    bpf_ringbuf_output(&rb, &d, sizeof(d), 0);
    bpf_printk("entry, start=%lu, rip=0x%lx", start, ip);
    return 0;
}

SEC("uretprobe/ret_uprobe")
int BPF_URETPROBE(uprobe_ret, long ret) {
    u64 end = bpf_ktime_get_ns();
    u64 ip = bpf_get_func_ip(ctx);
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct data d = {
        .pid = pid,
        .ip = ip,
        .call_time = end,
    };
    bpf_ringbuf_output(&rb, &d, sizeof(d), 0);
    bpf_printk("ret %d, end=%lu, rip=0x%lx", ret, end, ip);
    return 0;
}

