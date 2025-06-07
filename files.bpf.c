#include "../libbpf-bootstrap/vmlinux.h/include/x86_64/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// always needs a license
char _license[] SEC("license") = "GPL";

// functions should be put in specific sections based on what kind of program they are
// A list of program types and their formats can be found here:
// https://docs.kernel.org/bpf/libbpf/program_types.html
// It might not be required to do this if you use some other functions that specify the program type when loading the ebpf program


// different program types also have different arguments passed in
// im not too sure how to know what to use here, but /uapi/linux/bpf.h should have some documentation on it, there are also examples on the internet, such as libbpf-bootstrap
// syscalls can have their args passed in, should also use the BPF_SYSCALL macro

// view traces from printk with sudo cat /sys/kernel/debug/tracing/trace_pipe
// bpftrace -l 'ksyscall:*openat*'

#define PATHLEN 256


/*struct file_open_data {
    int pid;
    int tgid;
    int fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct my_value);
    __uint(max_entries, 16);
} icmpcnt SEC(".maps");*/

SEC("ksyscall/openat")
int BPF_KSYSCALL(openat_ksyscall_entry,  int dirfd, const char* filename, int flags, int mode) {
    char buf[PATHLEN]; // PATHLEN is defined to 256
    int res = bpf_probe_read_user_str(buf, sizeof(buf), (void*)filename);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int tgid = pid_tgid >> 32;
    int pid = pid_tgid & 0xffffffff;
    bpf_printk("ksyscall opened file from pid %d and tgid %d: %s, err: %d", pid, tgid, buf, res);
    return 0;
}


SEC("kretsyscall/openat")
int BPF_KRETSYSCALL(struct pt_regs* ctx) {
    int retval = ctx->ax;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int tgid = pid_tgid >> 32;
    int pid = pid_tgid & 0xffffffff;
    bpf_printk("kretsyscall opened file from pid %d and tgid %d: fd=%d", pid, tgid, retval);
    return 0;
}

/*SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(openat_kprobe_entry, int dfd, const char *filename, int flags, int mode) { 
    char buf[PATHLEN]; // PATHLEN is defined to 256
    int res = bpf_probe_read_str(buf, sizeof(buf), (void*)filename);
    bpf_printk("kprobe opened file: %s, err: %d", buf, res);
    return 0;
}*/

/*SEC("tracepoint/syscalls/sys_enter_openat")
int openat_entry_tracepoint(struct pt_regs* ctx) { 
    const char* filename = (const char*)&PT_REGS_PARM2(ctx);
    char buf[PATHLEN]; // PATHLEN is defined to 256
    int res = bpf_probe_read_user_str(buf, sizeof(buf), (void*)filename);
    bpf_printk("trace opened file: %s, err: %d", buf, res);
    return 0;
}*/

